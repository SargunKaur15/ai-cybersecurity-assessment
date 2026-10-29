import json
from pathlib import Path

import pytest
from sklearn.pipeline import Pipeline

from generate_dataset import generate_dataset, generate_shifted_dataset
import train_evaluate as te
from train_evaluate import (build_pipeline, compute_metrics, leave_one_template_out, load_labeled_csv, main,
                            per_template_table, run_experiment, split_by_template, split_data, to_binary)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


# ------------------------------------------------------------- input validation
def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_labeled_csv(tmp_path / "nope.csv")


def test_missing_column_raises(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("text\nhello\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required column"):
        load_labeled_csv(p)


def test_unknown_label_raises(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("text,label\nhello,spam\nhi,phishing\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown label"):
        load_labeled_csv(p)


def test_empty_text_raises(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text('text,label\n"  ",phishing\nok,legitimate\n', encoding="utf-8")
    with pytest.raises(ValueError, match="empty message"):
        load_labeled_csv(p)


def test_single_class_raises(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("text,label\na,phishing\nb,phishing\n", encoding="utf-8")
    with pytest.raises(ValueError, match="both classes"):
        load_labeled_csv(p)


def test_handwritten_adversarial_file_is_valid():
    df = load_labeled_csv(DATA_DIR / "adversarial_handwritten.csv", extra_columns=("probe_type",))
    assert len(df) >= 20
    assert set(df["label"]) == {"phishing", "legitimate"}


# --------------------------------------------------------- split / leakage checks
def test_split_is_stratified_disjoint_and_complete(small_df):
    train, test = split_data(small_df, test_size=0.25, seed=3)
    assert len(train) + len(test) == len(small_df)
    assert set(train["message_id"]).isdisjoint(test["message_id"])
    full_share = (small_df["label"] == "phishing").mean()
    assert abs((test["label"] == "phishing").mean() - full_share) < 0.01


def test_pipeline_structure():
    model = build_pipeline()
    assert isinstance(model, Pipeline)
    assert [name for name, _ in model.steps] == ["tfidf", "clf"]


def test_vectorizer_never_sees_test_text(small_df):
    train, test = split_data(small_df, seed=3)
    test_texts = test["text"].tolist()
    test_texts[0] += " zzqxuniquetoken zzqxuniquetoken"  # appears only in test data
    model = build_pipeline()
    model.fit(train["text"].tolist(), to_binary(train["label"]))
    assert "zzqxuniquetoken" not in model.named_steps["tfidf"].vocabulary_
    model.predict(test_texts)  # unseen tokens must be ignored, not crash


# ------------------------------------------- template-held-out evaluation
def test_template_split_shares_no_template_and_keeps_both_classes(small_df):
    train, test, held = split_by_template(small_df, test_fraction=0.25, seed=3)
    assert set(train["template_id"]).isdisjoint(test["template_id"])
    assert set(test["template_id"]) == set(held)
    assert set(train["label"]) == set(test["label"]) == {"phishing", "legitimate"}
    assert len(train) + len(test) == len(small_df)
    assert set(train["text"]).isdisjoint(test["text"])


def test_template_split_is_deterministic_and_seed_dependent(small_df):
    assert split_by_template(small_df, seed=1)[2] == split_by_template(small_df, seed=1)[2]
    assert any(split_by_template(small_df, seed=1)[2] != split_by_template(small_df, seed=s)[2] for s in range(2, 8))


def test_template_split_requires_template_ids(small_df):
    with pytest.raises(ValueError, match="template_id"):
        split_by_template(small_df.drop(columns=["template_id"]))


def test_template_split_needs_two_templates_per_class(small_df):
    one_each = small_df[small_df["template_id"].isin(["P01", "L01"])]
    with pytest.raises(ValueError, match="at least two templates"):
        split_by_template(one_each)


def test_leave_one_template_out_scores_every_row_once_with_unseen_template(small_df, monkeypatch):
    fitted = []
    real_build = te.build_pipeline

    def spy(seed=te.SEED):
        model = real_build(seed)
        original_fit = model.fit

        def fit(X, y):
            fitted.append(set(X))
            return original_fit(X, y)
        model.fit = fit
        return model

    monkeypatch.setattr(te, "build_pipeline", spy)
    scored, y_true, y_pred = leave_one_template_out(small_df, seed=3)
    assert list(scored["message_id"]) == list(small_df["message_id"]) and len(y_pred) == len(small_df)
    template_ids = sorted(small_df["template_id"].unique())
    assert len(fitted) == len(template_ids)
    for train_texts, tid in zip(fitted, template_ids):
        assert train_texts.isdisjoint(set(small_df.loc[small_df["template_id"] == tid, "text"]))


def test_per_template_table_counts_errors(small_df):
    scored, _, _ = leave_one_template_out(small_df, seed=3)
    table = per_template_table(scored)
    assert table["n"].sum() == len(small_df)
    assert table["errors"].sum() == (scored["error_type"] != "correct").sum()
    assert table["correct_rate"].between(0, 1).all()


# ------------------------------------------------------------------- metrics
def test_compute_metrics_known_values():
    m = compute_metrics([1, 1, 1, 0, 0, 0, 0, 0], [1, 1, 0, 1, 0, 0, 0, 0])
    assert m["confusion_matrix"] == {"true_negative": 4, "false_positive": 1, "false_negative": 1, "true_positive": 2}
    assert m["accuracy"] == 0.75
    assert m["precision"] == pytest.approx(0.6667, abs=1e-4)
    assert m["recall"] == pytest.approx(0.6667, abs=1e-4)
    assert m["f1"] == pytest.approx(0.6667, abs=1e-4)
    assert (m["n_samples"], m["n_phishing"], m["n_legitimate"]) == (8, 3, 5)


def test_compute_metrics_never_predicting_phishing_does_not_crash():
    m = compute_metrics([1, 0, 0], [0, 0, 0])
    assert m["precision"] == 0.0 and m["recall"] == 0.0 and m["f1"] == 0.0


# ------------------------------------------------------------ full experiment
@pytest.fixture()
def experiment_inputs(tmp_path):
    main_csv, shifted_csv = tmp_path / "main.csv", tmp_path / "shifted.csv"
    generate_dataset(n_total=300, seed=5).to_csv(main_csv, index=False)
    generate_shifted_dataset(n_total=60, seed=6).to_csv(shifted_csv, index=False)
    return main_csv, shifted_csv


def test_experiment_is_reproducible_and_writes_outputs(experiment_inputs, tmp_path):
    main_csv, shifted_csv = experiment_inputs
    adv = DATA_DIR / "adversarial_handwritten.csv"
    first = run_experiment(main_csv, shifted_csv, adv, tmp_path / "r1", seed=11)
    second = run_experiment(main_csv, shifted_csv, adv, tmp_path / "r2", seed=11)
    assert first == second
    for name in ("metrics.json", "confusion_matrix.png", "confusion_matrix.csv", "misclassified.csv",
                 "classification_report.txt", "top_features.csv", "adversarial_predictions.csv", "model.joblib",
                 "template_holdout_confusion_matrix.png", "template_holdout_per_template.csv",
                 "leave_one_template_out.csv"):
        assert (tmp_path / "r1" / name).is_file(), name
    saved = json.loads((tmp_path / "r1" / "metrics.json").read_text(encoding="utf-8"))
    assert saved["template_holdout"]["n_train"] + saved["template_holdout"]["n_test"] == 300
    assert saved["leave_one_template_out"]["n_samples"] == 300
    assert saved["data"]["n_train"] + saved["data"]["n_test"] == saved["data"]["n_total"] == 300
    assert saved["baseline_majority_class"]["recall"] == 0.0


def test_main_reports_missing_data_with_exit_code_2(tmp_path, capsys):
    code = main(["--data", str(tmp_path / "missing.csv"), "--results-dir", str(tmp_path / "out")])
    assert code == 2
    assert "Dataset not found" in capsys.readouterr().err
