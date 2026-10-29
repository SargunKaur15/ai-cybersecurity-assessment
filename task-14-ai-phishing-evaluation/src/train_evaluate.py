"""Train and evaluate a TF-IDF + Logistic Regression phishing-like message classifier (Task 14).

Experimental design
-------------------
1. Load the synthetic dataset and validate it.
2. Split into train/test (stratified, fixed seed) BEFORE anything is fitted.
3. Fit ONE scikit-learn Pipeline (TF-IDF -> Logistic Regression) on the training split only,
   so vocabulary and IDF weights never see test text.
4. Report accuracy / precision / recall / F1 / confusion matrix on the held-out test split
   (phishing is the positive class), plus a majority-class baseline.
5. Probe weaknesses: URLs masked, a separate shifted-distribution set, and a small
   hand-written adversarial set. None of these are used for fitting or tuning.

Hyper-parameters are fixed up front and were not tuned on any evaluation data.

Run:  python src/train_evaluate.py
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import re
import sys
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")  # file output only; no display needed
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

SEED = 42
TEST_SIZE = 0.25
LABELS = ("legitimate", "phishing")  # index 0 = negative class, index 1 = positive class
URL_RE = re.compile(r"https?://\S+")
TASK_DIR = Path(__file__).resolve().parents[1]


# ----------------------------------------------------------------- data loading
def load_labeled_csv(path, extra_columns=()):
    """Load and validate a labelled message CSV. Raises ValueError/FileNotFoundError with clear messages."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}. Run 'python src/generate_dataset.py' first.")
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    required = ["text", "label", *extra_columns]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"{path.name}: missing required column(s): {missing}")
    if df.empty:
        raise ValueError(f"{path.name}: dataset is empty")
    bad = sorted(set(df["label"]) - set(LABELS))
    if bad:
        raise ValueError(f"{path.name}: unknown label value(s) {bad}; expected {list(LABELS)}")
    if (df["text"].str.strip() == "").any():
        raise ValueError(f"{path.name}: contains empty message text")
    if df["label"].nunique() < 2:
        raise ValueError(f"{path.name}: needs both classes to train/evaluate")
    return df.reset_index(drop=True)


def to_binary(labels):
    """'phishing' -> 1, 'legitimate' -> 0."""
    return (pd.Series(labels) == "phishing").astype(int).to_numpy()


# ---------------------------------------------------------------------- model
def build_pipeline(seed=SEED):
    return Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
        ("clf", LogisticRegression(C=1.0, max_iter=1000, random_state=seed)),
    ])


def split_data(df, test_size=TEST_SIZE, seed=SEED):
    """Stratified train/test split. Called before any model is fitted."""
    return train_test_split(df, test_size=test_size, stratify=df["label"], random_state=seed)


def _require_templates(df):
    if "template_id" not in df.columns:
        raise ValueError("template-held-out evaluation needs a 'template_id' column")
    if (df["template_id"].str.strip() == "").any():
        raise ValueError("template_id must not be empty")


def split_by_template(df, test_fraction=0.25, seed=SEED):
    """Hold out WHOLE templates (stratified by class): no test message shares a template with training.

    Returns (train_df, test_df, held_out_template_ids). Every template belongs to one class, so
    templates are chosen per class and both classes appear in both splits.
    """
    _require_templates(df)
    rng = random.Random(seed)
    held = []
    for label in LABELS:
        ids = sorted(df.loc[df["label"] == label, "template_id"].unique())
        k = max(1, round(len(ids) * test_fraction))
        if len(ids) < 2 or k >= len(ids):
            raise ValueError(f"need at least two templates for class '{label}' to hold some out")
        held += rng.sample(ids, k)
    mask = df["template_id"].isin(held)
    return df[~mask], df[mask], sorted(held)


def leave_one_template_out(df, seed=SEED):
    """For each template, fit on all OTHER templates and score that template. Each message is
    therefore scored by a model that never saw its template. Returns (scored_df, y_true, y_pred)."""
    _require_templates(df)
    parts = []
    for template_id in sorted(df["template_id"].unique()):
        held = df["template_id"] == template_id
        model = build_pipeline(seed)
        model.fit(df.loc[~held, "text"].tolist(), to_binary(df.loc[~held, "label"]))
        scored, _, _ = predict_frame(model, df[held])
        parts.append(scored)
    out = pd.concat(parts).loc[df.index]  # restore original row order
    return out, to_binary(out["label"]), (out["predicted_label"] == "phishing").astype(int).to_numpy()


def per_template_table(scored):
    """Correct-rate per template (= recall for phishing templates, specificity for legitimate ones)."""
    work = scored.assign(is_error=scored["error_type"] != "correct")
    table = (work.groupby(["template_id", "category", "label"])
             .agg(n=("is_error", "size"), errors=("is_error", "sum"),
                  mean_phishing_probability=("phishing_probability", "mean")).reset_index())
    table["correct_rate"] = ((table["n"] - table["errors"]) / table["n"]).round(4)
    table["mean_phishing_probability"] = table["mean_phishing_probability"].round(3)
    return table


# -------------------------------------------------------------------- metrics
def compute_metrics(y_true, y_pred):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "n_samples": int(len(y_true)),
        "n_phishing": int((y_true == 1).sum()),
        "n_legitimate": int((y_true == 0).sum()),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp),
                             "false_negative": int(fn), "true_positive": int(tp)},
    }


def predict_frame(model, df):
    """Return df with predicted label, phishing probability and error type columns."""
    proba = model.predict_proba(df["text"].tolist())[:, 1]
    pred = (proba >= 0.5).astype(int)
    out = df.copy()
    out["predicted_label"] = np.where(pred == 1, "phishing", "legitimate")
    out["phishing_probability"] = np.round(proba, 4)
    true = to_binary(out["label"])
    out["error_type"] = np.select([(true == 0) & (pred == 1), (true == 1) & (pred == 0)],
                                  ["false_positive", "false_negative"], default="correct")
    return out, true, pred


def plot_confusion_matrix(metrics, path, title):
    c = metrics["confusion_matrix"]
    cm = np.array([[c["true_negative"], c["false_positive"]], [c["false_negative"], c["true_positive"]]])
    fig, ax = plt.subplots(figsize=(4.8, 4.2))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], labels=["legitimate", "phishing"])
    ax.set_yticks([0, 1], labels=["legitimate", "phishing"])
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    ax.set_title(title, fontsize=10)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=16,
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def top_features(model, k=15):
    names = model.named_steps["tfidf"].get_feature_names_out()
    coef = model.named_steps["clf"].coef_[0]
    order = np.argsort(coef)
    rows = [("legitimate", names[i], round(float(coef[i]), 4)) for i in order[:k]]
    rows += [("phishing", names[i], round(float(coef[i]), 4)) for i in order[::-1][:k]]
    return pd.DataFrame(rows, columns=["pushes_toward", "feature", "coefficient"])


# ----------------------------------------------------------------- experiment
def run_experiment(data_path, shifted_path, adversarial_path, results_dir, seed=SEED, test_size=TEST_SIZE):
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    df = load_labeled_csv(data_path)
    train_df, test_df = split_data(df, test_size, seed)  # split first, fit afterwards
    y_train, y_test = to_binary(train_df["label"]), to_binary(test_df["label"])

    model = build_pipeline(seed)
    model.fit(train_df["text"].tolist(), y_train)

    scored, _, y_pred = predict_frame(model, test_df)
    test_metrics = compute_metrics(y_test, y_pred)

    baseline = DummyClassifier(strategy="most_frequent").fit(train_df["text"].tolist(), y_train)
    baseline_metrics = compute_metrics(y_test, baseline.predict(test_df["text"].tolist()))

    masked = test_df.assign(text=test_df["text"].str.replace(URL_RE, "", regex=True).str.strip())
    _, _, masked_pred = predict_frame(model, masked)
    masked_metrics = compute_metrics(y_test, masked_pred)

    summary = {
        "config": {
            "seed": seed, "test_size": test_size,
            "pipeline": "TfidfVectorizer(ngram_range=(1,2), min_df=2, sublinear_tf=True) -> LogisticRegression(C=1.0)",
            "decision_threshold": 0.5, "positive_class": "phishing",
            "versions": {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
                         "pandas": pd.__version__, "numpy": np.__version__},
        },
        "data": {
            "n_total": int(len(df)), "n_train": int(len(train_df)), "n_test": int(len(test_df)),
            "train_class_distribution": train_df["label"].value_counts().sort_index().to_dict(),
            "test_class_distribution": test_df["label"].value_counts().sort_index().to_dict(),
        },
        "test_metrics": test_metrics,
        "baseline_majority_class": baseline_metrics,
        "robustness_urls_removed_from_test": masked_metrics,
    }

    # Stronger test: whole templates held out (the stratified split above shares templates with training).
    if "template_id" in df.columns and "category" in df.columns:
        th_train, th_test, held_ids = split_by_template(df, seed=seed)
        th_model = build_pipeline(seed)
        th_model.fit(th_train["text"].tolist(), to_binary(th_train["label"]))
        th_scored, th_true, th_pred = predict_frame(th_model, th_test)
        th_metrics = compute_metrics(th_true, th_pred)
        summary["template_holdout"] = {
            "held_out_templates": held_ids,
            "n_train": int(len(th_train)), "n_test": int(len(th_test)),
            "train_class_distribution": th_train["label"].value_counts().sort_index().to_dict(),
            "test_class_distribution": th_test["label"].value_counts().sort_index().to_dict(),
            "metrics": th_metrics,
        }
        th_scored[th_scored["error_type"] != "correct"].to_csv(results_dir / "template_holdout_misclassified.csv", index=False)
        per_template_table(th_scored).to_csv(results_dir / "template_holdout_per_template.csv", index=False)
        plot_confusion_matrix(th_metrics, results_dir / "template_holdout_confusion_matrix.png",
                              f"Template-held-out test set (n={th_metrics['n_samples']})")

        loto_scored, loto_true, loto_pred = leave_one_template_out(df, seed)
        summary["leave_one_template_out"] = compute_metrics(loto_true, loto_pred)
        per_template_table(loto_scored).to_csv(results_dir / "leave_one_template_out.csv", index=False)
        loto_scored[loto_scored["error_type"] != "correct"].to_csv(results_dir / "leave_one_template_out_misclassified.csv", index=False)

    # Out-of-sample probes: never used for fitting or tuning.
    if shifted_path and Path(shifted_path).is_file():
        shifted = load_labeled_csv(shifted_path)
        s_scored, s_true, s_pred = predict_frame(model, shifted)
        summary["shifted_distribution"] = compute_metrics(s_true, s_pred)
        s_scored[s_scored["error_type"] != "correct"].to_csv(results_dir / "shifted_misclassified.csv", index=False)
        if {"template_id", "category"} <= set(s_scored.columns):
            per_template = (s_scored.assign(is_error=s_scored["error_type"] != "correct")
                            .groupby(["template_id", "category", "label"])
                            .agg(n=("is_error", "size"), errors=("is_error", "sum"),
                                 mean_phishing_probability=("phishing_probability", "mean"))
                            .round(3).reset_index())
            per_template.to_csv(results_dir / "shifted_per_template.csv", index=False)
    if adversarial_path and Path(adversarial_path).is_file():
        adv = load_labeled_csv(adversarial_path, extra_columns=("probe_type",))
        a_scored, a_true, a_pred = predict_frame(model, adv)
        summary["adversarial_handwritten"] = compute_metrics(a_true, a_pred)
        a_scored.to_csv(results_dir / "adversarial_predictions.csv", index=False)

    # Persist outputs.
    (results_dir / "metrics.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    scored[scored["error_type"] != "correct"].to_csv(results_dir / "misclassified.csv", index=False)
    pd.DataFrame([test_metrics["confusion_matrix"]]).to_csv(results_dir / "confusion_matrix.csv", index=False)
    plot_confusion_matrix(test_metrics, results_dir / "confusion_matrix.png",
                          f"Held-out test set (n={test_metrics['n_samples']})")
    (results_dir / "classification_report.txt").write_text(
        classification_report(y_test, y_pred, target_names=list(LABELS), digits=4, zero_division=0), encoding="utf-8")
    top_features(model).to_csv(results_dir / "top_features.csv", index=False)
    joblib.dump(model, results_dir / "model.joblib")  # load only files you created yourself (pickle-based)
    return summary


def _print_summary(s):
    d, m = s["data"], s["test_metrics"]
    print(f"Samples: total={d['n_total']} train={d['n_train']} test={d['n_test']}")
    print(f"Test class distribution: {d['test_class_distribution']}")
    if "template_holdout" in s:
        s = {**s, "template_holdout_split": s["template_holdout"]["metrics"]}
        print(f"Held-out templates: {s['template_holdout']['held_out_templates']}")
    for name in ("test_metrics", "baseline_majority_class", "robustness_urls_removed_from_test",
                 "template_holdout_split", "leave_one_template_out",
                 "shifted_distribution", "adversarial_handwritten"):
        if name in s:
            x = s[name]
            c = x["confusion_matrix"]
            print(f"{name:34s} n={x['n_samples']:4d} acc={x['accuracy']:.4f} prec={x['precision']:.4f} "
                  f"rec={x['recall']:.4f} f1={x['f1']:.4f}  TN={c['true_negative']} FP={c['false_positive']} "
                  f"FN={c['false_negative']} TP={c['true_positive']}")
    print(f"Test confusion matrix (TN, FP, FN, TP): {list(m['confusion_matrix'].values())}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Train and evaluate the TF-IDF + Logistic Regression classifier.")
    parser.add_argument("--data", type=Path, default=TASK_DIR / "data" / "synthetic_messages.csv")
    parser.add_argument("--shifted", type=Path, default=TASK_DIR / "data" / "shifted_messages.csv")
    parser.add_argument("--adversarial", type=Path, default=TASK_DIR / "data" / "adversarial_handwritten.csv")
    parser.add_argument("--results-dir", type=Path, default=TASK_DIR / "results")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--test-size", type=float, default=TEST_SIZE)
    args = parser.parse_args(argv)
    try:
        summary = run_experiment(args.data, args.shifted, args.adversarial, args.results_dir, args.seed, args.test_size)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_summary(summary)
    print(f"Outputs written to {args.results_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
