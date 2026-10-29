import json

import pytest

from generate_dataset import generate_dataset, generate_shifted_dataset
from make_phishing_figures import main as make_figures
from train_evaluate import run_experiment

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@pytest.fixture(scope="module")
def results_dir(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("figs")
    generate_dataset(n_total=300, seed=5).to_csv(tmp / "main.csv", index=False)
    generate_shifted_dataset(n_total=60, seed=6).to_csv(tmp / "shifted.csv", index=False)
    run_experiment(tmp / "main.csv", tmp / "shifted.csv", None, tmp / "results", seed=11)
    return tmp / "results"


def test_figures_are_written_as_valid_pngs(results_dir):
    assert make_figures(["--results-dir", str(results_dir)]) == 0
    for name in ("metrics_by_evaluation", "loto_per_template", "confusion_matrices_compared", "workflow_diagram"):
        data = (results_dir / "figures" / f"{name}.png").read_bytes()
        assert data.startswith(PNG_SIGNATURE) and len(data) > 5_000


def test_missing_results_exit_2(tmp_path, capsys):
    assert make_figures(["--results-dir", str(tmp_path)]) == 2
    assert "train_evaluate.py" in capsys.readouterr().err


def test_figures_use_the_saved_numbers(results_dir):
    metrics = json.loads((results_dir / "metrics.json").read_text(encoding="utf-8"))
    assert {"test_metrics", "template_holdout", "leave_one_template_out"} <= set(metrics)
