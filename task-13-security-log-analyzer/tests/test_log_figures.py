from pathlib import Path

import pandas as pd

from cli import main as cli_main
from make_log_figures import main as make_figures

SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample_auth_logs.csv"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def test_figures_and_settings_table_are_written(tmp_path):
    assert cli_main(["analyze", "--input", str(SAMPLE), "--output-dir", str(tmp_path)]) == 0
    assert make_figures(["--results-dir", str(tmp_path)]) == 0
    for name in ("alerts_timeline", "settings_comparison", "workflow_diagram"):
        data = (tmp_path / "figures" / f"{name}.png").read_bytes()
        assert data.startswith(PNG_SIGNATURE) and len(data) > 5_000


def test_settings_table_matches_the_cli_default_run(tmp_path):
    cli_main(["analyze", "--input", str(SAMPLE), "--output-dir", str(tmp_path)])
    make_figures(["--results-dir", str(tmp_path)])
    table = pd.read_csv(tmp_path / "settings_comparison.csv", keep_default_na=False).set_index("setting")
    assert table.loc["Default", "total_alerts"] == 5
    assert list(table.index) == ["Strict", "Default", "Relaxed"]
    assert table["total_alerts"].is_monotonic_increasing          # looser settings never raise fewer alerts here
    assert table.loc["Default", "benign_scenarios_flagged"] == "S5"
    assert "S6" in table.loc["Relaxed", "attack_like_scenarios_flagged"]


def test_missing_report_exits_2(tmp_path, capsys):
    assert make_figures(["--results-dir", str(tmp_path)]) == 2
    assert "analyze" in capsys.readouterr().err
