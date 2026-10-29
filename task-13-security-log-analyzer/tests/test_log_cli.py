import csv
import json
from pathlib import Path

import pytest

from cli import main
from log_report import csv_safe

HEADER = "timestamp,username,source_ip,event_type,status\n"
SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample_auth_logs.csv"


def burst_file(tmp_path, user="alice", n=5):
    rows = "".join(f"2024-03-04T10:00:{i * 5:02d}Z,{user},192.0.2.1,login,failure\n" for i in range(n))
    p = tmp_path / "burst.csv"
    p.write_text(HEADER + rows, encoding="utf-8")
    return p


def test_analyze_sample_writes_reports_and_prints_summary(tmp_path, capsys):
    assert main(["analyze", "--input", str(SAMPLE), "--output-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Total events:        119" in out and "Alerts: 5" in out
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["total_events"] == 119 and report["alert_counts"]["total"] == 5
    assert all(a["evidence"] and a["severity_reasons"] for a in report["alerts"])
    with open(tmp_path / "alerts.csv", newline="", encoding="utf-8") as fh:
        assert len(list(csv.DictReader(fh))) == 5


def test_format_json_only(tmp_path):
    assert main(["analyze", "--input", str(SAMPLE), "--output-dir", str(tmp_path), "--format", "json"]) == 0
    assert (tmp_path / "report.json").exists() and not (tmp_path / "alerts.csv").exists()


def test_threshold_options_are_applied(tmp_path):
    p = burst_file(tmp_path, n=3)
    assert main(["analyze", "--input", str(p), "--output-dir", str(tmp_path / "a")]) == 0
    assert json.loads((tmp_path / "a" / "report.json").read_text())["alert_counts"]["total"] == 0
    assert main(["analyze", "--input", str(p), "--output-dir", str(tmp_path / "b"), "--failure-threshold", "3"]) == 0
    assert json.loads((tmp_path / "b" / "report.json").read_text())["alert_counts"]["total"] == 1


def test_empty_dataset_is_handled(tmp_path, capsys):
    p = tmp_path / "empty.csv"
    p.write_text(HEADER, encoding="utf-8")
    assert main(["analyze", "--input", str(p), "--output-dir", str(tmp_path / "o")]) == 0
    assert "Alerts: 0" in capsys.readouterr().out
    assert json.loads((tmp_path / "o" / "report.json").read_text())["summary"]["total_events"] == 0


def test_missing_input_exits_2(tmp_path, capsys):
    assert main(["analyze", "--input", str(tmp_path / "nope.csv"), "--output-dir", str(tmp_path)]) == 2
    assert "not found" in capsys.readouterr().err


def test_invalid_content_exits_2_with_line_number(tmp_path, capsys):
    p = tmp_path / "bad.csv"
    p.write_text(HEADER + "2024-03-04T10:00:00Z,a,999.9.9.9,login,failure\n", encoding="utf-8")
    assert main(["analyze", "--input", str(p), "--output-dir", str(tmp_path)]) == 2
    assert "line 2" in capsys.readouterr().err


def test_invalid_options_exit_2(tmp_path, capsys):
    assert main(["analyze", "--input", str(SAMPLE), "--output-dir", str(tmp_path), "--failure-threshold", "1"]) == 2
    assert "failure_threshold" in capsys.readouterr().err


def test_missing_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


@pytest.mark.parametrize("level,expected", [("low", 1), ("medium", 1), ("high", 0)])
def test_fail_on_uses_alert_severity(tmp_path, level, expected):
    # sample data contains medium and low alerts but no high alert
    assert main(["analyze", "--input", str(SAMPLE), "--output-dir", str(tmp_path), "--fail-on", level]) == expected


def test_fail_on_with_no_alerts_returns_0(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text(HEADER, encoding="utf-8")
    assert main(["analyze", "--input", str(p), "--output-dir", str(tmp_path / "o"), "--fail-on", "low"]) == 0


def test_generate_command_writes_log_and_manifest(tmp_path, capsys):
    out = tmp_path / "gen" / "log.csv"
    assert main(["generate", "--output", str(out), "--seed", "7"]) == 0
    assert out.exists() and (out.parent / "planted_scenarios.json").exists()
    assert main(["analyze", "--input", str(out), "--output-dir", str(tmp_path / "r")]) == 0   # round trip


def test_csv_report_neutralises_spreadsheet_formulas(tmp_path):
    p = burst_file(tmp_path, user="=sum(1+1)")
    assert main(["analyze", "--input", str(p), "--output-dir", str(tmp_path / "o")]) == 0
    with open(tmp_path / "o" / "alerts.csv", newline="", encoding="utf-8") as fh:
        row = next(csv.DictReader(fh))
    assert row["usernames"].startswith("'=")


@pytest.mark.parametrize("value,expected", [("=1+1", "'=1+1"), ("+x", "'+x"), ("-x", "'-x"), ("@x", "'@x"),
                                            ("alice", "alice"), ("a=b", "a=b")])
def test_csv_safe(value, expected):
    assert csv_safe(value) == expected
