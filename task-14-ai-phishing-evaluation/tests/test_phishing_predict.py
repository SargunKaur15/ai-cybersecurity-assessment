import joblib
import pytest

from predict import DISCLAIMER, main, predict_messages

PHISHY = ("URGENT: your email account will be suspended in 6 hours unless you verify your identity. "
          "Sign in here: http://account-verify.example.net/login")
ROUTINE = "Hello Sam, reminder: team meeting on Monday at 10:00 in room B12. Agenda: budget check-in."


@pytest.fixture()
def model_path(trained_model, tmp_path):
    path = tmp_path / "model.joblib"
    joblib.dump(trained_model, path)
    return path


def test_predict_messages_returns_expected_fields(trained_model):
    out = predict_messages(trained_model, [PHISHY, ROUTINE])
    assert [r["verdict"] for r in out] == ["phishing-like", "legitimate-like"]
    assert all(0.0 <= r["phishing_probability"] <= 1.0 for r in out)


def test_threshold_changes_verdict(trained_model):
    assert predict_messages(trained_model, [PHISHY], threshold=0.99999)[0]["verdict"] == "legitimate-like"


@pytest.mark.parametrize("bad", [[""], ["   "], [None], [123], []])
def test_invalid_messages_rejected(trained_model, bad):
    with pytest.raises(ValueError):
        predict_messages(trained_model, bad)


@pytest.mark.parametrize("threshold", [0, 1, -0.5, 2])
def test_invalid_threshold_rejected(trained_model, threshold):
    with pytest.raises(ValueError):
        predict_messages(trained_model, [ROUTINE], threshold=threshold)


def test_cli_single_message(model_path, capsys):
    assert main([PHISHY, "--model", str(model_path)]) == 0
    out = capsys.readouterr().out
    assert "phishing-like" in out and "P(phishing)=" in out and DISCLAIMER in out


def test_cli_file_input_skips_blank_lines(model_path, tmp_path, capsys):
    f = tmp_path / "msgs.txt"
    f.write_text(f"{PHISHY}\n\n{ROUTINE}\n", encoding="utf-8")
    assert main(["--file", str(f), "--model", str(model_path)]) == 0
    assert capsys.readouterr().out.count("P(phishing)=") == 2


def test_cli_missing_model_exits_2(tmp_path, capsys):
    assert main([ROUTINE, "--model", str(tmp_path / "none.joblib")]) == 2
    assert "Model not found" in capsys.readouterr().err


def test_cli_blank_message_exits_2(model_path, capsys):
    assert main(["   ", "--model", str(model_path)]) == 2
    assert "non-empty" in capsys.readouterr().err


def test_cli_missing_input_file_exits_2(model_path, tmp_path, capsys):
    assert main(["--file", str(tmp_path / "none.txt"), "--model", str(model_path)]) == 2
