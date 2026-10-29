"""Score a new SYNTHETIC message with the trained TF-IDF + Logistic Regression model (Task 14).

Usage:
    python src/predict.py "URGENT: verify your account at http://account-verify.example.net/login"
    python src/predict.py --file messages.txt          # one message per line

The output is a demonstration of a small model trained on synthetic data. It is NOT a
verdict on whether a real message is safe, and must not be used as a security control.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib

TASK_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = TASK_DIR / "results" / "model.joblib"
DISCLAIMER = "Note: research demo trained on synthetic data; not a reliable or standalone security control."


def load_model(path):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Model not found: {path}. Run 'python src/train_evaluate.py' first.")
    return joblib.load(path)  # pickle-based: only load model files you created yourself


def predict_messages(model, messages, threshold=0.5):
    """Return a list of dicts: message, phishing_probability, verdict."""
    if not 0.0 < threshold < 1.0:
        raise ValueError("threshold must be strictly between 0 and 1")
    cleaned = []
    for m in messages:
        if not isinstance(m, str) or not m.strip():
            raise ValueError("Messages must be non-empty strings")
        cleaned.append(m.strip())
    if not cleaned:
        raise ValueError("No messages to score")
    probs = model.predict_proba(cleaned)[:, 1]
    return [{"message": m, "phishing_probability": round(float(p), 4),
             "verdict": "phishing-like" if p >= threshold else "legitimate-like"}
            for m, p in zip(cleaned, probs)]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Classify a synthetic message as phishing-like or legitimate-like.")
    parser.add_argument("message", nargs="?", help="message text to score")
    parser.add_argument("--file", type=Path, help="text file with one message per line")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args(argv)

    try:
        if args.file:
            if not args.file.is_file():
                raise FileNotFoundError(f"Input file not found: {args.file}")
            messages = [ln for ln in args.file.read_text(encoding="utf-8").splitlines() if ln.strip()]
        elif args.message is not None:
            messages = [args.message]
        else:
            parser.error("provide a message or --file")
        results = predict_messages(load_model(args.model), messages, args.threshold)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for r in results:
        print(f"{r['verdict']:16s} P(phishing)={r['phishing_probability']:.4f}  | {r['message'][:100]}")
    print(DISCLAIMER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
