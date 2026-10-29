"""Command-line interface for the authentication log analyzer (Task 13).

    python src/cli.py generate [--output data/sample_auth_logs.csv] [--seed 42]
    python src/cli.py analyze  --input data/sample_auth_logs.csv [--output-dir results] [options]

Exit codes: 0 success; 1 an alert at or above --fail-on was raised; 2 invalid input or options.
Use only on synthetic or authorised logs.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from log_analyzer import LEVELS, AnalyzerConfig, detect, summarize
from log_generator import SEED, generate_events
from log_loader import LogValidationError, load_events
from log_report import build_report, format_console, write_csv, write_json

TASK_DIR = Path(__file__).resolve().parents[1]
logger = logging.getLogger("auth_log_analyzer")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cli.py", description="Summarise authentication logs and flag suspicious patterns.")
    parser.add_argument("-v", "--verbose", action="store_true", help="log progress to stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="write a synthetic authentication log")
    gen.add_argument("--output", type=Path, default=TASK_DIR / "data" / "sample_auth_logs.csv")
    gen.add_argument("--seed", type=int, default=SEED)

    ana = sub.add_parser("analyze", help="analyse a CSV log and write an alert report")
    ana.add_argument("--input", type=Path, required=True, help="CSV with timestamp,username,source_ip,event_type,status")
    ana.add_argument("--output-dir", type=Path, default=TASK_DIR / "results")
    ana.add_argument("--format", choices=["json", "csv", "both"], default="both")
    d = AnalyzerConfig()
    ana.add_argument("--failure-threshold", type=int, default=d.failure_threshold, help="failures that make a burst (default %(default)s)")
    ana.add_argument("--window-minutes", type=float, default=d.window_minutes, help="burst/spray window (default %(default)s)")
    ana.add_argument("--success-window-minutes", type=float, default=d.success_window_minutes,
                     help="how soon after a burst a success is reported (default %(default)s)")
    ana.add_argument("--spray-threshold", type=int, default=d.spray_user_threshold,
                     help="distinct accounts that make a multi-account pattern (default %(default)s)")
    ana.add_argument("--fail-on", choices=LEVELS, help="exit with code 1 if an alert of this severity or higher exists")
    return parser


def _cmd_generate(args) -> int:
    events, scenarios = generate_events(args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    events.to_csv(args.output, index=False)
    manifest = args.output.with_name("planted_scenarios.json")
    manifest.write_text(json.dumps({"seed": args.seed, "note": "Synthetic data. Describes what was planted and what the "
                                    "default configuration is expected to report.", "scenarios": scenarios}, indent=2) + "\n",
                        encoding="utf-8")
    print(f"Wrote {len(events)} synthetic events to {args.output}")
    print(f"Wrote scenario descriptions to {manifest}")
    return 0


def _cmd_analyze(args) -> int:
    config = AnalyzerConfig(failure_threshold=args.failure_threshold, window_minutes=args.window_minutes,
                            success_window_minutes=args.success_window_minutes, spray_user_threshold=args.spray_threshold)
    events = load_events(args.input)
    alerts = detect(events, config)
    report = build_report(summarize(events), alerts, config, args.input.name)
    written = []
    if args.format in ("json", "both"):
        written.append(write_json(report, args.output_dir / "report.json"))
    if args.format in ("csv", "both"):
        written.append(write_csv(alerts, args.output_dir / "alerts.csv"))
    print(format_console(report))
    for path in written:
        print(f"Wrote {path}")
    if args.fail_on and any(LEVELS.index(a["severity"]) >= LEVELS.index(args.fail_on) for a in report["alerts"]):
        return 1
    return 0


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        return _cmd_generate(args) if args.command == "generate" else _cmd_analyze(args)
    except (LogValidationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
