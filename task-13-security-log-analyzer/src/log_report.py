"""Build and write the analyzer's JSON / CSV reports and the console summary (Task 13)."""

from __future__ import annotations

import json
import textwrap
from dataclasses import asdict
from pathlib import Path

import pandas as pd

from log_analyzer import LEVELS, AnalyzerConfig

TOOL_NAME = "auth-log-analyzer"
TOOL_VERSION = "1.0.0"
NOTICE = ("Alerts mark patterns that warrant investigation. They are not confirmed incidents, and the absence of an "
          "alert does not mean the activity is safe. Intended for synthetic or authorised logs only.")

CSV_COLUMNS = ["alert_id", "severity", "rule", "title", "usernames", "source_ip", "first_seen", "last_seen",
               "event_count", "description", "severity_reasons", "evidence_lines", "evidence_omitted",
               "recommended_steps", "disposition"]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection: log-derived text must not run as a formula in Excel/Sheets."""
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def build_report(summary: dict, alerts: list, config: AnalyzerConfig, input_name: str) -> dict:
    counts = {level: sum(a.severity == level for a in alerts) for level in reversed(LEVELS)}
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "input_file": input_name,
        "notice": NOTICE,
        "config": asdict(config),
        "summary": summary,
        "alert_counts": {"total": len(alerts), **counts},
        "alerts": [a.to_dict() for a in alerts],
    }


def write_json(report: dict, path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path


def write_csv(alerts: list, path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for a in alerts:
        rows.append({
            "alert_id": a.alert_id, "severity": a.severity, "rule": a.rule, "title": a.title,
            "usernames": ";".join(csv_safe(u) for u in a.usernames), "source_ip": a.source_ip,
            "first_seen": a.first_seen, "last_seen": a.last_seen, "event_count": a.event_count,
            "description": csv_safe(a.description), "severity_reasons": " | ".join(a.severity_reasons),
            "evidence_lines": ";".join(str(e["line"]) for e in a.evidence), "evidence_omitted": a.evidence_omitted,
            "recommended_steps": " | ".join(a.recommended_steps), "disposition": a.disposition})
    pd.DataFrame(rows, columns=CSV_COLUMNS).to_csv(path, index=False, encoding="utf-8")
    return path


def format_console(report: dict) -> str:
    s, c = report["summary"], report["alert_counts"]
    lines = [
        f"Authentication log summary: {report['input_file']}",
        f"  Total events:        {s['total_events']}",
        f"  Successful logins:   {s['successful_logins']}",
        f"  Failed logins:       {s['failed_logins']}",
        f"  Unique users:        {s['unique_users']}",
        f"  Unique source IPs:   {s['unique_source_ips']}",
        f"  Time range (UTC):    {s['first_event']} -> {s['last_event']}",
        "",
        f"Alerts: {c['total']} (high {c['high']}, medium {c['medium']}, low {c['low']})",
    ]
    for a in report["alerts"]:
        who = ",".join(a["usernames"]) if len(a["usernames"]) <= 3 else f"{len(a['usernames'])} accounts"
        lines.append(f"  [{a['alert_id']}] {a['severity'].upper():6s} {a['rule']}  user={who}  src={a['source_ip']}  "
                     f"events={a['event_count']}  {a['first_seen']}")
    lines += [""] + textwrap.wrap(NOTICE, width=110)  # wrapped for readable terminals; the JSON keeps one line
    return "\n".join(lines)
