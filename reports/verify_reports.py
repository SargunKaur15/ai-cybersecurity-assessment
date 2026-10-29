"""Check that numbers in the READMEs and reports match the saved results.

    python reports/verify_reports.py

What is checked (nothing is "fixed" automatically):
  * every 4-decimal figure written in a README/report exists in that task's result files
  * headline tables are rebuilt from metrics.json / report.json / settings_comparison.csv and must appear verbatim
  * console transcripts pasted into the reports equal the saved console output files
  * test counts (total and per file) match results/pytest_output.txt
  * stale test counts, missing figures and broken relative links are flagged
Exit code 0 = everything matches; 1 = at least one mismatch (listed).
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
T14, T13 = ROOT / "task-14-ai-phishing-evaluation", ROOT / "task-13-security-log-analyzer"
errors: list[str] = []


def check(cond: bool, message: str) -> None:
    if not cond:
        errors.append(message)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def tokens4(text: str) -> set[str]:
    return set(re.findall(r"\b\d\.\d{4}\b", text))


def result_numbers(results: Path) -> set[str]:
    nums: set[str] = set()

    def walk(obj):
        if isinstance(obj, float):
            nums.add(f"{obj:.4f}")
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    for p in results.rglob("*"):
        if p.suffix == ".json":
            walk(json.loads(read(p)))
        elif p.suffix in {".csv", ".txt"}:
            text = read(p)
            nums |= tokens4(text)
            if p.suffix == ".csv":
                for row in csv.reader(text.splitlines()):
                    for cell in row:
                        try:
                            nums.add(f"{float(cell):.4f}")
                        except ValueError:
                            pass
    return nums


def pytest_summary(results: Path, prefix: str):
    text = read(results / "pytest_output.txt")
    m = re.search(r"=+ (\d+) passed in ([\d.]+)s =+", text)
    check(bool(m), f"{results.name}: could not parse the pytest summary line")
    per_file = {}
    for name in sorted(set(re.findall(rf"(test_{prefix}_\w+\.py)::", text))):
        per_file[name] = len(re.findall(rf"{re.escape(name)}::.*PASSED", text))
    total = int(m.group(1)) if m else -1
    check(sum(per_file.values()) == total, f"{results.name}: per-file counts {per_file} do not add up to {total}")
    return total, (m.group(2) if m else "?"), per_file


def transcript_lines_present(report: str, transcript: Path, label: str) -> None:
    for line in read(transcript).splitlines():
        if line.strip():
            check(line.rstrip() in report, f"{label}: transcript line missing from the report: {line[:90]!r}")


def doc_checks(doc_path: Path, allowed_counts: set[int]) -> None:
    text = read(doc_path)
    rel = doc_path.relative_to(ROOT)
    for m in re.finditer(r"\b(\d+) (?:passed|pytest tests|tests)\b", text):
        n = int(m.group(1))
        check(n in allowed_counts, f"{rel}: stale or unknown test count '{m.group(0)}'")
    for target in re.findall(r"!?\[[^\]]*\]\(([^)#\s]+)\)", text):
        if not target.startswith(("http://", "https://", "mailto:")):
            check((doc_path.parent / target).exists(), f"{rel}: broken relative link/image '{target}'")


def verify_task14() -> int:
    results, report = T14 / "results", read(T14 / "report.md")
    readme = read(T14 / "README.md")
    m = json.loads(read(results / "metrics.json"))
    numbers = result_numbers(results)
    for label, text in (("task-14 report.md", report), ("task-14 README.md", readme)):
        for tok in sorted(tokens4(text) - numbers):
            check(False, f"{label}: figure {tok} does not appear in any saved result file")

    rows = [("Stratified random split", m["test_metrics"]), ("Same, URLs removed", m["robustness_urls_removed_from_test"]),
            ("**Template-held-out split**", m["template_holdout"]["metrics"]), ("**Leave-one-template-out**", m["leave_one_template_out"]),
            ("Shifted distribution", m["shifted_distribution"]), ("Hand-written adversarial", m["adversarial_handwritten"])]
    for name, x in rows:
        c = x["confusion_matrix"]
        expected = (f"| {name} | {x['n_samples']:,} | {x['accuracy']:.4f} | {x['precision']:.4f} | {x['recall']:.4f} | "
                    f"{x['f1']:.4f} | {c['false_positive']} | {c['false_negative']} |")
        check(expected in report, f"task-14 report: comparison row not found: {expected}")

    d, th = m["data"], m["template_holdout"]
    templates = len({r["template_id"] for r in csv.DictReader(read(T14 / "data" / "synthetic_messages.csv").splitlines())})
    held = len(th["held_out_templates"])
    for expected in (
            f"| Full dataset | {d['n_total']:,} | {d['train_class_distribution']['phishing'] + d['test_class_distribution']['phishing']} | "
            f"{d['train_class_distribution']['legitimate'] + d['test_class_distribution']['legitimate']} |",
            f"| Stratified split: training | {d['n_train']:,} | {d['train_class_distribution']['phishing']} | {d['train_class_distribution']['legitimate']} |",
            f"| **Stratified split: test** | **{d['n_test']}** | **{d['test_class_distribution']['phishing']}** | **{d['test_class_distribution']['legitimate']}** |",
            f"| Template-held-out split: training ({templates - held} templates) | {th['n_train']} | {th['train_class_distribution']['phishing']} | {th['train_class_distribution']['legitimate']} |",
            f"| **Template-held-out split: test ({held} templates)** | **{th['n_test']}** | **{th['test_class_distribution']['phishing']}** | **{th['test_class_distribution']['legitimate']}** |"):
        check(expected in report, f"task-14 report: dataset row not found: {expected}")
    check(f"{templates} templates" in report, f"task-14 report: should mention {templates} templates")

    total, secs, per_file = pytest_summary(results, "phishing")
    check(f"**{total} passed in {secs} s**" in report, f"task-14 report: expected '**{total} passed in {secs} s**'")
    check(f"**{total} passed in {secs} s**" in readme, f"task-14 README: expected '**{total} passed in {secs} s**'")
    for name, count in per_file.items():
        check(f"`{name}`, {count} tests" in report, f"task-14 report: per-file count for {name} should be {count}")
        check(f"`{name}` | {count} |" in readme, f"task-14 README: per-file count for {name} should be {count}")
    transcript_lines_present(report, results / "train_evaluate_output.txt", "task-14 report")
    for fig in ("workflow_diagram", "metrics_by_evaluation", "loto_per_template", "confusion_matrices_compared"):
        check((results / "figures" / f"{fig}.png").exists() and f"results/figures/{fig}.png" in report, f"task-14: figure {fig} missing or not used")
    doc_checks(T14 / "report.md", {total, *per_file.values()})
    doc_checks(T14 / "README.md", {total, *per_file.values()})
    return total


def verify_task13() -> int:
    results, report = T13 / "results", read(T13 / "report.md")
    readme = read(T13 / "README.md")
    rep = json.loads(read(results / "report.json"))
    numbers = result_numbers(results)
    for label, text in (("task-13 report.md", report), ("task-13 README.md", readme)):
        for tok in sorted(tokens4(text) - numbers):
            check(False, f"{label}: figure {tok} does not appear in any saved result file")
    s = rep["summary"]
    check(f"{s['total_events']} events (" in report and f"{s['successful_logins']} successful and {s['failed_logins']} failed logins, "
          f"{s['unique_users']} users, {s['unique_source_ips']} source addresses" in report, "task-13 report: abstract summary counts differ from report.json")
    c = rep["alert_counts"]
    check(f"Counts: {c['total']} alerts ({c['high']} high, {c['medium']} medium, {c['low']} low)" in report, "task-13 report: alert counts differ from report.json")
    for a in rep["alerts"]:
        check(f"| {a['alert_id']} | {a['severity']} | {a['rule']} |" in report, f"task-13 report: alert row {a['alert_id']} not found")
        check(f"| {a['source_ip']} | {a['event_count']} | {a['first_seen'][11:19]} |" in report, f"task-13 report: alert {a['alert_id']} ip/count/time not found")
    with open(results / "settings_comparison.csv", newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            expected = (f"| {r['setting']} | {r['failure_threshold']} / {float(r['window_minutes']):g} min | "
                        f"{r['total_alerts']} ({r['low']} / {r['medium']} / {r['high']}) |")
            check(expected in report, f"task-13 report: settings row not found: {expected}")
    total, secs, per_file = pytest_summary(results, "log")
    check(f"**{total} passed in {secs} s**" in report, f"task-13 report: expected '**{total} passed in {secs} s**'")
    check(f"**{total} passed in {secs} s**" in readme, f"task-13 README: expected '**{total} passed in {secs} s**'")
    for name, count in per_file.items():
        check(f"| `{name}` | {count} |" in report, f"task-13 report: per-file count for {name} should be {count}")
    for transcript in ("cli_analyze_output.txt", "example_invalid_input_output.txt"):
        transcript_lines_present(report, results / transcript, "task-13 report")
    for fig in ("workflow_diagram", "alerts_timeline", "settings_comparison"):
        check((results / "figures" / f"{fig}.png").exists() and f"results/figures/{fig}.png" in report, f"task-13: figure {fig} missing or not used")
    doc_checks(T13 / "report.md", {total, *per_file.values()})
    doc_checks(T13 / "README.md", {total, *per_file.values()})
    return total


def main(argv=None) -> int:
    t14_total, t13_total = verify_task14(), verify_task13()
    root = read(ROOT / "README.md")
    both = t14_total + t13_total
    check(f"**{both} passed**" in root and f"{t14_total} for Task 14" in root and f"{t13_total} for Task 13" in root,
          f"root README: expected '**{both} passed**' ({t14_total} for Task 14, {t13_total} for Task 13)")
    doc_checks(ROOT / "README.md", {both, t14_total, t13_total})
    for tok in sorted(tokens4(root) - result_numbers(T14 / "results") - result_numbers(T13 / "results")):
        check(False, f"root README: figure {tok} does not appear in any saved result file")
    placeholders = sum(len(re.findall(r"\[(?:STUDENT NAME|ID:|DATE:|GitHub URL|SCREENSHOT PLACEHOLDER)", read(p))) for p in (T14 / "report.md", T13 / "report.md"))
    if errors:
        print(f"FAILED: {len(errors)} problem(s)")
        for e in errors:
            print("  -", e)
        return 1
    print(f"OK: all checked numbers, tables, transcripts, counts and links match ({t14_total} + {t13_total} = {both} tests).")
    print(f"Note: {placeholders} marked placeholder(s) remain in the report.md files (student ID, submission date and repository URL on each title page).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
