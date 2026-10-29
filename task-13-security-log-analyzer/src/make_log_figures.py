"""Draw the report figures for Task 13 from the saved analyzer results.

* ``alerts_timeline.png``      failed logins per 10 minutes, the alerts raised, and the planted attack-like
                               scenarios that raised none (read from the sample log, report.json and the manifest)
* ``settings_comparison.png``  alerts under three threshold/window settings (computed by running the analyzer)
* ``workflow_diagram.png``     the tool's data flow (a drawing, no data)
* ``results/settings_comparison.csv`` the numbers behind the settings chart

Run:  python src/make_log_figures.py        (after python src/cli.py analyze --input data/sample_auth_logs.csv)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

from log_analyzer import AnalyzerConfig, detect
from log_loader import LogValidationError, load_events

TASK_DIR = Path(__file__).resolve().parents[1]
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BLUE, ORANGE, BLUE_LIGHT = "#2a78d6", "#eb6834", "#cde2fb"
SEVERITY_COLORS = {"low": "#86b6ef", "medium": "#2a78d6", "high": "#104281"}  # ordinal blue ramp (step 250/450/650)
RULE_SHORT = {"REPEATED_FAILED_LOGINS": "R1 repeated failures",
              "SUCCESS_AFTER_REPEATED_FAILURES": "R2 success after failures",
              "MULTI_ACCOUNT_FAILURES_FROM_SOURCE": "R3 many accounts, one source"}
SETTINGS = [("Strict", 10, 10.0), ("Default", 5, 10.0), ("Relaxed", 3, 120.0)]  # label, N, W (minutes)
plt.rcParams.update({"figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
                     "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
                     "font.size": 9, "axes.edgecolor": AXIS})


def _clean_axes(ax, grid_axis="y"):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def alerts_timeline(events: pd.DataFrame, report: dict, scenarios: list, path: Path) -> None:
    fails = events[(events["event_type"] == "login") & (events["status"] == "failure")].copy()
    fails["t"] = fails["timestamp"].dt.tz_convert(None)
    bins = fails.set_index("t").resample("10min").size()
    alerts = report["alerts"]

    fig, (top, lanes) = plt.subplots(2, 1, figsize=(7.4, 5.6), sharex=True,
                                     gridspec_kw={"height_ratios": [3, 2], "hspace": 0.08})
    top.bar(bins.index, bins.values, width=pd.Timedelta(minutes=8), align="edge", color=BLUE)
    ymax = max(int(bins.max()), 1)
    top.set_ylim(0, ymax * 1.75)
    top.set_ylabel("Failed logins per 10 min")
    top.set_title("Failed logins over the day, and what the analyzer reported (default settings)",
                  loc="left", fontsize=10, color=INK)
    _clean_axes(top)

    # Attack-like planted scenarios (not benign) that raised no alert: data-driven brackets.
    alerted_users = {u for a in alerts for u in a["usernames"]}
    level = 1.12
    for sc in scenarios:
        if sc.get("benign") or alerted_users & set(sc["usernames"]):
            continue
        mine = fails[fails["username"].isin(sc["usernames"])]
        if len(mine) < 5:
            continue
        t0, t1 = mine["t"].min(), mine["t"].max() + pd.Timedelta(minutes=10)
        y = ymax * level
        top.plot([t0, t1], [y, y], color=ORANGE, linewidth=1.6, solid_capstyle="butt")
        top.plot([t0, t0], [y - ymax * 0.05, y], color=ORANGE, linewidth=1.6)
        top.plot([t1, t1], [y - ymax * 0.05, y], color=ORANGE, linewidth=1.6)
        top.text(t0 + (t1 - t0) / 2, y + ymax * 0.06, f"{sc['id']} {sc['name'].replace('_', ' ')}: no alert",
                 ha="center", va="bottom", fontsize=7.5, color=INK2)
        level += 0.30

    lanes.set_ylim(len(alerts) - 0.4, -0.7)
    lanes.set_yticks(range(len(alerts)), [a["alert_id"] for a in alerts])
    for i, a in enumerate(alerts):
        t0 = pd.Timestamp(a["first_seen"]).tz_convert(None)
        t1 = pd.Timestamp(a["last_seen"]).tz_convert(None)
        lanes.plot([t0, t1], [i, i], color=SEVERITY_COLORS[a["severity"]], linewidth=7, solid_capstyle="round")
        who = ", ".join(a["usernames"]) if len(a["usernames"]) <= 2 else f"{len(a['usernames'])} accounts"
        lanes.text(t1 + pd.Timedelta(minutes=14), i, f"{RULE_SHORT[a['rule']]} · {who} · {a['severity']}",
                   va="center", fontsize=7.5, color=INK2)
    lanes.set_ylabel("Alert")
    _clean_axes(lanes, "x")
    lanes.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    lanes.set_xlabel("Time of day (UTC), 2024-03-04 (synthetic data)")
    handles = [plt.Line2D([0], [0], color=c, linewidth=6, label=k) for k, c in SEVERITY_COLORS.items()]
    lanes.legend(handles=handles, title="Alert severity", loc="upper center", bbox_to_anchor=(0.5, -0.27), ncol=3,
                 frameon=False, fontsize=8, title_fontsize=8)
    lanes.set_xlim(bins.index.min() - pd.Timedelta(minutes=10), bins.index.max() + pd.Timedelta(minutes=190))
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def settings_table(events: pd.DataFrame, scenarios: list) -> pd.DataFrame:
    rows = []
    for label, n, w in SETTINGS:
        alerts = detect(events, AnalyzerConfig(failure_threshold=n, window_minutes=w))
        users = {u for a in alerts for u in a.usernames}
        hit = {s["id"] for s in scenarios if users & set(s["usernames"])}
        rows.append({
            "setting": label, "failure_threshold": n, "window_minutes": w, "spray_user_threshold": 5,
            "total_alerts": len(alerts),
            **{lvl: sum(a.severity == lvl for a in alerts) for lvl in ("low", "medium", "high")},
            "attack_like_scenarios_flagged": ";".join(sorted(s["id"] for s in scenarios if not s["benign"] and s["id"] in hit)),
            "benign_scenarios_flagged": ";".join(sorted(s["id"] for s in scenarios if s["benign"] and s["id"] in hit))})
    return pd.DataFrame(rows)


def settings_comparison(table: pd.DataFrame, scenarios: list, path: Path) -> None:
    n_attack = sum(not s["benign"] for s in scenarios)
    n_benign = sum(s["benign"] for s in scenarios)
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    x = range(len(table))
    bottom = [0] * len(table)
    for lvl in ("low", "medium", "high"):
        vals = table[lvl].tolist()
        ax.bar(x, vals, bottom=bottom, width=0.5, color=SEVERITY_COLORS[lvl], label=lvl,
               edgecolor=SURFACE, linewidth=2)
        for i, (v, b) in enumerate(zip(vals, bottom)):
            if v:
                ax.text(i, b + v / 2, str(v), ha="center", va="center", fontsize=9,
                        color="#0b0b0b" if lvl == "low" else "white")
        bottom = [b + v for b, v in zip(bottom, vals)]
    for i, total in enumerate(table["total_alerts"]):
        ax.text(i, total + 0.15, f"{total} alerts", ha="center", va="bottom", fontsize=9, color=INK)
    labels = []
    for r in table.itertuples():
        flagged_attack = len([s for s in r.attack_like_scenarios_flagged.split(";") if s])
        flagged_benign = len([s for s in r.benign_scenarios_flagged.split(";") if s])
        labels.append(f"{r.setting}\n{r.failure_threshold} failures / {r.window_minutes:g} min\n"
                      f"attack-like flagged: {flagged_attack}/{n_attack}\nbenign flagged: {flagged_benign}/{n_benign}")
    ax.set_xticks(list(x), labels, fontsize=8)
    ax.set_ylabel("Alerts raised")
    ax.set_ylim(0, max(table["total_alerts"].max() + 2, 4))
    ax.set_title("Looser settings find more planted attacks, and flag more benign activity",
                 loc="left", fontsize=10, color=INK)
    _clean_axes(ax)
    ax.legend(title="Severity", loc="upper left", frameon=False, fontsize=8, title_fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def _box(ax, x, y, w, h, text, fill=BLUE_LIGHT, edge=BLUE, size=8.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2",
                                facecolor=fill, edgecolor=edge, linewidth=1.2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, color=INK, linespacing=1.35)


def _arrow(ax, x0, y0, x1, y1, color=INK2):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>", mutation_scale=11, color=color, linewidth=1.1))


def workflow_diagram(path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8.0, 5.8))
    ax.set_xlim(-1, 101)
    ax.set_ylim(-4, 66)
    ax.axis("off")
    grey, orange_fill = "#eeeeea", "#fbd9cb"
    _box(ax, 1, 51, 31, 11, "log_generator.py\nseeded synthetic events\n+ 7 planted scenarios")
    _box(ax, 42, 51, 50, 11, "data/sample_auth_logs.csv  (+ planted_scenarios.json)\nany authorised log in the same format works too")
    _arrow(ax, 32.6, 56.5, 41.4, 56.5)
    _box(ax, 1, 33, 52, 11, "log_loader.py\nstrict CSV parsing + validation of every field\n(line-numbered errors, UTC times, canonical IPs)")
    _arrow(ax, 67, 50.2, 40, 44.8)
    _box(ax, 64, 33, 35, 11, "Invalid input\nclear message on stderr,\nexit code 2", fill=orange_fill, edge=ORANGE)
    _arrow(ax, 54.2, 38.5, 63.4, 38.5)
    _box(ax, 1, 15, 52, 12, "log_analyzer.py\nsummarize(): counts, time range, top failing IPs\ndetect(): R3 spray -> R1 bursts -> R2 success after failures\n(severity + reasons + evidence per alert)", size=8)
    _arrow(ax, 27, 32.2, 27, 27.9)
    _box(ax, 64, 15, 35, 12, "cli.py (runs every step)\ngenerate | analyze\noptions, --fail-on,\nexit codes 0 / 1 / 2", fill=grey, edge=MUTED)
    _box(ax, 1, -3, 52, 10, "log_report.py -> results/\nreport.json · alerts.csv · console summary", fill=grey, edge=MUTED)
    _arrow(ax, 27, 14.2, 27, 7.9)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Draw Task 13 figures from saved results.")
    parser.add_argument("--input", type=Path, default=TASK_DIR / "data" / "sample_auth_logs.csv")
    parser.add_argument("--manifest", type=Path, default=TASK_DIR / "data" / "planted_scenarios.json")
    parser.add_argument("--results-dir", type=Path, default=TASK_DIR / "results")
    parser.add_argument("--out-dir", type=Path, default=None, help="default: <results-dir>/figures")
    args = parser.parse_args(argv)
    out = args.out_dir or args.results_dir / "figures"
    try:
        events = load_events(args.input)
        report = json.loads((args.results_dir / "report.json").read_text(encoding="utf-8"))
        scenarios = json.loads(args.manifest.read_text(encoding="utf-8"))["scenarios"]
    except (LogValidationError, FileNotFoundError) as exc:
        print(f"error: {exc}. Run 'python src/cli.py analyze --input data/sample_auth_logs.csv' first.", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    table = settings_table(events, scenarios)
    table.to_csv(args.results_dir / "settings_comparison.csv", index=False)
    alerts_timeline(events, report, scenarios, out / "alerts_timeline.png")
    settings_comparison(table, scenarios, out / "settings_comparison.png")
    workflow_diagram(out / "workflow_diagram.png")
    print(f"Wrote 3 figures to {out} and {args.results_dir / 'settings_comparison.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
