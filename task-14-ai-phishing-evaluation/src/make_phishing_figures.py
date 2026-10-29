"""Draw the report figures for Task 14 from the saved experiment results.

Charts read ``results/metrics.json`` and the per-template CSVs, so every number shown comes from
an actual run of ``train_evaluate.py``. The workflow diagram is a drawing (no data).

Run:  python src/make_phishing_figures.py        (after python src/train_evaluate.py)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

TASK_DIR = Path(__file__).resolve().parents[1]

# Reference palette (validated): blue/orange categorical slots, blue sequential ramp, neutral chrome.
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BLUE, ORANGE = "#2a78d6", "#eb6834"
BLUE_LIGHT, BLUE_DARK = "#cde2fb", "#0d366b"
plt.rcParams.update({"figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
                     "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
                     "font.size": 9, "axes.edgecolor": AXIS})


def _clean_axes(ax, grid_axis="x"):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def metrics_by_evaluation(metrics: dict, path: Path) -> None:
    rows = [("Stratified random split", metrics["test_metrics"]),
            ("Template-held-out split", metrics.get("template_holdout", {}).get("metrics")),
            ("Leave-one-template-out", metrics.get("leave_one_template_out")),
            ("Shifted distribution", metrics.get("shifted_distribution")),
            ("Hand-written adversarial", metrics.get("adversarial_handwritten"))]
    rows = [(name, m) for name, m in rows if m]
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    y = np.arange(len(rows))[::-1]
    h = 0.30
    for offset, key, color, label in ((h / 2 + 0.02, "precision", BLUE, "Precision"),
                                      (-h / 2 - 0.02, "recall", ORANGE, "Recall")):
        values = [m[key] for _, m in rows]
        ax.barh(y + offset, values, height=h, color=color, label=label)
        for yy, v in zip(y + offset, values):
            ax.text(v + 0.01, yy, f"{v:.3f}", va="center", ha="left", fontsize=8, color=INK2)
    ax.set_yticks(y, [f"{name}\n(n={m['n_samples']})" for name, m in rows])
    ax.set_xlim(0, 1.12)
    ax.set_xlabel("Score (phishing = positive class)")
    ax.set_title("Precision and recall under progressively harder evaluations", loc="left", fontsize=10, color=INK)
    _clean_axes(ax)
    ax.legend(loc="lower left", bbox_to_anchor=(0.0, -0.32), ncol=2, frameon=False)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def loto_per_template(table: pd.DataFrame, path: Path) -> None:
    table = table.copy()
    table["order"] = table["label"].map({"phishing": 0, "legitimate": 1})
    table = table.sort_values(["order", "correct_rate", "template_id"], ascending=[True, True, True])
    fig, ax = plt.subplots(figsize=(7.2, 7.4))
    y = np.arange(len(table))
    colors = [BLUE if lab == "phishing" else ORANGE for lab in table["label"]]
    ax.barh(y, table["correct_rate"], height=0.62, color=colors)
    for yy, rate, n in zip(y, table["correct_rate"], table["n"]):
        if rate < 1.0:
            ax.text(rate + 0.01, yy, f"{rate:.2f}  (n={n})", va="center", fontsize=7.5, color=INK2)
    ax.set_yticks(y, [f"{t}  {c}" for t, c in zip(table["template_id"], table["category"])], fontsize=7.5)
    ax.set_xlim(0, 1.25)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xlabel("Share of the template's messages classified correctly")
    ax.set_title("Leave-one-template-out: correct-classification rate per template",
                 loc="left", fontsize=10, color=INK)
    _clean_axes(ax)
    ax.invert_yaxis()
    handles = [plt.Rectangle((0, 0), 1, 1, color=BLUE), plt.Rectangle((0, 0), 1, 1, color=ORANGE)]
    ax.legend(handles, ["Phishing template (= recall)", "Legitimate template (= correctly passed)"],
              loc="lower left", bbox_to_anchor=(0.0, -0.10), ncol=2, frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def confusion_side_by_side(metrics: dict, path: Path) -> None:
    panels = [("Stratified random split", metrics["test_metrics"]),
              ("Template-held-out split", metrics["template_holdout"]["metrics"])]
    cmap = LinearSegmentedColormap.from_list("seq_blue", [BLUE_LIGHT, BLUE_DARK])
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.5))
    for ax, (name, m) in zip(axes, panels):
        c = m["confusion_matrix"]
        cm = np.array([[c["true_negative"], c["false_positive"]], [c["false_negative"], c["true_positive"]]])
        ax.imshow(cm, cmap=cmap, vmin=0, vmax=max(cm.max(), 1))
        ax.set_xticks([0, 1], ["legitimate", "phishing"])
        ax.set_yticks([0, 1], ["legitimate", "phishing"])
        ax.set_xlabel("Predicted label")
        ax.set_title(f"{name} (n={m['n_samples']})", fontsize=9, color=INK)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=15,
                        color="white" if cm[i, j] > cm.max() * 0.45 else INK)
        for side in ax.spines.values():
            side.set_visible(False)
    axes[0].set_ylabel("True label")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def _box(ax, x, y, w, h, text, fill=BLUE_LIGHT, edge=BLUE, size=8.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2",
                                facecolor=fill, edgecolor=edge, linewidth=1.2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, color=INK, linespacing=1.35)


def _arrow(ax, x0, y0, x1, y1):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>", mutation_scale=11, color=INK2, linewidth=1.1))


def workflow_diagram(path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8.0, 5.6))
    ax.set_xlim(-1, 101)
    ax.set_ylim(-3, 64)
    ax.axis("off")
    orange_fill = "#fbd9cb"
    _box(ax, 2, 49, 27, 10, "generate_dataset.py\nseeded templates + noise")
    _box(ax, 38, 49, 38, 10, "data/ CSV files\nmain 1,000  ·  shifted 200\nadversarial 24 (hand-written)")
    _arrow(ax, 29.6, 54, 37.4, 54)
    top = [(1, 23, "Stratified random\n75/25 split\n(headline test)"),
           (26, 23, "Template-held-out\nsplit: whole templates\nunseen in training"),
           (51, 23, "Leave-one-template-\nout: 32 fits, each\ntemplate unseen")]
    for x, w, txt in top:
        _box(ax, x, 30, w, 11, txt)
        _arrow(ax, 57, 48.2, x + w / 2, 41.8)
    _box(ax, 77, 30, 22, 11, "Shifted + adversarial\nsets: evaluation only,\nnever trained on", fill=orange_fill, edge=ORANGE)
    _arrow(ax, 57, 48.2, 88, 41.8)
    _box(ax, 1, 13.5, 73, 10, "scikit-learn Pipeline, fitted on the TRAINING part only\nTfidfVectorizer (1-2-grams)  ->  LogisticRegression")
    for x, w, _ in top:
        _arrow(ax, x + w / 2, 29.2, x + w / 2, 24.3)
    _box(ax, 1, -2, 46, 9, "train_evaluate.py -> results/\nmetrics.json, confusion matrices,\nerror CSVs, per-template tables", fill="#eeeeea", edge=MUTED)
    _box(ax, 54, -2, 45, 9, "predict.py\nsaved model -> verdict + P(phishing)", fill="#eeeeea", edge=MUTED)
    _arrow(ax, 30, 12.7, 30, 7.9)
    _arrow(ax, 60, 12.7, 72, 7.9)
    _arrow(ax, 75.2, 20, 86, 29.2)  # the fitted model scores the evaluation-only sets
    ax.text(84, 22.2, "fitted model\nscores them", fontsize=7.5, color=INK2, ha="center", va="center")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Draw Task 14 figures from saved results.")
    parser.add_argument("--results-dir", type=Path, default=TASK_DIR / "results")
    parser.add_argument("--out-dir", type=Path, default=None, help="default: <results-dir>/figures")
    args = parser.parse_args(argv)
    out = args.out_dir or args.results_dir / "figures"
    try:
        metrics = json.loads((args.results_dir / "metrics.json").read_text(encoding="utf-8"))
        loto = pd.read_csv(args.results_dir / "leave_one_template_out.csv")
    except FileNotFoundError as exc:
        print(f"error: {exc.filename} not found. Run 'python src/train_evaluate.py' first.", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    metrics_by_evaluation(metrics, out / "metrics_by_evaluation.png")
    loto_per_template(loto, out / "loto_per_template.png")
    confusion_side_by_side(metrics, out / "confusion_matrices_compared.png")
    workflow_diagram(out / "workflow_diagram.png")
    print(f"Wrote 4 figures to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
