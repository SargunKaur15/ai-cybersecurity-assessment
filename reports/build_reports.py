"""Build the two PDF reports from each task's report.md.

    python reports/build_reports.py [--task 13|14|all] [--browser PATH] [--skip-verify]

Pipeline: verify numbers (verify_reports.py) -> Markdown -> styled HTML -> headless Edge/Chrome prints a PDF
-> PyMuPDF adds the table of contents (with real page numbers), page footers and PDF bookmarks.

Author name, ID, date and repository URL come from reports/report_metadata.json: edit that file and
re-run this script to change the cover page. Real terminal screenshots (PNG) placed in
<task>/screenshots/ are embedded in the Screenshots section automatically.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import markdown
import pymupdf

ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = ROOT / "reports"
TASKS = {
    "14": {"dir": ROOT / "task-14-ai-phishing-evaluation", "pdf": "Task_14_AI_Phishing_Detection_Report.pdf",
           "label": "Task 14", "short": "Task 14: AI Phishing Detection Evaluation"},
    "13": {"dir": ROOT / "task-13-security-log-analyzer", "pdf": "Task_13_Security_Log_Analyzer_Report.pdf",
           "label": "Task 13", "short": "Task 13: Security Log Analyzer"},
}
BROWSER_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
]

CSS = """
@page { size: A4; margin: 20mm 17mm 22mm 17mm; }
@page cover { margin: 0; }
* { box-sizing: border-box; }
body { font-family: "Cambria", "Georgia", "Times New Roman", serif; font-size: 10.5pt; line-height: 1.45; color: #1f2328; }
h1, h2, h3, .sans { font-family: "Segoe UI", "Calibri", "Helvetica Neue", Arial, sans-serif; }
h1 { font-size: 16pt; color: #0d366b; border-bottom: 1.5px solid #2a78d6; padding-bottom: 3pt; margin: 20pt 0 8pt; break-after: avoid; }
h2 { font-size: 12.5pt; color: #184f95; margin: 14pt 0 5pt; break-after: avoid; }
h3 { font-size: 11pt; color: #1f2328; margin: 10pt 0 4pt; break-after: avoid; }
p { margin: 0 0 7pt; text-align: justify; hyphens: auto; }
ul, ol { margin: 0 0 8pt 0; padding-left: 18pt; } li { margin-bottom: 3pt; }
hr { display: none; }
a { color: #1c5cab; text-decoration: none; word-break: break-all; }
blockquote { margin: 8pt 0; padding: 6pt 12pt; border-left: 3px solid #2a78d6; background: #f1f6fd; }
blockquote p { margin: 0 0 4pt; text-align: left; }
code { font-family: "Cascadia Mono", "Consolas", "Courier New", monospace; font-size: 8.6pt; background: #f2f2ef; padding: 0 2pt; border-radius: 2pt; overflow-wrap: break-word; }
pre { background: #f6f6f3; border: 1px solid #deded8; border-radius: 4pt; padding: 7pt 9pt; margin: 6pt 0 10pt; white-space: pre-wrap; word-break: break-word; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 7.6pt; line-height: 1.35; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 11pt; font-family: "Segoe UI", "Calibri", Arial, sans-serif; font-size: 8.6pt; break-inside: avoid; }
th { background: #e6eefa; color: #0d366b; text-align: left; font-weight: 600; }
th, td { border: 1px solid #cfd6df; padding: 3.5pt 5pt; vertical-align: top; }
tbody tr:nth-child(even) td { background: #f8f9fb; }
td code { font-size: 7.8pt; }
img { display: block; margin: 8pt auto 3pt; max-width: 100%; max-height: 215mm; }
p:has(> img) { break-after: avoid; text-align: center; margin-bottom: 0; }
p:has(+ pre) { break-after: avoid; }
p.caption { text-align: center; font-size: 8.8pt; color: #52514e; margin-bottom: 11pt; }
figure { margin: 10pt 0; break-inside: avoid; text-align: center; }
figcaption { font-size: 8.8pt; color: #52514e; }

.cover { page: cover; width: 210mm; height: 297mm; padding: 0; position: relative; break-after: page; font-family: "Segoe UI", "Calibri", Arial, sans-serif; }
.cover .band { background: #0d366b; color: #fff; padding: 34mm 24mm 16mm; height: 120mm; }
.cover .kicker { font-size: 11pt; letter-spacing: 2.5pt; text-transform: uppercase; color: #b7d3f6; margin-bottom: 8mm; }
.cover h1.title { font-size: 26pt; line-height: 1.2; color: #fff; border: 0; margin: 0 0 7mm; padding: 0; }
.cover .subtitle { font-size: 13pt; color: #cde2fb; line-height: 1.4; }
.cover .accent { height: 3mm; background: #2a78d6; }
.cover .meta { margin: 16mm 24mm 0; }
.cover .meta table { font-size: 10.5pt; width: 100%; margin: 0; }
.cover .meta td { border: 0; border-bottom: 1px solid #dde3ea; padding: 6pt 4pt; background: none !important; }
.cover .meta td:first-child { width: 42mm; color: #52514e; font-weight: 600; }
.cover .note { position: absolute; left: 24mm; right: 24mm; bottom: 18mm; font-size: 9pt; color: #52514e; border-top: 1px solid #dde3ea; padding-top: 5mm; line-height: 1.5; }
.toc { break-after: page; }
.toc h1 { margin-top: 0; }
.toc table { font-size: 10pt; border: 0; } .toc td { border: 0; border-bottom: 1px dotted #b8c2cf; padding: 4pt 2pt; background: none !important; }
.toc td.pg { width: 14mm; text-align: right; font-variant-numeric: tabular-nums; }
.toc td.no { width: 11mm; color: #52514e; }
"""


def find_browser(explicit: str | None) -> str:
    for cand in ([explicit] if explicit else []) + BROWSER_CANDIDATES + [shutil.which(n) or "" for n in ("msedge", "google-chrome", "chromium")]:
        if cand and Path(cand).exists():
            return cand
    raise SystemExit("error: no Edge/Chrome found. Pass --browser PATH, or open the generated HTML in a browser and use Print -> Save as PDF.")


def load_metadata() -> dict:
    meta = json.loads((REPORTS_DIR / "report_metadata.json").read_text(encoding="utf-8"))
    return {k: meta.get(k, "") for k in ("author", "student_id", "submission_date", "repository")}


def split_report(md_text: str):
    """Return (document title, final-results line, body markdown without the Title Page section)."""
    title = re.search(r'^title:\s*"(.*)"\s*$', md_text, re.M).group(1)
    results_date = re.search(r"\| Final results generated \| (.*?) \|", md_text).group(1)
    body = re.sub(r"\A---\n.*?\n---\n", "", md_text, count=1, flags=re.S)
    body = re.sub(r"# 1\. Title Page.*?(?=# 2\. )", "", body, count=1, flags=re.S)
    return title, results_date, body


def screenshots_block(task_dir: Path, body: str) -> str:
    shots = sorted((task_dir / "screenshots").glob("*.png"))
    if not shots or "<!-- screenshots:placeholder:start -->" not in body:
        return body  # the report already links its screenshots (or none exist yet)
    body = re.sub(r"<!-- screenshots:placeholder:start -->.*?<!-- screenshots:placeholder:end -->", "", body, flags=re.S)
    figures = "\n".join(f'<figure><img src="screenshots/{p.name}" alt="{p.stem}"><figcaption>Screenshot: {p.stem.replace("_", " ")}</figcaption></figure>' for p in shots)
    return body.replace("**Console output", figures + "\n\n**Console output", 1)


def autolink_references(html_text: str) -> str:
    start, end = html_text.find("<h1>16."), html_text.find("<h1>17.")
    if start < 0:
        return html_text
    end = end if end > 0 else len(html_text)
    section = re.sub(r'(?<!["\'>])(https?://[^\s<]+[^\s<.,;)])', r'<a href="\1">\1</a>', html_text[start:end])
    return html_text[:start] + section + html_text[end:]


def build_html(task: dict, meta: dict, page_numbers: dict[str, int]) -> tuple[str, list[tuple[str, str]]]:
    md_text = (task["dir"] / "report.md").read_text(encoding="utf-8")
    title, results_date, body = split_report(md_text)
    body = screenshots_block(task["dir"], body)
    body_html = markdown.markdown(body, extensions=["tables", "fenced_code", "sane_lists", "attr_list"])
    body_html = autolink_references(body_html)
    body_html = re.sub(r"<p><em>((?:Figure|Screenshot) \d+\.)", r'<p class="caption"><em>\1', body_html)
    headings = re.findall(r"<h1>(\d+)\.\s*(.*?)</h1>", body_html)
    toc_rows = "".join(f'<tr><td class="no">{n}</td><td>{t}</td><td class="pg">{page_numbers.get(f"{n}. {html.unescape(re.sub("<[^>]+>", "", t))}", "00")}</td></tr>' for n, t in headings)
    subtitle = {"14": "TF-IDF and Logistic Regression on synthetic messages, tested with whole templates held out", "13": "Python authentication-log analyzer with explainable, evidence-backed alerts"}[task["label"][-2:]]
    rows = [("Author", meta["author"]), ("Student / Applicant ID", meta["student_id"]), ("Submission date", meta["submission_date"]),
            ("Repository", meta["repository"]), ("Final results generated", results_date)]
    meta_rows = "".join(f"<tr><td>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>" for k, v in rows)
    cover = f"""
<section class="cover"><div class="band"><div class="kicker">Cybersecurity Assessment &middot; {task['label']}</div>
<h1 class="title">{html.escape(title)}</h1><div class="subtitle">{subtitle}</div></div><div class="accent"></div>
<div class="meta"><table>{meta_rows}</table></div>
<div class="note">All data in this report is synthetic. No real credentials, personal data, logs or live systems were used.
Every figure and table was generated from the code in the accompanying repository.</div></section>
<section class="toc"><h1>Contents</h1><table>{toc_rows}</table></section>"""
    doc = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{html.escape(title)}</title><style>{CSS}</style></head><body>{cover}{body_html}</body></html>'
    return doc, [(n, re.sub("<[^>]+>", "", t)) for n, t in headings]


def print_pdf(browser: str, html_path: Path, pdf_path: Path) -> None:
    with tempfile.TemporaryDirectory() as profile:
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--user-data-dir={profile}",
               "--run-all-compositor-stages-before-draw", "--virtual-time-budget=15000",
               f"--print-to-pdf={pdf_path}", html_path.as_uri()]
        subprocess.run(cmd, check=False, timeout=180, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not pdf_path.exists() or pdf_path.stat().st_size < 10_000:
        raise SystemExit(f"error: browser did not produce {pdf_path.name}")


def locate_headings(pdf_path: Path, headings) -> dict[str, int]:
    pages = {}
    with pymupdf.open(pdf_path) as doc:
        for n, text in headings:
            key = f"{n}. {html.unescape(text)}"
            for p in range(2, len(doc)):  # skip cover (0) and contents (1)
                if doc[p].search_for(key):
                    pages[key] = p + 1
                    break
    return pages


def finish_pdf(raw: Path, out: Path, task: dict, meta: dict, headings, pages: dict[str, int]) -> int:
    with pymupdf.open(raw) as doc:
        total = len(doc)
        for i, page in enumerate(doc):
            if i == 0:
                continue  # cover has no footer
            r = page.rect
            y = r.height - 30
            page.draw_line((48, y - 8), (r.width - 48, y - 8), color=(0.80, 0.82, 0.86), width=0.5)
            page.insert_text((48, y + 4), task["short"], fontsize=8, fontname="helv", color=(0.32, 0.32, 0.30))
            label = f"Page {i + 1} of {total}"
            width = pymupdf.get_text_length(label, fontname="helv", fontsize=8)
            page.insert_text((r.width - 48 - width, y + 4), label, fontsize=8, fontname="helv", color=(0.32, 0.32, 0.30))
        toc = [[1, "Contents", 2]] + [[1, f"{n}. {t}", pages[f"{n}. {t}"]] for n, t in headings if f"{n}. {t}" in pages]
        doc.set_toc(toc)
        author = "" if meta["author"].startswith("[") else meta["author"]
        doc.set_metadata({"title": task["short"] + " - Report", "author": author, "subject": "Cybersecurity assessment report (synthetic data only)",
                          "creator": "reports/build_reports.py", "producer": "PyMuPDF", "keywords": "cybersecurity, assessment, synthetic data"})
        doc.save(out, garbage=3, deflate=True)
    return total


def build(task_key: str, browser: str, keep_html: bool) -> Path:
    task, meta = TASKS[task_key], load_metadata()
    out = REPORTS_DIR / task["pdf"]
    with tempfile.TemporaryDirectory() as tmp:
        html_path, raw = task["dir"] / ".report_build.html", Path(tmp) / "raw.pdf"
        pages: dict[str, int] = {}
        for attempt in range(3):  # table-of-contents page numbers need the layout first
            doc_html, headings = build_html(task, meta, pages)
            html_path.write_text(doc_html, encoding="utf-8")
            print_pdf(browser, html_path, raw)
            found = locate_headings(raw, headings)
            if found == pages and len(found) == len(headings):
                break
            pages = found
        else:
            raise SystemExit("error: table-of-contents page numbers did not settle")
        total = finish_pdf(raw, out, task, meta, headings, pages)
    if not keep_html:
        html_path.unlink(missing_ok=True)
    print(f"Wrote {out.relative_to(ROOT)} ({total} pages, {out.stat().st_size // 1024} KB)")
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build the PDF reports.")
    parser.add_argument("--task", choices=["13", "14", "all"], default="all")
    parser.add_argument("--browser", help="path to Edge/Chrome")
    parser.add_argument("--skip-verify", action="store_true", help="do not run verify_reports.py first")
    parser.add_argument("--keep-html", action="store_true")
    args = parser.parse_args(argv)
    if not args.skip_verify:
        sys.path.insert(0, str(REPORTS_DIR))
        import verify_reports
        if verify_reports.main([]) != 0:
            print("error: report numbers do not match the saved results; fix before building PDFs (or use --skip-verify)", file=sys.stderr)
            return 1
    browser = find_browser(args.browser)
    for key in (["14", "13"] if args.task == "all" else [args.task]):
        build(key, browser, args.keep_html)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
