# AI & Cybersecurity Assessment: Tasks 13 and 14

Two separate, reproducible projects built for the cybersecurity assessment, each with a technical report (Markdown and PDF). Both use **synthetic data only**; nothing here touches real systems, credentials or logs.

| Task | Project | Summary |
|---|---|---|
| **14**: Evaluate an AI Security Claim | [task-14-ai-phishing-evaluation](task-14-ai-phishing-evaluation/) | Tests the claim *"AI can identify phishing messages"* with a TF-IDF + Logistic Regression model on synthetic messages, including a stronger test that holds out entire message templates, then probes where it fails. |
| **13**: Build a Small Defensive Security Tool | [task-13-security-log-analyzer](task-13-security-log-analyzer/) | A CLI that summarises synthetic authentication logs and flags suspicious patterns with explainable severity and evidence. |

Each folder has its own `README.md` (objectives, files, setup, execution, test results) and a technical report, `report.md`. The PDF reports are in [reports/](reports/). A requirement-by-requirement mapping is in [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md).

## Objectives

- **Task 14:** design and run a small, honest experiment on an AI security claim, with a leakage-safe pipeline, standard metrics, error analysis, and a clear account of its limitations. It does **not** claim the model is production-ready.
- **Task 13:** build a small, tested defensive tool with input validation, configurable detection, explainable severity, evidence for every alert, and documented false positives and false negatives.

## Repository structure

```
ai-cybersecurity-assessment/
├── README.md
├── SUBMISSION_CHECKLIST.md
├── requirements.txt
├── pytest.ini
├── .gitignore
├── task-14-ai-phishing-evaluation/    data/  src/  tests/  results/  screenshots/  README.md  report.md
├── task-13-security-log-analyzer/     data/  src/  tests/  results/  screenshots/  README.md  report.md
└── reports/                           PDF reports, build_reports.py, verify_reports.py, report_metadata.json
```

## Setup

Recorded results were produced with Python 3.14.7 on Windows 11. Dependencies are pinned in `requirements.txt` (pandas 3.0.5, numpy 2.5.2, scikit-learn 1.9.0, matplotlib 3.11.1, pytest 9.2.0).

```bash
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# macOS / Linux:       source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run

**Task 14** (from `task-14-ai-phishing-evaluation/`):

```bash
python src/generate_dataset.py
python src/train_evaluate.py
python src/make_phishing_figures.py
python src/predict.py "URGENT: verify your account at http://account-verify.example.net/login"
```

**Task 13** (from `task-13-security-log-analyzer/`):

```bash
python src/cli.py generate
python src/cli.py analyze --input data/sample_auth_logs.csv
python src/make_log_figures.py
```

## Tests

From the repository root, run both suites together:

```bash
python -m pytest -q
```

Actual result when this was last run: **155 passed** (50 for Task 14, 105 for Task 13), on Python 3.14.7 / Windows 11. Each task's full test log is saved in its `results/pytest_output.txt`.

## PDF reports

The finished reports are `reports/Task_14_AI_Phishing_Detection_Report.pdf` and `reports/Task_13_Security_Log_Analyzer_Report.pdf`. To rebuild them (for example after adding your name or screenshots):

```bash
python -m pip install -r reports/requirements-reports.txt
# edit reports/report_metadata.json (author, ID, date, repository URL)
python reports/build_reports.py
```

The build first runs `reports/verify_reports.py`, which checks that every number, table row, console transcript and test count in the READMEs and reports matches the saved result files, then prints the PDFs with Microsoft Edge or Google Chrome (headless). Without a Chromium browser, open the Markdown reports in any Markdown viewer and print to PDF instead.

## Results at a glance

All numbers come from files in each `results/` folder.

**Task 14** (stratified test split: 250 messages, 100 phishing / 150 legitimate)

| Evaluation | Accuracy | Recall | Notes |
|---|---:|---:|---|
| Stratified random split | 1.0000 | 1.0000 | Perfect score reflects easy synthetic templates, **not** real-world ability |
| Template-held-out split (241 msgs) | 0.8797 | 0.7071 | 8 of 32 templates never seen in training |
| Leave-one-template-out (1,000 msgs) | 0.8650 | 0.7350 | 29 false positives, 106 false negatives |
| Shifted templates (200 msgs) | 0.9550 | 0.8875 | All 9 misses from one link-free template |
| Hand-written adversarial (24 msgs) | 0.7083 | 0.5000 | 6 false negatives, 1 false positive |

**Task 13** (sample log: 119 events; 34 successful and 55 failed logins; 18 users; 24 source IPs)

Default settings produce **5 alerts** (0 high, 4 medium, 1 low) that match the 7 planted scenarios: 3 planted patterns detected, 1 benign look-alike correctly ignored, 1 benign pattern flagged (a deliberate false positive), and 2 evasive attacks missed (deliberate false negatives). A strict / default / relaxed comparison shows the threshold trade-off.

## Limitations (short version)

- Synthetic data cannot represent real phishing or real authentication traffic. Both sets of results show the code behaving as designed, not effectiveness against real attackers.
- Task 14's random-split score is inflated by template repetition and generator artifacts; the template-held-out, shifted and adversarial evaluations are more informative but are still small and written by the same author.
- Task 13 uses fixed thresholds: it misses slow or distributed attacks and flags some benign patterns. Alerts are leads for investigation, never confirmed incidents.

Neither tool is production-ready or a standalone security control. Full discussions are in the two reports.

## Screenshots

Each task's `screenshots/` folder holds four real screenshots (`01`-`04`) of the commands documented in that task's README: dataset generation, training/analysis, prediction or invalid-input handling, and the test run. They were captured from real console windows that ran the commands (see each folder's README for the method); nothing was drawn or edited. They appear in section 12 of each report and PDF. The same console output is saved as text in each `results/` folder.

## Safety and ethics

Defensive and educational use only. All data is fabricated: URLs use reserved example domains (RFC 2606) and IP addresses use documentation ranges (RFC 5737), both enforced by unit tests. Use the tools only on synthetic data or logs you are authorised to analyse.
