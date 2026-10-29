# Submission Checklist

Maps every requirement (from the assessment PDF and from the project brief) to its implementation, evidence and report section, then lists the steps to publish and submit. "Report §" refers to the numbered sections of each task's `report.md` / PDF.

Paths are relative to the task folder (`task-14-ai-phishing-evaluation/` or `task-13-security-log-analyzer/`).

## 1. Assessment requirements (from `Assessment_Taskss.pdf`)

| Task | Problem statement (assessment) | Expected deliverable | Where it is delivered |
|---|---|---|---|
| 14 | "Investigate a claim about AI and cybersecurity, such as AI-based phishing detection. Design a small experiment using synthetic examples, assess limitations, and explain where the approach may fail." | Experiment plan, results, and limitations | Plan: report §7.2. Results: report §11 and `results/`. Limitations and failure modes: report §13. |
| 13 | "Create a simple tool for a benign task, such as ... summarizing sample logs. Use a language you are comfortable with." | Working prototype, sample output, and test cases | Prototype: `src/`. Sample output: report §11.2-11.6 and `results/`. Test cases: `tests/` and report §10-11.1. |

Submission rules from the PDF: submit a Git repository or a documentation file; upload to Google Drive and submit the link through the designated Google Form; set sharing to "anyone with the link can view"; include references, screenshots, test results and supporting evidence; both tasks within two days.

## 2. Task 14 requirement map

| # | Requirement | Implementation | Evidence | Report § |
|---|---|---|---|---|
| 1 | Documented synthetic phishing/legitimate dataset | `src/generate_dataset.py`, `data/synthetic_messages.csv` (1,000 messages, 32 templates) | `tests/test_phishing_dataset.py` | 7.3, 11.1 |
| 2 | Split into train/test before fitting | `split_data()` in `src/train_evaluate.py` | `test_split_is_stratified_disjoint_and_complete` | 7.4 |
| 3 | No data leakage (pipeline) | `build_pipeline()`: one scikit-learn `Pipeline` | `test_vectorizer_never_sees_test_text` | 7.4, 10 |
| 4 | Train and evaluate | `run_experiment()` | `results/train_evaluate_output.txt` | 11.2 |
| 5 | Accuracy, precision, recall, F1, confusion matrix | `compute_metrics()` | `results/metrics.json`, `confusion_matrix.png/.csv`, `classification_report.txt` | 11.2-11.3 |
| 6 | Save actual metrics and outputs | `results/` | all files listed in the task README | 11, 17 |
| 7 | Inspect false positives and false negatives | error CSVs per evaluation | `results/*misclassified.csv`, `adversarial_predictions.csv` | 11.3-11.5 |
| 8 | Bias, overfitting, distribution shift, limitations | shifted set, adversarial set, `top_features.csv` | `results/shifted_*`, `top_features.csv` | 11.5, 13 |
| 9 | Reproducible prediction script | `src/predict.py` | `results/predict_example_output.txt`, `tests/test_phishing_predict.py` | 11.8 |
| 10 | Automated tests | `tests/` (50 tests) | `results/pytest_output.txt` | 10, 11.7 |
| 11 | No claim that perfect synthetic scores show real effectiveness | stated in README and report | n/a | 2, 11.2, 13.1, 15 |
| 12 | **Stronger split holding out entire templates** | `split_by_template()`, `leave_one_template_out()` | `results/template_holdout_*`, `leave_one_template_out*.csv`, `figures/loto_per_template.png` | 7.5, 11.3-11.4 |
| 13 | Matplotlib charts | `src/make_phishing_figures.py` | `results/figures/*.png` | 8, 11 |

## 3. Task 13 requirement map

| # | Requirement | Implementation | Evidence | Report § |
|---|---|---|---|---|
| 1 | Generate synthetic authentication events | `src/log_generator.py`, `data/sample_auth_logs.csv` (119 events) | `tests/test_log_generator.py` | 9.6 |
| 2 | Fields: timestamp, username, source IP, event type, status | schema in `src/log_loader.py` | loader tests | 9.1 |
| 3 | Input validation, malformed and empty datasets | `load_events()` / `validate_events()` | `test_log_loader.py`, `results/example_invalid_input_output.txt` | 9.1, 11.6 |
| 4 | Summaries: total, successful, failed, users, IPs | `summarize()` in `src/log_analyzer.py` | `results/cli_analyze_output.txt` (re-counted with `awk`) | 11.2 |
| 5 | Repeated failures, configurable threshold and window | rule R1, `AnalyzerConfig`, CLI options | boundary tests in `test_log_analyzer.py`; `results/settings_comparison.csv` | 9.2, 11.5 |
| 6 | Success following repeated failures | rule R2 | R2 tests | 9.2, 11.3 |
| 7 | Explainable severity and evidence | `severity_reasons`, `evidence` per alert | `results/report.json`, evidence-integrity tests | 9.3-9.4 |
| 8 | Do not label every unusual event a confirmed attack | fixed disposition and wording | `test_alert_wording_never_claims_a_confirmed_attack` | 9.4, 14 |
| 9 | Export CSV/JSON | `src/log_report.py` | `results/report.json`, `results/alerts.csv` | 9.5 |
| 10 | Command-line interface | `src/cli.py` | `test_log_cli.py` | 9.5 |
| 11 | Tests: normal, suspicious, invalid, empty, edge cases | `tests/` (105 tests) | `results/pytest_output.txt` | 10, 11.1 |
| 12 | Assumptions, false positives, false negatives, why an alert is not proof | README and report | planted scenarios S5, S6, S7 | 5, 9.4, 13.2-13.4 |
| 13 | Recommended investigation steps | `recommended_steps` per alert | `results/report.json` | 13.1 |
| 14 | Synthetic or authorised logs only | RFC 5737 addresses, enforced by test | `test_only_documentation_ip_ranges_are_used` | 14 |

## 4. Report content map (both PDFs)

| Required section | Report § |
|---|---|
| Cover page | generated from `reports/report_metadata.json` |
| Abstract / executive summary | 2 |
| Original assessment problem statement | 3 |
| Objectives and scope | 4, 5 |
| Tools and technologies | 6 |
| Methodology | 7 |
| Workflow / architecture diagram | 8 |
| Implementation details | 9 |
| Testing methodology and actual test results | 10, 11 |
| Output tables and charts | 11 |
| Screenshots of real execution | 12 (four real console screenshots per task in `screenshots/`, plus the verbatim console output) |
| Analysis, limitations, assumptions | 13 (and 5) |
| Security and ethical considerations | 14 |
| Conclusion | 15 |
| References with valid links | 16 |
| Appendix: files and reproduction steps | 17 |

## 5. Status and what is left for you

- [x] **Name:** Sargun Kaur (cover pages, both `report.md` title pages and PDF metadata).
- [x] **Student ID:** none assigned, so the field is omitted from the cover and title pages (leave `student_id` empty in `reports/report_metadata.json`).
- [x] **Submission date:** 29 October 2026 (as you provided it).
- [x] **Repository URL:** https://github.com/SargunKaur15/ai-cybersecurity-assessment (public).
- [x] **Screenshots:** four real console screenshots per task are in each `screenshots/` folder and embedded in report section 12 (capture method: see each `screenshots/README.md`).
- [x] `python -m pytest -q` shows 155 passed; `python reports/verify_reports.py` prints `OK`.
- [ ] **Read both reports end to end.** Be ready to explain every number, the template-held-out result, and each planted scenario (S1-S7). Check the assessment's rules on AI assistance and disclose it if required.
- [ ] Open both PDFs and look at every page.
- [ ] Open the repository link in a private/incognito window to confirm it loads without signing in.

## 6. GitHub repository

The repository is published at https://github.com/SargunKaur15/ai-cybersecurity-assessment. To publish later changes (for example after editing a report and rebuilding the PDFs with `python reports/build_reports.py`):

```bash
git add .
git status                                 # review: no .venv, no *.joblib, no _private-notes
git commit -m "Describe your change"
git push
```

## 7. Submit

1. Upload the two PDFs (and optionally the repository as a ZIP) to Google Drive.
2. Set sharing to **Anyone with the link can view** for each file or folder.
3. Open each link in a private/incognito window to confirm it opens.
4. Paste the GitHub repository link and/or Drive links into the designated Google Form and submit.
5. Re-check that all links still open before the deadline.
