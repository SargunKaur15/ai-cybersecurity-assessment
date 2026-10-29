# Task 14: Evaluate an AI Security Claim

**Claim investigated:** *"AI can identify phishing messages."*
**Question tested:** How well does a small TF-IDF + Logistic Regression model separate phishing-like from legitimate messages in **synthetic** data, and where does it break?

> **Research exercise, not a security product.** The model is trained on synthetic, template-generated text. It is not production-ready and must not be used as a standalone (or any real) security control.

## Objectives

1. State the claim as a testable hypothesis and write an experiment plan (see [report.md](report.md), section 7).
2. Build a reproducible synthetic dataset with varied wording and deliberate class overlap.
3. Train a TF-IDF + Logistic Regression classifier in a scikit-learn `Pipeline`, splitting **before** fitting to prevent data leakage.
4. Evaluate with accuracy, precision, recall, F1 and a confusion matrix, reporting sample counts and class distribution.
5. Go beyond a random split: **hold out entire message templates**, so the test set is not made of near-duplicates of the training set.
6. Examine false positives and false negatives and explain their practical impact.
7. Probe failure modes: distribution shift, adversarial wording, and reliance on synthetic artifacts.
8. Provide a prediction script, tests, saved outputs, and reproduction instructions.

## Headline results (actual output of this code)

| Evaluation | n | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| Stratified random split (same templates in train and test) | 250 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 | 0 |
| Majority-class baseline (same split) | 250 | 0.6000 | 0.0000 | 0.0000 | 0.0000 | 0 | 100 |
| Same split, URLs removed from test text | 250 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 | 0 |
| **Template-held-out split** (8 of 32 templates unseen) | 241 | 0.8797 | 1.0000 | 0.7071 | 0.8284 | 0 | 29 |
| **Leave-one-template-out** (each message's template unseen) | 1,000 | 0.8650 | 0.9102 | 0.7350 | 0.8133 | 29 | 106 |
| Shifted distribution (different templates and wording) | 200 | 0.9550 | 1.0000 | 0.8875 | 0.9404 | 0 | 9 |
| Hand-written adversarial probes | 24 | 0.7083 | 0.8571 | 0.5000 | 0.6316 | 1 | 6 |

Stratified split: 250 test messages (100 phishing, 150 legitimate); training: 750 (300 / 450). Template-held-out split: 241 test messages (99 phishing, 142 legitimate) from 8 unseen templates.

**How to read this:** the perfect score on the random split reflects how easy the synthetic templates are to separate and the fact that every template appears in both halves; it is **not** real-world detection ability. Once whole templates are held out, recall drops to about 0.71 to 0.74 and false positives appear. Two link-free templates (a gift-card request and a macro-attachment lure) were never detected when held out, and legitimate security notices were flagged about half the time. Details, error examples and caveats are in [report.md](report.md).

## Folder layout

```
task-14-ai-phishing-evaluation/
├── data/
│   ├── synthetic_messages.csv        # 1,000 generated messages from 32 templates (main dataset)
│   ├── shifted_messages.csv          # 200 messages from different templates (never trained on)
│   └── adversarial_handwritten.csv   # 24 hand-written probe messages
├── src/
│   ├── generate_dataset.py           # seeded synthetic data generator
│   ├── train_evaluate.py             # splits -> Pipeline -> all evaluations -> output files
│   ├── predict.py                    # score a new synthetic message
│   └── make_phishing_figures.py      # charts and workflow diagram from the saved results
├── tests/                            # pytest suite (50 tests)
├── results/                          # actual outputs (see below)
├── screenshots/                      # real console screenshots of the commands below (see screenshots/README.md)
└── report.md                         # technical report (PDF version: ../reports/)
```

## Setup and reproduction

Python 3.14.7 on Windows 11 was used for the recorded results. Run from the repository root.

```bash
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# macOS / Linux:       source .venv/bin/activate
python -m pip install -r requirements.txt
cd task-14-ai-phishing-evaluation

python src/generate_dataset.py      # writes data/synthetic_messages.csv and data/shifted_messages.csv
python src/train_evaluate.py        # trains, evaluates, writes results/*
python src/make_phishing_figures.py # draws results/figures/*.png from the saved results
python -m pytest tests -q           # 50 tests
```

Everything is seeded (`SEED = 42`), so re-running regenerates identical data and results.

### Score a new message

```bash
python src/predict.py "URGENT: your email account will be suspended. Verify at http://account-verify.example.net/login"
python src/predict.py --file my_messages.txt      # one message per line
```

Output is `phishing-like` or `legitimate-like` plus the model's probability. Run `train_evaluate.py` first, because it creates `results/model.joblib`.

## Test results

`python -m pytest tests -v` on Python 3.14.7 / Windows 11: **50 passed in 12.69 s** (full log: `results/pytest_output.txt`).

| Test file | Tests | Covers |
|---|---:|---|
| `test_phishing_dataset.py` | 12 | Seed reproducibility, schema and labels, class fraction, no duplicate texts, reserved-domain URLs only, shifted set disjoint from the main set, invalid arguments |
| `test_phishing_pipeline.py` | 19 | Input validation, stratified/disjoint split, Pipeline structure, **no test text in the TF-IDF vocabulary**, **template split shares no template**, **leave-one-template-out never trains on the held-out template**, metric values against a hand-computed matrix, full-experiment reproducibility and output files, CLI error code |
| `test_phishing_predict.py` | 16 | Verdict fields, threshold behaviour, rejection of empty/invalid input, CLI success, file input and error exit codes |
| `test_phishing_figures.py` | 3 | Figures are valid PNG files; missing results give a clear error |

These tests check that the code behaves as designed. They do **not** show that the model detects real phishing.

## Output files in `results/`

| File | Content |
|---|---|
| `metrics.json` | All metrics, confusion matrices, sample counts, class distributions, held-out template list, library versions |
| `confusion_matrix.png` / `.csv`, `template_holdout_confusion_matrix.png` | Confusion matrices (stratified and template-held-out test sets) |
| `classification_report.txt` | scikit-learn per-class report (stratified split) |
| `misclassified.csv` | Stratified-split errors (header only: there were none) |
| `template_holdout_misclassified.csv`, `template_holdout_per_template.csv` | Template-held-out errors and per-template breakdown |
| `leave_one_template_out.csv`, `leave_one_template_out_misclassified.csv` | Per-template correct rates and every error under leave-one-template-out |
| `shifted_misclassified.csv`, `shifted_per_template.csv` | Errors and per-template breakdown on the shifted set |
| `adversarial_predictions.csv` | Prediction for each of the 24 hand-written probes |
| `top_features.csv` | Strongest TF-IDF terms for each class (shows what the model relies on) |
| `figures/*.png` | Report charts and the workflow diagram |
| `train_evaluate_output.txt`, `pytest_output.txt`, `predict_example_output.txt` | Captured console output |
| `model.joblib` | Trained pipeline (git-ignored; regenerated by the training script) |

## Design in one paragraph

Data is split (stratified, seed 42) **before** fitting. A single scikit-learn `Pipeline` (TF-IDF with 1-2 grams, then Logistic Regression) is fitted on the training split only, so the vocabulary and IDF weights never see test text (a unit test checks this). Two stronger evaluations then hold out whole templates (one split of 8 templates, and leave-one-template-out over all 32). Hyperparameters are fixed up front and were not tuned on any evaluation data. The shifted and adversarial sets are used only for evaluation.

## Key limitations (full discussion in the report)

- **Synthetic, template-based data** cannot represent real phishing: no real attacker creativity, languages, formatting, HTML, headers, attachments or sender reputation.
- **Even the template-held-out results are optimistic.** There are only 32 templates, some are close siblings of each other, and the headline number depends on which templates are held out (per-template rates range from 0% to 100%).
- **The model learns generator artifacts.** `results/top_features.csv` shows tokens such as `http`, `test` and `invalid` (from the generator's fake domains) among the strongest phishing indicators.
- **The shifted set was written by the same author** and reuses the same fake-URL pool, so it understates real distribution shift. The adversarial set is tiny (24 messages).
- One data seed and one held-out choice: no confidence intervals are reported.
- Text only: no URL reputation, headers, authentication results (SPF/DKIM/DMARC) or user context.

## Safety and ethics

All data is fabricated. URLs use only reserved example domains (`example.com/.net/.org`, `.test`, `.invalid`; RFC 2606), checked by a unit test. No real credentials, personal data, logs or live systems are involved.
`results/model.joblib` is a pickle-based file; only load model files you created yourself.
