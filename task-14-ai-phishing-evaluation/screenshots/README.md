# Screenshots

Real console screenshots of the Task 14 commands, run from `task-14-ai-phishing-evaluation/` with the project's virtual environment:

| File | Command shown |
|---|---|
| `01_generate_dataset.png` | `python src/generate_dataset.py` |
| `02_train_evaluate.png` | `python src/train_evaluate.py` |
| `03_predict.png` | `python src/predict.py "URGENT: verify your account at http://account-verify.example.net/login"` |
| `04_pytest.png` | `python -m pytest tests -q` (50 passed) |

**How they were captured:** a script opened a real console window, echoed each command line, ran it, and saved an image of that window using the Windows `PrintWindow` call. Nothing was typed into the image, drawn or edited. The prompt was shortened to `PS>` so that no user-profile path appears. Run times shown (for example in the pytest line) differ slightly from the saved log in `../results/pytest_output.txt` because they come from a separate run.

The same output is saved as text in `../results/` (`train_evaluate_output.txt`, `pytest_output.txt`, `predict_example_output.txt`). The images are embedded in section 12 of `../report.md` and of the PDF report.
