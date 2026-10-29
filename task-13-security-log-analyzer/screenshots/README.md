# Screenshots

Real console screenshots of the Task 13 commands, run from `task-13-security-log-analyzer/` with the project's virtual environment:

| File | Command shown |
|---|---|
| `01_generate.png` | `python src/cli.py generate` |
| `02_analyze.png` | `python src/cli.py analyze --input data/sample_auth_logs.csv` |
| `03_invalid_input.png` | creates a deliberately malformed `bad_input.csv`, runs `python src/cli.py analyze --input bad_input.csv` (error `line 4: expected 5 field(s), found 4`, exit code 2), then deletes the file |
| `04_pytest.png` | `python -m pytest tests -q` (105 passed) |

**How they were captured:** a script opened a real console window, echoed each command line, ran it, and saved an image of that window using the Windows `PrintWindow` call. Nothing was typed into the image, drawn or edited. The prompt was shortened to `PS>` so that no user-profile path appears. Run times shown differ slightly from the saved log in `../results/pytest_output.txt` because they come from a separate run.

The temporary `bad_input.csv` was deleted at the end of the capture (the screenshot shows `Test-Path` returning `False`). The same output is saved as text in `../results/`. The images are embedded in section 12 of `../report.md` and of the PDF report.
