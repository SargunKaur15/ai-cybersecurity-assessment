# Task 13: Authentication Log Analyzer (Small Defensive Security Tool)

A command-line tool that summarises authentication logs and flags suspicious patterns **for further investigation**. It works on **synthetic or authorised logs only**.

> Alerts are leads, not verdicts. Every alert says *"requires investigation; not a confirmed incident"*, shows the exact events it is based on, and explains why it has its severity.

## Objectives

1. Generate synthetic authentication events (`timestamp, username, source_ip, event_type, status`).
2. Validate input and fail with clear, line-numbered errors.
3. Summarise total events, successful and failed logins, unique users and unique source IPs.
4. Detect repeated failed logins with a **configurable threshold and time window**.
5. Detect a **successful login after repeated failures** where the data supports it.
6. Assign **explainable severity** levels and attach **evidence to every alert**, without calling anything a confirmed attack.
7. Write a JSON/CSV report from a **command-line interface**, with unit tests and documented limitations.

## Files

```
task-13-security-log-analyzer/
├── data/
│   ├── sample_auth_logs.csv        # 119 synthetic events (generated, seed 42)
│   └── planted_scenarios.json      # what was planted in the sample and what the tool should report
├── src/
│   ├── log_loader.py               # CSV loading + validation (LogValidationError)
│   ├── log_generator.py            # synthetic events + 7 planted scenarios
│   ├── log_analyzer.py             # summary + three detection rules + severity logic
│   ├── log_report.py               # JSON / CSV / console output (CSV formula-injection safe)
│   ├── cli.py                      # `generate` and `analyze` commands
│   └── make_log_figures.py         # charts, workflow diagram and settings_comparison.csv
├── tests/                          # pytest suite (105 tests)
├── results/                        # actual outputs of running the tool (see below)
├── screenshots/                    # real console screenshots of the commands below (see screenshots/README.md)
└── report.md                       # technical report
```

## Setup

Python 3.14.7 on Windows 11 was used for the recorded results. Run from the repository root:

```bash
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# macOS / Linux:       source .venv/bin/activate
python -m pip install -r requirements.txt
cd task-13-security-log-analyzer
```

Only `pandas` (plus the standard library: `csv`, `logging`, `datetime`, `ipaddress`, `argparse`, `json`) is needed to run the tool; `pytest` is needed for the tests.

## Execution

```bash
# 1. (Re)generate the synthetic sample log. Same seed -> identical file.
python src/cli.py generate

# 2. Analyse it with the default settings and write results/report.json + results/alerts.csv
python src/cli.py analyze --input data/sample_auth_logs.csv

# 3. Change the detection settings (use a separate output folder so results/ is not overwritten)
python src/cli.py analyze --input data/sample_auth_logs.csv --failure-threshold 3 --window-minutes 120 --format json --output-dir custom_run

# 4. Draw the report figures and results/settings_comparison.csv (needs step 2 first)
python src/make_log_figures.py

# 5. Run the tests
python -m pytest tests -q
```

`analyze` options: `--output-dir`, `--format {json,csv,both}`, `--failure-threshold N` (default 5), `--window-minutes W` (10), `--success-window-minutes S` (10), `--spray-threshold M` (5), `--fail-on {low,medium,high}` (exit code 1 if an alert at or above that level exists), and the global `-v` for progress logging on stderr.
Exit codes: `0` success, `1` `--fail-on` triggered, `2` invalid input or options.

### Input format

CSV with header `timestamp,username,source_ip,event_type,status`.
- `timestamp`: ISO 8601; values without an offset are treated as **UTC**.
- `username`: non-empty, compared case-insensitively.
- `source_ip`: valid IPv4 or IPv6 address.
- `event_type`: `login`, `logout`, `password_reset`, `mfa_challenge`.
- `status`: `success` or `failure`.

Invalid files are rejected with messages such as `line 4: expected 5 field(s), found 4` (see `results/example_invalid_input_output.txt`).

## Detection rules

Only `login` events are used by the rules. Windows are inclusive (events exactly W minutes apart count as "within").

| Rule | Fires when | Severity (default settings) |
|---|---|---|
| **R1** `REPEATED_FAILED_LOGINS` | at least **N** failures for the same username **and** source IP within **W** minutes (overlapping windows merge into one alert) | **low**; **medium** if failures ≥ 2N; **+1 level** if the same IP also triggers R3 |
| **R2** `SUCCESS_AFTER_REPEATED_FAILURES` | a success for the same username and IP within **S** minutes after an R1 burst | **medium**; **high** if failures ≥ 2N; **+1 level** if the IP also triggers R3 |
| **R3** `MULTI_ACCOUNT_FAILURES_FROM_SOURCE` | failures for at least **M** distinct usernames from one IP within **W** minutes | **medium**; **high** if accounts ≥ 2M. Later successes for the targeted accounts are listed as a note but do **not** change severity |

Severity is capped at `high`; there is deliberately no "critical" level. Each alert's `severity_reasons` lists every step that produced its level.

## Actual results

### Test results

`python -m pytest tests -v` on Python 3.14.7 / Windows 11: **105 passed in 6.30 s** (full log: `results/pytest_output.txt`).

| Test file | Tests |
|---|---:|
| `test_log_loader.py` | 25 |
| `test_log_analyzer.py` | 48 |
| `test_log_generator.py` | 9 |
| `test_log_cli.py` | 20 |
| `test_log_figures.py` | 3 |

Tests cover normal events, below-threshold failures, exact window and threshold boundaries, repeated failures, success-after-failures, multi-account patterns, severity levels, evidence integrity, invalid input (bad timestamp, IP, status, event type, missing columns, wrong field counts, non-UTF-8, empty and header-only files), the CLI, and reproducibility. As a check that the tests are not vacuous, four deliberate bugs (an off-by-one in each window, a severity threshold, and distinct-user counting) were introduced into a scratch copy of the analyzer; each made tests fail (1, 1, 3 and 13 failing tests respectively), while the unmutated copy passed all 105.

### Sample run (`results/cli_analyze_output.txt`)

```
Authentication log summary: sample_auth_logs.csv
  Total events:        119
  Successful logins:   34
  Failed logins:       55
  Unique users:        18
  Unique source IPs:   24
  Time range (UTC):    2024-03-04T08:13:39Z -> 2024-03-04T17:26:47Z

Alerts: 5 (high 0, medium 4, low 1)
  [A001] MEDIUM MULTI_ACCOUNT_FAILURES_FROM_SOURCE  user=5 accounts  src=192.0.2.10  events=5  2024-03-04T08:30:00Z
  [A002] MEDIUM REPEATED_FAILED_LOGINS  user=admin  src=203.0.113.50  events=12  2024-03-04T10:03:00Z
  [A003] MEDIUM SUCCESS_AFTER_REPEATED_FAILURES  user=carol  src=203.0.113.23  events=7  2024-03-04T11:20:00Z
  [A004] MEDIUM MULTI_ACCOUNT_FAILURES_FROM_SOURCE  user=8 accounts  src=203.0.113.77  events=8  2024-03-04T13:05:00Z
  [A005] LOW    REPEATED_FAILED_LOGINS  user=carol  src=203.0.113.23  events=6  2024-03-04T11:20:00Z
```

The five summary counts were independently re-counted with `awk` (not using this code) and matched: 119 / 34 / 55 / 18 / 24.

### How the sample alerts map to the planted scenarios

The sample log contains a baseline of normal activity plus seven planted scenarios (`data/planted_scenarios.json`). Because the data is synthetic, the answer key is known:

| Scenario | Planted behaviour | Default result |
|---|---|---|
| S1 | 3 failures then success for `dana` (below N=5) | No alert (correct) |
| S2 | 12 failures for `admin` from one IP, no success | A002 medium |
| S3 | 6 failures then a success for `carol`, same IP | A005 low + A003 medium |
| S4 | 1 failure each for 8 accounts from one IP; one later success | A004 medium |
| S5 | 5 colleagues behind a shared office IP fail once each during an outage, then succeed (**benign**) | A001 medium (**a false positive**, by design) |
| S6 | 12 failures for `grace`, one every 15 min (slow) | No alert (**a miss**, by design) |
| S7 | 6 failures for `heidi` from 6 different IPs, then a success from a 7th | No alert (**a miss**, by design) |

Changing the settings changes this picture (`results/settings_comparison.csv`, spray threshold fixed at 5):

| Setting | Failures / window | Alerts (low / medium / high) | Attack-like scenarios flagged (of 5) | Benign scenarios flagged (of 2) |
|---|---|---|---|---|
| Strict | 10 / 10 min | 3 (1 / 2 / 0) | 2: S2, S4 | 1: S5 |
| Default | 5 / 10 min | 5 (1 / 4 / 0) | 3: S2, S3, S4 | 1: S5 |
| Relaxed | 3 / 120 min | 8 (1 / 6 / 1) | 4: S2, S3, S4, S6 | 2: S1, S5 |

Relaxing the settings catches the slow attack (S6) but also flags the benign fumble (S1); no setting catches S7 (`results/example_custom_thresholds_output.txt`).

### Output files in `results/`

| File | Content |
|---|---|
| `report.json` | Config, summary, alert counts and all alerts with evidence, reasons and recommended steps |
| `alerts.csv` | One row per alert (evidence as source line numbers) |
| `cli_generate_output.txt`, `cli_analyze_output.txt` | Captured console output |
| `example_custom_thresholds_output.txt`, `example_invalid_input_output.txt` | Captured output for a custom run and for a malformed input file |
| `settings_comparison.csv` | Alerts under strict / default / relaxed settings (made by `make_log_figures.py`) |
| `figures/*.png` | Alert timeline, settings comparison chart, workflow diagram |
| `pytest_output.txt` | Full test log |

Reports contain no generation timestamp, so re-running on the same input gives a byte-identical `report.json` (checked by file hash).

## Recommended investigation steps (per alert)

Each alert in `report.json` lists `recommended_steps`. In short: check whether the account owner recognises the activity (through a separate trusted channel); look at the account's lockout/MFA/reset state; review other activity from the same source address; for multi-account patterns check whether the source is a known shared gateway or whether there was an outage; and follow your own incident process before taking any blocking action.

## Assumptions

- Timestamps without an offset are UTC; usernames are case-insensitive; duplicates are not removed.
- "Successful/failed logins" count only `event_type = login` rows. "Unique users/IPs" count all rows.
- The log is complete and in one time zone. Rows may be in any order (they are sorted internally).
- R2 and R3's success notes link events only when username **and** source IP match (that is what the available fields support).

## Limitations, false positives and false negatives

**False positives (benign activity flagged):**
- Users mistyping passwords, or password-manager/mobile clients retrying old passwords (R1/R2).
- Shared NAT, VPN or proxy addresses and single-sign-on outages (R3), as in S5.
- A user who fails several times and then remembers the password (R2). The tool cannot tell this from a guessed password.

**False negatives (suspicious activity missed):**
- **Slow, low-rate attempts** that stay under the threshold per window (S6).
- **Distributed attempts** spread over many source addresses against one account (S7), because R1 groups by username *and* IP.
- Success from a *different* IP after failures (not linked by the available fields).
- Spraying that uses fewer than M accounts per window, or spreads attempts across windows.
- Attackers who try one account at a time with long gaps, or who already hold valid credentials.
- Anything not in the log: failed attempts that are not logged, other protocols, or events from other systems.

**Other limits:** the rules use fixed thresholds with no baseline of each user's normal location or time; geolocation, device identity, account lockout state and IP reputation are not used; one file is analysed in memory, so very large logs would need streaming. Detection thresholds should be tuned to the environment.

## Safety and ethics

Defensive only. The sample data is fabricated; all IP addresses are from the documentation ranges reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, checked by a unit test) and all usernames are invented. The tool reads files only: it does not contact hosts, block anything, or modify accounts. Use it only on logs you are authorised to analyse. Text taken from logs is neutralised in `alerts.csv` (leading `= + - @` characters are prefixed with `'`) so a hostile username cannot run as a formula when the CSV is opened in a spreadsheet.
