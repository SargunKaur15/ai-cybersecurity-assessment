"""Load and validate authentication-event CSV files (Task 13).

Required columns: timestamp, username, source_ip, event_type, status.

Assumptions (also documented in the README):
* ``timestamp`` is ISO 8601. Values without a UTC offset are treated as UTC.
* ``username`` is compared case-insensitively (stored lower-case).
* ``event_type`` is one of login, logout, password_reset, mfa_challenge.
* ``status`` is one of success, failure.
* Extra columns are ignored.

Problems are reported with CSV line numbers, up to a cap. Rows with the wrong number of
fields are reported first; once every row has the right shape, all field-level problems
(timestamp, username, IP, event type, status) are reported together.
"""

from __future__ import annotations

import csv
import ipaddress
import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger("auth_log_analyzer")

REQUIRED_COLUMNS = ["timestamp", "username", "source_ip", "event_type", "status"]
VALID_EVENT_TYPES = ("login", "logout", "password_reset", "mfa_challenge")
VALID_STATUSES = ("success", "failure")
MAX_REPORTED_PROBLEMS = 20
MAX_USERNAME_LENGTH = 256


class LogValidationError(ValueError):
    """Raised when the input file cannot be used; the message is safe to show to the user."""


def _short(value: str, limit: int = 40) -> str:
    """Truncate and escape a raw value before echoing it in an error message."""
    value = value.encode("unicode_escape").decode("ascii")
    return value if len(value) <= limit else value[:limit] + "..."


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _raise_problems(problems: list) -> None:
    problems = sorted(problems, key=lambda p: int(p.split(":")[0].split()[1]))
    shown = problems[:MAX_REPORTED_PROBLEMS]
    extra = len(problems) - len(shown)
    suffix = f"\n... and {extra} more problem(s)" if extra > 0 else ""
    raise LogValidationError(f"Invalid input ({len(problems)} problem(s)):\n" + "\n".join(shown) + suffix)


def validate_events(raw: pd.DataFrame, lines=None) -> pd.DataFrame:
    """Validate a raw all-string DataFrame and return a normalised one.

    ``lines`` optionally gives the source line number of each row (default: row index + 2,
    i.e. a one-line header). The result has columns: line, timestamp (UTC datetime), username,
    source_ip (canonical form), event_type, status. A header-only file yields an empty frame.
    """
    raw = raw.copy()
    raw.columns = [str(c).strip().lower() for c in raw.columns]
    missing = [c for c in REQUIRED_COLUMNS if c not in raw.columns]
    if missing:
        raise LogValidationError(
            f"Missing required column(s): {', '.join(missing)}. Expected: {', '.join(REQUIRED_COLUMNS)}")

    df = raw[REQUIRED_COLUMNS].astype(str).apply(lambda col: col.str.strip())
    df.insert(0, "line", list(lines) if lines is not None else list(df.index + 2))

    problems: list[str] = []

    ts = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601", errors="coerce")
    for idx in df.index[ts.isna()]:
        problems.append(f"line {df.at[idx, 'line']}: timestamp '{_short(df.at[idx, 'timestamp'])}' is not ISO 8601")

    df["username"] = df["username"].str.lower()
    bad_user = (df["username"] == "") | (df["username"].str.len() > MAX_USERNAME_LENGTH)
    for idx in df.index[bad_user]:
        problems.append(f"line {df.at[idx, 'line']}: username is empty or longer than {MAX_USERNAME_LENGTH} characters")

    ip_ok = {v: _valid_ip(v) for v in df["source_ip"].unique()}
    for idx in df.index[~df["source_ip"].map(ip_ok).astype(bool)]:
        problems.append(f"line {df.at[idx, 'line']}: source_ip '{_short(df.at[idx, 'source_ip'])}' is not a valid IP address")

    df["event_type"] = df["event_type"].str.lower()
    for idx in df.index[~df["event_type"].isin(VALID_EVENT_TYPES)]:
        problems.append(f"line {df.at[idx, 'line']}: event_type '{_short(df.at[idx, 'event_type'])}' "
                        f"is not one of {', '.join(VALID_EVENT_TYPES)}")

    df["status"] = df["status"].str.lower()
    for idx in df.index[~df["status"].isin(VALID_STATUSES)]:
        problems.append(f"line {df.at[idx, 'line']}: status '{_short(df.at[idx, 'status'])}' "
                        f"is not one of {', '.join(VALID_STATUSES)}")

    if problems:
        _raise_problems(problems)

    df["timestamp"] = ts
    df["source_ip"] = df["source_ip"].map(lambda v: str(ipaddress.ip_address(v)))
    return df.reset_index(drop=True)


def load_events(path) -> pd.DataFrame:
    """Read a CSV file from disk and validate it. Raises LogValidationError on any problem."""
    path = Path(path)
    if not path.is_file():
        raise LogValidationError(f"Input file not found: {path}")
    if path.stat().st_size == 0:
        raise LogValidationError(f"Input file is empty (no header row): {path}")
    # The csv module (not pandas.read_csv) is used so every row's field count is checked and
    # the true line number is kept; pandas would silently drop surplus fields.
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            reader = csv.reader(fh)
            header = next(reader, None)
            if header is None:
                raise LogValidationError(f"Input file has no header row: {path}")
            rows, line_numbers, shape_problems = [], [], []
            for row in reader:
                if not row:  # blank line
                    continue
                if len(row) != len(header):
                    shape_problems.append(f"line {reader.line_num}: expected {len(header)} field(s), found {len(row)}")
                else:
                    rows.append(row)
                    line_numbers.append(reader.line_num)
    except (csv.Error, UnicodeDecodeError) as exc:
        raise LogValidationError(f"Could not parse {path.name} as UTF-8 CSV: {exc}") from exc
    if shape_problems:
        _raise_problems(shape_problems)
    events = validate_events(pd.DataFrame(rows, columns=header, dtype=str), line_numbers)
    logger.info("Loaded %d event(s) from %s", len(events), path.name)
    return events
