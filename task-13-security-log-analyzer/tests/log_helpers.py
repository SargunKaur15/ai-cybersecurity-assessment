"""Small builders for hand-written test events."""

from datetime import datetime, timedelta, timezone

import pandas as pd

from log_loader import REQUIRED_COLUMNS, validate_events

BASE = datetime(2024, 3, 4, 10, 0, 0, tzinfo=timezone.utc)
IP_A, IP_B = "192.0.2.1", "192.0.2.2"


def t(seconds=0):
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(seconds, user="alice", ip=IP_A, etype="login", status="failure"):
    return (t(seconds), user, ip, etype, status)


def fails(n, step=10, start=0, user="alice", ip=IP_A):
    return [ev(start + i * step, user, ip, "login", "failure") for i in range(n)]


def frame(rows):
    return validate_events(pd.DataFrame(list(rows), columns=REQUIRED_COLUMNS, dtype=str))
