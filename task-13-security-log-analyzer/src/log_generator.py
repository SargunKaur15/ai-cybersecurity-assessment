"""Synthetic authentication-event generator (Task 13).

Everything here is fabricated. Source IPs come only from the documentation ranges
reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); usernames are
invented. Timestamps use a fixed date so output depends only on the seed.

The data is a quiet baseline of normal activity plus seven *planted scenarios*. Each
scenario records what the analyzer is expected to do with the DEFAULT configuration,
including two deliberate misses (S6, S7) and one deliberate false-positive pattern (S5),
so the tool's limitations can be demonstrated rather than only asserted.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pandas as pd

SEED = 42
BASE = datetime(2024, 3, 4, 8, 0, 0, tzinfo=timezone.utc)
COLUMNS = ["timestamp", "username", "source_ip", "event_type", "status"]

REGULAR_USERS = ["alice", "bob", "carol", "dana", "erin", "frank", "grace", "heidi", "ivan", "judy", "kim", "leo"]
OFFICE_USERS = ["nina", "omar", "pat", "quinn", "ravi"]  # share one office/NAT address
OFFICE_IP = "192.0.2.10"
HOME_IPS = {u: f"198.51.100.{11 + i}" for i, u in enumerate(REGULAR_USERS)}
HOME_IPS.update({u: OFFICE_IP for u in OFFICE_USERS})


def _at(hour: int, minute: int = 0, second: int = 0) -> datetime:
    return BASE.replace(hour=hour, minute=minute, second=second)


def generate_events(seed: int = SEED):
    """Return (events DataFrame sorted by time, list of planted-scenario descriptions)."""
    rng = random.Random(seed)
    rows: list[tuple] = []

    def add(ts, user, ip, event_type, status):
        rows.append((ts, user, ip, event_type, status))

    # ---- baseline: normal logins/logouts, rare single typos, a few MFA events -------------
    for user in REGULAR_USERS + OFFICE_USERS:
        for _ in range(rng.choice([1, 2])):
            login = BASE + timedelta(seconds=rng.randint(0, 8 * 3600))
            ip = HOME_IPS[user]
            if rng.random() < 0.05:  # a single mistyped password
                add(login - timedelta(seconds=rng.randint(20, 90)), user, ip, "login", "failure")
            add(login, user, ip, "login", "success")
            if rng.random() < 0.3:
                add(login + timedelta(seconds=5), user, ip, "mfa_challenge", "success")
            add(login + timedelta(minutes=rng.randint(30, 240)), user, ip, "logout", "success")
    add(_at(12, 0), "judy", HOME_IPS["judy"], "password_reset", "success")

    scenarios = []

    # S1: benign fumble: 3 failures then success, below the default threshold of 5.
    ip = HOME_IPS["dana"]
    for offset in (0, 25, 70):
        add(_at(9, 12) + timedelta(seconds=offset), "dana", ip, "login", "failure")
    add(_at(9, 12) + timedelta(seconds=100), "dana", ip, "login", "success")
    scenarios.append({"id": "S1", "name": "benign_fumble", "benign": True, "usernames": ["dana"], "source_ip": ip,
                      "description": "3 failed logins then a success within ~100 s, from the user's usual address.",
                      "expected_default_alerts": []})

    # S2: repeated failures with no success against 'admin' from one external address.
    ip, t = "203.0.113.50", _at(10, 3)
    for _ in range(12):
        add(t, "admin", ip, "login", "failure")
        t += timedelta(seconds=rng.randint(15, 25))
    scenarios.append({"id": "S2", "name": "repeated_failures_no_success", "benign": False, "usernames": ["admin"], "source_ip": ip,
                      "description": "12 failed logins for 'admin' in about 4 minutes, never followed by a success.",
                      "expected_default_alerts": [
                          {"rule": "REPEATED_FAILED_LOGINS", "severity": "medium", "usernames": ["admin"], "source_ip": ip}]})

    # S3: 6 failures then a success for the same account from the same address.
    ip, t = "203.0.113.23", _at(11, 20)
    for _ in range(6):
        add(t, "carol", ip, "login", "failure")
        t += timedelta(seconds=45)
    add(t + timedelta(seconds=15), "carol", ip, "login", "success")
    scenarios.append({"id": "S3", "name": "success_after_repeated_failures", "benign": False, "usernames": ["carol"], "source_ip": ip,
                      "description": "6 failed logins in ~4 minutes, then a success ~60 s after the last failure, same address.",
                      "expected_default_alerts": [
                          {"rule": "REPEATED_FAILED_LOGINS", "severity": "low", "usernames": ["carol"], "source_ip": ip},
                          {"rule": "SUCCESS_AFTER_REPEATED_FAILURES", "severity": "medium", "usernames": ["carol"], "source_ip": ip}]})

    # S4: one failure each against 8 accounts from one address (spray), one later success.
    ip, t = "203.0.113.77", _at(13, 5)
    targets = ["alice", "bob", "erin", "frank", "ivan", "judy", "kim", "leo"]
    for user in targets:
        add(t, user, ip, "login", "failure")
        t += timedelta(seconds=45)
    add(_at(13, 12), "frank", ip, "login", "success")
    scenarios.append({"id": "S4", "name": "password_spray_pattern", "benign": False, "usernames": sorted(targets), "source_ip": ip,
                      "description": "1 failed login each for 8 accounts in ~6 minutes from one address; one later success for 'frank'.",
                      "expected_default_alerts": [
                          {"rule": "MULTI_ACCOUNT_FAILURES_FROM_SOURCE", "severity": "medium",
                           "usernames": sorted(targets), "source_ip": ip}]})

    # S5: shared office address; an outage makes 5 colleagues each fail once then succeed (benign).
    t = _at(8, 30)
    for user in OFFICE_USERS:
        add(t, user, OFFICE_IP, "login", "failure")
        add(t + timedelta(seconds=40), user, OFFICE_IP, "login", "success")
        t += timedelta(seconds=75)
    scenarios.append({"id": "S5", "name": "shared_nat_false_positive", "benign": True, "usernames": sorted(OFFICE_USERS), "source_ip": OFFICE_IP,
                      "description": "5 colleagues behind one office address each fail once during an SSO hiccup, then succeed. Benign by construction.",
                      "expected_default_alerts": [
                          {"rule": "MULTI_ACCOUNT_FAILURES_FROM_SOURCE", "severity": "medium",
                           "usernames": sorted(OFFICE_USERS), "source_ip": OFFICE_IP}]})

    # S6: slow, low-rate guessing: 12 failures, one every 15 minutes (below any 10-minute window).
    ip = "203.0.113.99"
    for k in range(12):
        add(_at(14, 0) + timedelta(minutes=15 * k), "grace", ip, "login", "failure")
    scenarios.append({"id": "S6", "name": "slow_low_rate_attempts", "benign": False, "usernames": ["grace"], "source_ip": ip,
                      "description": "12 failed logins spread over ~3 hours (one per 15 min). Missed by design with default settings.",
                      "expected_default_alerts": []})

    # S7: failures against one account spread over 6 different addresses, then a success from a 7th.
    t = _at(15, 30)
    for k in range(6):
        add(t, "heidi", f"203.0.113.{101 + k}", "login", "failure")
        t += timedelta(seconds=50)
    add(_at(15, 40), "heidi", "203.0.113.107", "login", "success")
    scenarios.append({"id": "S7", "name": "distributed_single_account", "benign": False, "usernames": ["heidi"], "source_ip": "203.0.113.101-107",
                      "description": "6 failures for one account, each from a different address, then a success from a 7th. Missed by design.",
                      "expected_default_alerts": []})

    rows.sort(key=lambda r: r[0])  # stable: ties keep generation order
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["timestamp"] = df["timestamp"].map(lambda ts: ts.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return df, scenarios
