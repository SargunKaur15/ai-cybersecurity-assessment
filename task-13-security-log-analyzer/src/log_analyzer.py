"""Summaries and explainable detection rules for authentication events (Task 13).

Rules (all consider only ``login`` events):

R1  REPEATED_FAILED_LOGINS               >= N failures for one (username, source_ip) within W minutes
R2  SUCCESS_AFTER_REPEATED_FAILURES      a success for the same (username, source_ip) within S minutes
                                         after an R1 burst
R3  MULTI_ACCOUNT_FAILURES_FROM_SOURCE   failures for >= M distinct usernames from one source_ip within W minutes

Alerts describe patterns that *warrant investigation*. They are never labelled as confirmed
attacks: every one of these patterns also has innocent explanations (typos, shared gateways,
outages). Each alert carries the exact events it is based on and the reasons for its severity.

Window comparisons are inclusive: events exactly W minutes apart are "within" the window.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from dataclasses import asdict, dataclass, field

import pandas as pd

logger = logging.getLogger("auth_log_analyzer")

LEVELS = ("low", "medium", "high")
RULE_FAILURES = "REPEATED_FAILED_LOGINS"
RULE_SUCCESS = "SUCCESS_AFTER_REPEATED_FAILURES"
RULE_SPRAY = "MULTI_ACCOUNT_FAILURES_FROM_SOURCE"
DISPOSITION = "Requires investigation; not a confirmed incident."
REQUIRED_FRAME_COLUMNS = ["line", "timestamp", "username", "source_ip", "event_type", "status"]


@dataclass(frozen=True)
class AnalyzerConfig:
    failure_threshold: int = 5        # N: failures that make a burst
    window_minutes: float = 10.0      # W: burst / spray window
    success_window_minutes: float = 10.0  # S: how soon after a burst a success is reported
    spray_user_threshold: int = 5     # M: distinct accounts that make a spray pattern
    max_evidence_rows: int = 50       # evidence rows kept per alert (event_count is always exact)

    def __post_init__(self):
        for name in ("failure_threshold", "spray_user_threshold", "max_evidence_rows"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < 2:
                raise ValueError(f"{name} must be an integer >= 2 (got {v!r})")
        for name in ("window_minutes", "success_window_minutes"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
                raise ValueError(f"{name} must be a finite number > 0 (got {v!r})")


@dataclass
class Alert:
    alert_id: str
    rule: str
    severity: str
    title: str
    description: str
    usernames: list
    source_ip: str
    first_seen: str
    last_seen: str
    event_count: int
    severity_reasons: list
    recommended_steps: list
    evidence: list = field(default_factory=list)
    evidence_omitted: int = 0
    disposition: str = DISPOSITION

    def to_dict(self) -> dict:
        return asdict(self)


def _iso(ts) -> str:
    return pd.Timestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_frame(events: pd.DataFrame) -> None:
    missing = [c for c in REQUIRED_FRAME_COLUMNS if c not in events.columns]
    if missing:
        raise ValueError(f"events frame is missing column(s): {missing}; use log_loader.load_events()")


# ------------------------------------------------------------------ summary
def summarize(events: pd.DataFrame) -> dict:
    """Counts for the whole file. 'Logins' are rows with event_type == login."""
    _check_frame(events)
    logins = events[events["event_type"] == "login"]
    failed = logins[logins["status"] == "failure"]
    top = (failed.groupby("source_ip").size().rename("failed_logins").reset_index()
           .sort_values(["failed_logins", "source_ip"], ascending=[False, True]).head(5))
    return {
        "total_events": int(len(events)),
        "successful_logins": int((logins["status"] == "success").sum()),
        "failed_logins": int(len(failed)),
        "unique_users": int(events["username"].nunique()),
        "unique_source_ips": int(events["source_ip"].nunique()),
        "first_event": None if events.empty else _iso(events["timestamp"].min()),
        "last_event": None if events.empty else _iso(events["timestamp"].max()),
        "events_by_type": {k: int(v) for k, v in sorted(events["event_type"].value_counts().items())},
        "top_failed_source_ips": [{"source_ip": r.source_ip, "failed_logins": int(r.failed_logins)}
                                  for r in top.itertuples()],
    }


# ---------------------------------------------------------- window helpers
def _merge_ranges(ranges):
    merged: list[list[int]] = []
    for i, j in ranges:
        if merged and i <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], j)
        else:
            merged.append([i, j])
    return [tuple(r) for r in merged]


def _burst_ranges(times, threshold, window):
    """Index ranges [i, j] (merged) where >= threshold events fall within `window`."""
    ranges, i = [], 0
    for j in range(len(times)):
        while times[j] - times[i] > window:
            i += 1
        if j - i + 1 >= threshold:
            ranges.append((i, j))
    return _merge_ranges(ranges)


def _spray_ranges(times, users, threshold, window):
    """Index ranges where >= threshold distinct users appear within `window`."""
    counts: Counter = Counter()
    ranges, i = [], 0
    for j in range(len(times)):
        counts[users[j]] += 1
        while times[j] - times[i] > window:
            counts[users[i]] -= 1
            if counts[users[i]] == 0:
                del counts[users[i]]
            i += 1
        if len(counts) >= threshold:
            ranges.append((i, j))
    return _merge_ranges(ranges)


def _evidence(rows: pd.DataFrame, max_rows: int):
    """Evidence list (original CSV line numbers kept). If capped, the final row is always kept."""
    recs = [{"line": int(r.line), "timestamp": _iso(r.timestamp), "username": r.username,
             "source_ip": r.source_ip, "event_type": r.event_type, "status": r.status}
            for r in rows.itertuples()]
    if len(recs) <= max_rows:
        return recs, 0
    return recs[: max_rows - 1] + [recs[-1]], len(recs) - max_rows


def _bump(level: str) -> str:
    return LEVELS[min(LEVELS.index(level) + 1, len(LEVELS) - 1)]


def _fmt_delta(seconds: float) -> str:
    seconds = int(round(seconds))
    return f"{seconds} s" if seconds < 120 else f"{seconds / 60:.1f} min"


# ---------------------------------------------------------------- detection
def detect(events: pd.DataFrame, config: AnalyzerConfig = AnalyzerConfig()) -> list:
    """Run all rules and return alerts ordered by severity (high first), then time."""
    _check_frame(events)
    window = pd.Timedelta(minutes=config.window_minutes)
    success_window = pd.Timedelta(minutes=config.success_window_minutes)
    N, M = config.failure_threshold, config.spray_user_threshold

    logins = events[events["event_type"] == "login"]
    fails = logins[logins["status"] == "failure"].sort_values("timestamp", kind="stable")
    succs = logins[logins["status"] == "success"].sort_values("timestamp", kind="stable")
    succ_by_key = {k: g for k, g in succs.groupby(["username", "source_ip"])}

    # R3 first, because R1/R2 severity can depend on it.
    sprays = []  # (ip, failure rows, related success rows)
    for ip, grp in fails.groupby("source_ip", sort=True):
        times, users = grp["timestamp"].tolist(), grp["username"].tolist()
        for i, j in _spray_ranges(times, users, M, window):
            rows = grp.iloc[i:j + 1]
            targeted = set(rows["username"])
            last = rows["timestamp"].max()
            ok = succs[(succs["source_ip"] == ip) & succs["username"].isin(targeted)
                       & (succs["timestamp"] >= rows["timestamp"].min())
                       & (succs["timestamp"] <= last + success_window)]
            sprays.append((ip, rows, ok))
    spray_ips = {ip for ip, _, _ in sprays}

    alerts: list[Alert] = []

    for ip, rows, ok in sprays:
        users = sorted(set(rows["username"]))
        n = len(users)
        level = "medium"
        reasons = [f"{n} distinct accounts failed from this address within {config.window_minutes:g} min "
                   f"(threshold {M}): base severity medium"]
        if n >= 2 * M:
            level = "high"
            reasons.append(f"{n} accounts is at least twice the threshold ({2 * M}): raised to high")
        if not ok.empty:
            reasons.append(f"{ok['username'].nunique()} of the {n} targeted account(s) had a successful login from this "
                           f"address shortly afterwards ({', '.join(sorted(set(ok['username'])))}); "
                           "severity not changed because this also happens in benign cases, but check those accounts first")
        ev, omitted = _evidence(pd.concat([rows, ok]).sort_values("timestamp", kind="stable"), config.max_evidence_rows)
        alerts.append(Alert(
            alert_id="", rule=RULE_SPRAY, severity=level,
            title="Failed logins against many accounts from one source",
            description=(f"{ip} failed to log in to {n} distinct accounts ({len(rows)} failed attempts) between "
                         f"{_iso(rows['timestamp'].min())} and {_iso(rows['timestamp'].max())}. This pattern is associated "
                         "with password spraying, but shared gateways/NAT, single sign-on outages and scanners can look the "
                         "same. Requires investigation."),
            usernames=users, source_ip=ip, first_seen=_iso(rows["timestamp"].min()), last_seen=_iso(rows["timestamp"].max()),
            event_count=int(len(rows)), severity_reasons=reasons,
            recommended_steps=[
                "Check whether the source address is a known shared gateway, VPN or office NAT.",
                "Look for a service outage or recent SSO/password-policy change around these times.",
                "Review the targeted accounts' other recent activity, starting with any that later succeeded.",
                "If the source is unexpected, consider temporary rate limiting or blocking per your policy."],
            evidence=ev, evidence_omitted=omitted))

    for (user, ip), grp in fails.groupby(["username", "source_ip"], sort=True):
        for i, j in _burst_ranges(grp["timestamp"].tolist(), N, window):
            rows = grp.iloc[i:j + 1]
            n, first, last = len(rows), rows["timestamp"].min(), rows["timestamp"].max()
            sprayed = ip in spray_ips

            level = "low"
            reasons = [f"{n} failures within {config.window_minutes:g} min meets threshold {N}: base severity low"]
            if n >= 2 * N:
                level = "medium"
                reasons.append(f"{n} failures is at least twice the threshold ({2 * N}): raised to medium")
            if sprayed:
                level = _bump(level)
                reasons.append("the same source address also failed against many other accounts (see multi-account alert): raised one level")
            ev, omitted = _evidence(rows, config.max_evidence_rows)
            alerts.append(Alert(
                alert_id="", rule=RULE_FAILURES, severity=level,
                title="Repeated failed logins for one account from one source",
                description=(f"{n} failed logins for '{user}' from {ip} between {_iso(first)} and {_iso(last)} "
                             f"(threshold {N} within {config.window_minutes:g} min). This may indicate password guessing, but a user "
                             "mistyping a password or a misconfigured client can produce the same pattern. Requires investigation."),
                usernames=[user], source_ip=ip, first_seen=_iso(first), last_seen=_iso(last), event_count=int(n),
                severity_reasons=reasons,
                recommended_steps=[
                    "Ask whether the account owner recognises this activity.",
                    "Check the account's lockout, MFA and recent password-reset state.",
                    "Review other activity from the same source address in the same period.",
                    "If the source is unexpected, consider rate limiting or blocking per your policy."],
                evidence=ev, evidence_omitted=omitted))

            # R2: success from the same account and address shortly after the burst.
            later = succ_by_key.get((user, ip))
            if later is None:
                continue
            hit = later[(later["timestamp"] > last) & (later["timestamp"] - last <= success_window)]
            if hit.empty:
                continue
            first_ok = hit.iloc[:1]
            gap = (first_ok["timestamp"].iloc[0] - last).total_seconds()
            level = "medium"
            reasons = [f"success followed {n} repeated failures from the same address: base severity medium "
                       "(a user who then remembers the password looks identical)"]
            if n >= 2 * N:
                level = _bump(level)
                reasons.append(f"{n} failures is at least twice the threshold ({2 * N}): raised to high")
            if sprayed:
                level = _bump(level)
                reasons.append("the same source address also failed against many other accounts: raised one level")
            ev, omitted = _evidence(pd.concat([rows, first_ok]), config.max_evidence_rows)
            alerts.append(Alert(
                alert_id="", rule=RULE_SUCCESS, severity=level,
                title="Successful login shortly after repeated failures",
                description=(f"A successful login for '{user}' from {ip} at {_iso(first_ok['timestamp'].iloc[0])} came "
                             f"{_fmt_delta(gap)} after {n} failed logins from the same address. This is consistent with a guessed "
                             "or later-remembered password; the data cannot show which. Requires investigation (not a confirmed compromise)."),
                usernames=[user], source_ip=ip, first_seen=_iso(first), last_seen=_iso(first_ok["timestamp"].iloc[0]),
                event_count=int(n + 1), severity_reasons=reasons,
                recommended_steps=[
                    "Contact the account owner through a separate, trusted channel and confirm the login was theirs.",
                    "Review what the session did after logging in, using authorised audit logs.",
                    "If not recognised, follow your incident process: reset credentials, revoke sessions, check MFA enrolment.",
                    "Check whether the source address appears in other alerts."],
                evidence=ev, evidence_omitted=omitted))

    alerts.sort(key=lambda a: (-LEVELS.index(a.severity), a.first_seen, a.rule, a.source_ip))
    for k, alert in enumerate(alerts, start=1):
        alert.alert_id = f"A{k:03d}"
    logger.info("Detection finished: %d alert(s)", len(alerts))
    return alerts
