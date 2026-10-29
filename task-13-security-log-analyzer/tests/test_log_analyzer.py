import random

import pytest

from log_analyzer import (RULE_FAILURES, RULE_SPRAY, RULE_SUCCESS, AnalyzerConfig, detect, summarize)
from log_helpers import IP_A, IP_B, ev, fails, frame, t


def rules(alerts):
    return sorted((a.rule, a.severity) for a in alerts)


# ------------------------------------------------------------------ summary
def test_summary_counts_match_hand_count():
    df = frame([
        ev(0, "alice", IP_A, "login", "success"),
        ev(10, "alice", IP_A, "login", "failure"),
        ev(20, "bob", IP_B, "login", "failure"),
        ev(30, "alice", IP_A, "logout", "success"),
        ev(40, "bob", IP_B, "mfa_challenge", "failure"),   # not a login: must not count as a failed login
        ev(50, "alice", IP_A, "password_reset", "success"),
    ])
    s = summarize(df)
    assert (s["total_events"], s["successful_logins"], s["failed_logins"]) == (6, 1, 2)
    assert (s["unique_users"], s["unique_source_ips"]) == (2, 2)
    assert s["events_by_type"] == {"login": 3, "logout": 1, "mfa_challenge": 1, "password_reset": 1}
    assert s["first_event"] == t(0) and s["last_event"] == t(50)
    assert s["top_failed_source_ips"][0] == {"source_ip": IP_A, "failed_logins": 1}


def test_summary_of_empty_dataset():
    s = summarize(frame([]))
    assert s["total_events"] == s["failed_logins"] == s["unique_users"] == 0
    assert s["first_event"] is None and s["top_failed_source_ips"] == []
    assert detect(frame([])) == []


def test_usernames_are_case_insensitive_in_summary():
    df = frame([ev(0, "Alice", status="success"), ev(5, "ALICE", status="success")])
    assert summarize(df)["unique_users"] == 1


# --------------------------------------------------- normal / below threshold
def test_normal_activity_raises_no_alerts():
    df = frame([ev(0, "alice", status="success"), ev(3600, "alice", etype="logout", status="success"),
                ev(10, "bob", IP_B, status="success")])
    assert detect(df) == []


def test_below_threshold_is_not_alerted():
    assert detect(frame(fails(4))) == []


def test_failures_in_other_event_types_are_ignored():
    assert detect(frame([ev(i * 10, etype="mfa_challenge") for i in range(10)])) == []


# -------------------------------------------------- R1 repeated failures
def test_threshold_failures_in_window_raise_low_alert():
    alerts = detect(frame(fails(5)))
    assert rules(alerts) == [(RULE_FAILURES, "low")]
    assert alerts[0].event_count == 5 and alerts[0].usernames == ["alice"] and alerts[0].source_ip == IP_A


def test_window_boundary_is_inclusive():
    exactly = [ev(s) for s in (0, 150, 300, 450, 600)]    # span == 10 min
    just_over = [ev(s) for s in (0, 150, 300, 450, 601)]  # span == 10 min 1 s
    assert len(detect(frame(exactly))) == 1
    assert detect(frame(just_over)) == []


def test_failures_from_different_ips_do_not_combine():
    assert detect(frame(fails(3, ip=IP_A) + fails(3, start=5, ip=IP_B))) == []


def test_failures_for_different_users_do_not_combine_into_r1():
    assert detect(frame(fails(3, user="alice") + fails(3, start=5, user="bob"))) == []


def test_long_attack_is_one_merged_alert():
    alerts = detect(frame(fails(12, step=30)))
    assert len(alerts) == 1 and alerts[0].event_count == 12


def test_separate_bursts_make_separate_alerts():
    alerts = detect(frame(fails(5) + fails(5, start=3600)))
    assert [a.rule for a in alerts] == [RULE_FAILURES, RULE_FAILURES] and [a.event_count for a in alerts] == [5, 5]


def test_unsorted_input_gives_same_result_and_keeps_line_numbers():
    rows = fails(6)
    shuffled = rows[:]
    random.Random(1).shuffle(shuffled)
    a, b = detect(frame(rows)), detect(frame(shuffled))
    assert rules(a) == rules(b) and a[0].event_count == b[0].event_count == 6
    assert {e["line"] for e in b[0].evidence} == set(range(2, 8))


def test_custom_threshold_and_window():
    cfg = AnalyzerConfig(failure_threshold=3, window_minutes=1)
    assert len(detect(frame(fails(3, step=20)), cfg)) == 1           # 40 s span
    assert detect(frame(fails(3, step=40)), cfg) == []              # 80 s span


# ------------------------------------------------------------ severities
def test_severity_rises_with_failure_volume():
    assert detect(frame(fails(9)))[0].severity == "low"
    assert detect(frame(fails(10)))[0].severity == "medium"


def test_severity_reasons_are_explained():
    alert = detect(frame(fails(10)))[0]
    assert len(alert.severity_reasons) == 2 and "twice the threshold" in alert.severity_reasons[1]


def test_r1_is_raised_one_level_when_source_also_sprays():
    rows = fails(5, user="alice") + [ev(100 + i, f"user{i}", IP_A) for i in range(4)]  # 5 distinct users from IP_A
    alerts = detect(frame(rows))
    by_rule = {a.rule: a for a in alerts}
    assert by_rule[RULE_FAILURES].severity == "medium"
    assert any("raised one level" in r for r in by_rule[RULE_FAILURES].severity_reasons)
    assert by_rule[RULE_SPRAY].severity == "medium"


# ------------------------------------------- R2 success after failures
def test_success_after_repeated_failures_is_flagged():
    alerts = detect(frame(fails(5) + [ev(100, status="success")]))   # last failure at 40 s
    assert rules(alerts) == [(RULE_FAILURES, "low"), (RULE_SUCCESS, "medium")]
    r2 = next(a for a in alerts if a.rule == RULE_SUCCESS)
    assert r2.evidence[-1]["status"] == "success" and r2.event_count == 6
    assert "not a confirmed compromise" in r2.description


def test_success_window_boundary_is_inclusive():
    last = 40
    assert any(a.rule == RULE_SUCCESS for a in detect(frame(fails(5) + [ev(last + 600, status="success")])))
    assert not any(a.rule == RULE_SUCCESS for a in detect(frame(fails(5) + [ev(last + 601, status="success")])))


def test_success_before_or_during_failures_is_not_r2():
    assert not any(a.rule == RULE_SUCCESS for a in detect(frame(fails(5, start=100) + [ev(0, status="success")])))
    assert not any(a.rule == RULE_SUCCESS for a in detect(frame(fails(5) + [ev(40, status="success")])))  # same instant


@pytest.mark.parametrize("success", [ev(100, "alice", IP_B, status="success"),     # other address
                                     ev(100, "bob", IP_A, status="success")])       # other account
def test_success_for_different_user_or_ip_is_not_r2(success):
    assert not any(a.rule == RULE_SUCCESS for a in detect(frame(fails(5) + [success])))


def test_success_after_many_failures_is_high():
    alerts = detect(frame(fails(10) + [ev(200, status="success")]))
    assert next(a for a in alerts if a.rule == RULE_SUCCESS).severity == "high"


def test_success_without_enough_failures_is_not_flagged():
    assert detect(frame(fails(4) + [ev(100, status="success")])) == []


# -------------------------------------------------- R3 multi-account
def test_many_accounts_from_one_ip_raises_spray_alert():
    alerts = detect(frame([ev(i * 30, f"user{i}", IP_A) for i in range(5)]))
    assert rules(alerts) == [(RULE_SPRAY, "medium")]
    assert alerts[0].usernames == [f"user{i}" for i in range(5)] and alerts[0].event_count == 5


def test_four_accounts_do_not_trigger_spray():
    assert detect(frame([ev(i * 30, f"user{i}", IP_A) for i in range(4)])) == []


def test_spray_outside_window_is_not_flagged():
    # one account every 3 minutes: never 5 distinct accounts within 10 minutes
    assert detect(frame([ev(i * 180, f"user{i}", IP_A) for i in range(5)])) == []


def test_spray_of_twice_the_threshold_is_high():
    assert detect(frame([ev(i * 20, f"user{i}", IP_A) for i in range(10)]))[0].severity == "high"


def test_spray_notes_later_success_without_changing_severity():
    rows = [ev(i * 30, f"user{i}", IP_A) for i in range(5)] + [ev(300, "user2", IP_A, status="success")]
    alert = detect(frame(rows))[0]
    assert alert.severity == "medium"
    assert any("user2" in r for r in alert.severity_reasons) and alert.evidence[-1]["status"] == "success"


# ------------------------------------------------------ alert quality
def test_every_alert_has_evidence_that_exists_in_the_input():
    rows = fails(10) + [ev(200, status="success")] + [ev(1000 + i * 20, f"u{i}", IP_B) for i in range(6)]
    df = frame(rows)
    alerts = detect(df)
    assert len(alerts) >= 3
    for a in alerts:
        assert a.evidence and a.severity_reasons and a.recommended_steps
        for e in a.evidence:
            src = df[df["line"] == e["line"]].iloc[0]
            assert (src["username"], src["source_ip"], src["status"]) == (e["username"], e["source_ip"], e["status"])
            assert e["username"] in a.usernames


def test_evidence_is_capped_but_counts_stay_exact():
    alert = detect(frame(fails(12, step=5)), AnalyzerConfig(max_evidence_rows=3))[0]
    assert len(alert.evidence) == 3 and alert.evidence_omitted == 9 and alert.event_count == 12
    assert alert.evidence[-1]["timestamp"] == t(55)  # final event is always kept


def test_alert_wording_never_claims_a_confirmed_attack():
    rows = fails(10) + [ev(200, status="success")] + [ev(1000 + i * 20, f"u{i}", IP_B) for i in range(10)]
    for a in detect(frame(rows)):
        text = (a.description + " " + a.disposition).lower()
        assert "requires investigation" in text and "not a confirmed" in a.disposition.lower()
        assert "attack confirmed" not in text and "compromised" not in a.title.lower()


def test_alerts_are_ordered_high_first_and_ids_sequential():
    rows = fails(5, start=0) + [ev(2000 + i * 20, f"u{i}", IP_B) for i in range(10)]
    alerts = detect(frame(rows))
    assert [a.severity for a in alerts] == ["high", "low"]
    assert [a.alert_id for a in alerts] == ["A001", "A002"]


def test_detection_is_deterministic():
    df = frame(fails(10) + [ev(200, status="success")])
    assert [a.to_dict() for a in detect(df)] == [a.to_dict() for a in detect(df)]


# ------------------------------------------------------------- config
@pytest.mark.parametrize("kwargs", [
    {"failure_threshold": 1}, {"failure_threshold": 0}, {"failure_threshold": -3}, {"failure_threshold": 2.5},
    {"failure_threshold": True}, {"spray_user_threshold": 1}, {"max_evidence_rows": 1},
    {"window_minutes": 0}, {"window_minutes": -5}, {"window_minutes": float("nan")},
    {"window_minutes": float("inf")}, {"success_window_minutes": 0}, {"window_minutes": "10"},
])
def test_invalid_config_is_rejected(kwargs):
    with pytest.raises(ValueError):
        AnalyzerConfig(**kwargs)


def test_detect_requires_a_validated_frame():
    import pandas as pd
    with pytest.raises(ValueError, match="missing column"):
        detect(pd.DataFrame({"username": ["a"]}))
