import ipaddress
import json
from pathlib import Path

import pandas as pd
import pytest

from log_analyzer import AnalyzerConfig, detect
from log_generator import COLUMNS, SEED, generate_events
from log_loader import validate_events

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@pytest.fixture(scope="module")
def generated():
    events, scenarios = generate_events(SEED)
    return events, scenarios, validate_events(events.astype(str))


def test_same_seed_reproduces_and_different_seed_differs():
    a, _ = generate_events(1)
    b, _ = generate_events(1)
    c, _ = generate_events(2)
    assert a.equals(b) and not a.equals(c)


def test_generated_data_passes_the_loader_and_is_time_ordered(generated):
    events, _, loaded = generated
    assert list(events.columns) == COLUMNS and len(events) > 100
    assert loaded["timestamp"].is_monotonic_increasing


def test_only_documentation_ip_ranges_are_used(generated):
    _, _, loaded = generated
    for ip in loaded["source_ip"].unique():
        assert any(ipaddress.ip_address(ip) in net for net in DOC_NETS), ip


def test_committed_sample_matches_generator(generated):
    events, _, _ = generated
    on_disk = pd.read_csv(DATA_DIR / "sample_auth_logs.csv", dtype=str, keep_default_na=False)
    assert on_disk.equals(events.astype(str))


def test_default_config_finds_exactly_the_planted_alerts(generated):
    _, scenarios, loaded = generated
    expected = {(e["rule"], e["severity"], tuple(e["usernames"]), e["source_ip"])
                for s in scenarios for e in s["expected_default_alerts"]}
    actual = {(a.rule, a.severity, tuple(a.usernames), a.source_ip) for a in detect(loaded)}
    assert actual == expected and len(expected) == 5


def test_benign_and_deliberately_missed_scenarios_stay_quiet_by_default(generated):
    _, _, loaded = generated
    flagged_users = {u for a in detect(loaded) for u in a.usernames}
    assert not {"dana", "grace", "heidi"} & flagged_users     # S1, S6, S7


def test_missed_scenarios_depend_on_configuration(generated):
    _, _, loaded = generated
    loose = detect(loaded, AnalyzerConfig(failure_threshold=3))
    assert any("dana" in a.usernames for a in loose)                        # S1 now flagged (more noise)
    slow = detect(loaded, AnalyzerConfig(window_minutes=120))
    assert any("grace" in a.usernames for a in slow)                        # S6 caught by a longer window


def test_benign_flags_match_the_scenario_design(generated):
    _, scenarios, _ = generated
    assert {s["id"] for s in scenarios if s["benign"]} == {"S1", "S5"}


def test_manifest_file_matches_generator(generated):
    _, scenarios, _ = generated
    manifest = json.loads((DATA_DIR / "planted_scenarios.json").read_text(encoding="utf-8"))
    assert manifest["scenarios"] == scenarios and [s["id"] for s in scenarios] == [f"S{i}" for i in range(1, 8)]
