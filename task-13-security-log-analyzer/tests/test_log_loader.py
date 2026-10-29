import pytest

from log_loader import LogValidationError, load_events, validate_events
from log_helpers import frame
import pandas as pd

HEADER = "timestamp,username,source_ip,event_type,status\n"


def write(tmp_path, text, name="log.csv", encoding="utf-8"):
    p = tmp_path / name
    p.write_bytes(text.encode(encoding))
    return p


def test_valid_file_loads_and_normalises(tmp_path):
    p = write(tmp_path, HEADER + "2024-03-04T10:00:00Z,Alice,192.0.2.1,LOGIN, Success \n"
                                 "2024-03-04T10:01:00Z,bob,192.0.2.2,logout,success\n")
    df = load_events(p)
    assert list(df["username"]) == ["alice", "bob"]
    assert list(df["status"]) == ["success", "success"]
    assert list(df["line"]) == [2, 3]          # CSV line numbers, header is line 1
    assert str(df["timestamp"].dt.tz) == "UTC"


def test_column_names_are_case_and_space_insensitive(tmp_path):
    p = write(tmp_path, " Timestamp ,USERNAME,Source_IP,Event_Type,Status\n2024-03-04T10:00:00Z,a,192.0.2.1,login,failure\n")
    assert len(load_events(p)) == 1


def test_extra_columns_are_ignored(tmp_path):
    p = write(tmp_path, HEADER.strip() + ",note\n2024-03-04T10:00:00Z,a,192.0.2.1,login,failure,hello\n")
    assert "note" not in load_events(p).columns


def test_utf8_bom_is_handled(tmp_path):
    p = write(tmp_path, "﻿" + HEADER + "2024-03-04T10:00:00Z,a,192.0.2.1,login,failure\n")
    assert len(load_events(p)) == 1


def test_timestamps_without_offset_are_utc_and_offsets_are_converted():
    df = frame([("2024-03-04T10:00:00", "a", "192.0.2.1", "login", "failure"),
                ("2024-03-04T12:00:00+02:00", "a", "192.0.2.1", "login", "failure")])
    assert df["timestamp"].iloc[0] == df["timestamp"].iloc[1]


def test_ipv6_is_accepted_and_canonicalised():
    df = frame([("2024-03-04T10:00:00Z", "a", "2001:DB8:0:0:0:0:0:1", "login", "failure")])
    assert df["source_ip"].iloc[0] == "2001:db8::1"


def test_header_only_file_gives_empty_frame(tmp_path):
    df = load_events(write(tmp_path, HEADER))
    assert df.empty and "timestamp" in df.columns


def test_zero_byte_file_is_rejected(tmp_path):
    with pytest.raises(LogValidationError, match="empty"):
        load_events(write(tmp_path, ""))


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(LogValidationError, match="not found"):
        load_events(tmp_path / "nope.csv")


def test_missing_columns_named_in_error(tmp_path):
    with pytest.raises(LogValidationError, match="source_ip, status"):
        load_events(write(tmp_path, "timestamp,username,event_type\n2024-03-04T10:00:00Z,a,login\n"))


@pytest.mark.parametrize("row,fragment", [
    ("not-a-time,a,192.0.2.1,login,failure", "timestamp"),
    (",a,192.0.2.1,login,failure", "timestamp"),
    ("2024-03-04T10:00:00Z,,192.0.2.1,login,failure", "username"),
    ("2024-03-04T10:00:00Z,a,999.1.1.1,login,failure", "source_ip"),
    ("2024-03-04T10:00:00Z,a,not-an-ip,login,failure", "source_ip"),
    ("2024-03-04T10:00:00Z,a,192.0.2.1,teleport,failure", "event_type"),
    ("2024-03-04T10:00:00Z,a,192.0.2.1,login,maybe", "status"),
])
def test_each_bad_field_is_reported_with_line_number(tmp_path, row, fragment):
    with pytest.raises(LogValidationError) as exc:
        load_events(write(tmp_path, HEADER + "2024-03-04T10:00:00Z,ok,192.0.2.1,login,success\n" + row + "\n"))
    msg = str(exc.value)
    assert "line 3" in msg and fragment in msg and "line 2" not in msg


def test_many_problems_are_capped_but_counted(tmp_path):
    rows = "".join(f"bad{i},a,192.0.2.1,login,failure\n" for i in range(30))
    with pytest.raises(LogValidationError) as exc:
        load_events(write(tmp_path, HEADER + rows))
    assert "30 problem(s)" in str(exc.value) and "10 more" in str(exc.value)


def test_long_bad_values_are_truncated_in_errors(tmp_path):
    with pytest.raises(LogValidationError) as exc:
        load_events(write(tmp_path, HEADER + "2024-03-04T10:00:00Z,a,192.0.2.1,login," + "x" * 500 + "\n"))
    assert len(str(exc.value)) < 400


@pytest.mark.parametrize("bad_row,found", [
    ("2024-03-04T10:00:00Z,a,192.0.2.1,login,failure,x,y,z", 8),   # surplus fields must not be silently dropped
    ("2024-03-04T10:00:00Z,a,192.0.2.1", 3),                        # truncated row
])
def test_rows_with_wrong_field_count_are_reported(tmp_path, bad_row, found):
    good = "2024-03-04T10:00:00Z,a,192.0.2.1,login,failure\n"
    with pytest.raises(LogValidationError) as exc:
        load_events(write(tmp_path, HEADER + good + bad_row + "\n"))
    assert f"line 3: expected 5 field(s), found {found}" in str(exc.value)


def test_blank_lines_are_skipped_and_line_numbers_stay_true(tmp_path):
    df = load_events(write(tmp_path, HEADER + "\n2024-03-04T10:00:00Z,a,192.0.2.1,login,failure\n\n"
                                              "2024-03-04T10:00:05Z,a,192.0.2.1,login,failure\n\n"))
    assert list(df["line"]) == [3, 5]


def test_quoted_commas_are_parsed(tmp_path):
    df = load_events(write(tmp_path, HEADER + '2024-03-04T10:00:00Z,"smith, j",192.0.2.1,login,failure\n'))
    assert df["username"].iloc[0] == "smith, j"


def test_non_utf8_file_is_reported(tmp_path):
    with pytest.raises(LogValidationError):
        load_events(write(tmp_path, HEADER + "2024-03-04T10:00:00Z,caf\xe9,192.0.2.1,login,failure\n", encoding="latin-1"))


def test_validate_events_does_not_mutate_input():
    raw = pd.DataFrame([("2024-03-04T10:00:00Z", "ALICE", "192.0.2.1", "login", "failure")],
                       columns=["timestamp", "username", "source_ip", "event_type", "status"])
    validate_events(raw)
    assert raw["username"].iloc[0] == "ALICE"
