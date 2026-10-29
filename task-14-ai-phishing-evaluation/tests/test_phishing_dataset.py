import re

import pytest

from generate_dataset import COLUMNS, generate_dataset, generate_shifted_dataset

ALLOWED_HOST_SUFFIXES = ("example.com", "example.net", "example.org", "example.invalid", ".test")
HOST_RE = re.compile(r"https?://([^/\s]+)", re.IGNORECASE)


def test_same_seed_is_reproducible():
    a = generate_dataset(n_total=200, seed=1)
    b = generate_dataset(n_total=200, seed=1)
    assert a.equals(b)


def test_different_seed_changes_data():
    a = generate_dataset(n_total=200, seed=1)
    b = generate_dataset(n_total=200, seed=2)
    assert not a["text"].equals(b["text"])


def test_schema_and_labels(small_df):
    assert list(small_df.columns) == COLUMNS
    assert set(small_df["label"]) == {"phishing", "legitimate"}
    assert (small_df["text"].str.strip() != "").all()
    assert small_df["message_id"].is_unique


def test_class_fraction_and_size():
    df = generate_dataset(n_total=1000, phishing_fraction=0.4)
    assert len(df) == 1000
    assert (df["label"] == "phishing").sum() == 400


def test_no_exact_duplicate_messages():
    df = generate_dataset(n_total=1000)
    assert df["text"].is_unique


def test_all_urls_use_reserved_example_domains():
    for df in (generate_dataset(n_total=500), generate_shifted_dataset(n_total=200)):
        for text in df["text"]:
            for host in HOST_RE.findall(text):
                assert host.lower().endswith(ALLOWED_HOST_SUFFIXES), host


def test_shifted_set_uses_disjoint_templates_and_texts():
    main, shifted = generate_dataset(n_total=1000), generate_shifted_dataset(n_total=200)
    assert set(main["template_id"]).isdisjoint(shifted["template_id"])
    assert set(main["text"]).isdisjoint(shifted["text"])


@pytest.mark.parametrize("fraction", [0.0, 1.0, -0.1, 1.5])
def test_invalid_fraction_rejected(fraction):
    with pytest.raises(ValueError):
        generate_dataset(n_total=100, phishing_fraction=fraction)


def test_too_few_messages_rejected():
    with pytest.raises(ValueError):
        generate_dataset(n_total=1)
