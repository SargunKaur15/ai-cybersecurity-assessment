import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from generate_dataset import generate_dataset  # noqa: E402
from train_evaluate import build_pipeline, to_binary  # noqa: E402


@pytest.fixture(scope="session")
def small_df():
    return generate_dataset(n_total=400, seed=7)


@pytest.fixture(scope="session")
def trained_model(small_df):
    model = build_pipeline(seed=7)
    model.fit(small_df["text"].tolist(), to_binary(small_df["label"]))
    return model
