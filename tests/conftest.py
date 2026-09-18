"""Shared test fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Ensure deterministic dev config before any cloudhunt import reads settings.
os.environ.setdefault("CLOUDHUNT_ENV", "dev")
os.environ.setdefault("CLOUDHUNT_JWT_SECRET", "test-secret")

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "sample_data"


@pytest.fixture(scope="session")
def sample_dir() -> Path:
    return SAMPLE


@pytest.fixture(scope="session")
def cloudtrail_dir(sample_dir: Path) -> Path:
    return sample_dir / "cloudtrail"


@pytest.fixture(scope="session")
def guardduty_dir(sample_dir: Path) -> Path:
    return sample_dir / "guardduty"


# --- Milestone 2: IAM graph + policy evaluation ---
@pytest.fixture(scope="session")
def authz(sample_dir: Path):
    from cloudhunt.graph.authorization import IamAuthorization

    return IamAuthorization.from_file(sample_dir / "iam_auth" / "authz_snapshot_01.json")


@pytest.fixture()
def evaluator(authz):
    from cloudhunt.graph.policy_eval import PolicyEvaluator

    return PolicyEvaluator(authz)


@pytest.fixture()
def graph(authz):
    from cloudhunt.graph.model import build_graph

    return build_graph(authz)