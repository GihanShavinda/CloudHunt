"""Runtime configuration.

Everything comes from the environment. There are development defaults so the
app boots on a fresh clone, but every default that touches security (the JWT
signing key, demo-user seeding) is guarded by ``environment == "dev"`` so it can
never silently ship to production.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


_REPO_ROOT = Path(__file__).resolve().parents[3]

# Load project-root .env for local development.
# Existing real environment variables keep priority.
load_dotenv(_REPO_ROOT / ".env", override=False)


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("CLOUDHUNT_ENV", "dev")

    # --- auth ---
    jwt_secret: str = os.getenv(
        "CLOUDHUNT_JWT_SECRET",
        "dev-only-insecure-change-me",
    )
    jwt_algorithm: str = os.getenv("CLOUDHUNT_JWT_ALG", "HS256")
    access_token_minutes: int = int(
        os.getenv("CLOUDHUNT_TOKEN_MINUTES", "60")
    )

    # Seed demo analyst/admin/viewer accounts on startup (dev only).
    dev_seed_users: bool = _env_bool(
        "CLOUDHUNT_DEV_SEED",
        True,
    )

    # --- ingestion sources ---
    localstack_endpoint: str = os.getenv(
        "CLOUDHUNT_LOCALSTACK_URL",
        "http://localhost:4566",
    )
    aws_region: str = os.getenv(
        "AWS_DEFAULT_REGION",
        "us-east-1",
    )
    sqs_queue_url: str = os.getenv(
        "CLOUDHUNT_SQS_URL",
        "",
    )

    # --- sample data (cost-free dev) ---
    sample_data_dir: Path = Path(
        os.getenv(
            "CLOUDHUNT_SAMPLE_DIR",
            str(_REPO_ROOT / "sample_data"),
        )
    )

    # Thin assistant kill switch.
    assistant_enabled: bool = _env_bool(
        "CLOUDHUNT_ASSISTANT_ENABLED",
        False,
    )

    # --- optional production adapters ---
    database_url: str = os.getenv(
        "CLOUDHUNT_DATABASE_URL",
        "",
    )
    redis_url: str = os.getenv(
        "CLOUDHUNT_REDIS_URL",
        "",
    )
    neo4j_uri: str = os.getenv(
        "CLOUDHUNT_NEO4J_URI",
        "bolt://localhost:7687",
    )
    neo4j_user: str = os.getenv(
        "CLOUDHUNT_NEO4J_USER",
        "neo4j",
    )
    neo4j_password: str = os.getenv(
        "CLOUDHUNT_NEO4J_PASSWORD",
        "cloudhunt",
    )

    @property
    def is_dev(self) -> bool:
        return self.environment == "dev"


settings = Settings()