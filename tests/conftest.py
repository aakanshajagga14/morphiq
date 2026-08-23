from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

from morphiq.config import Config, ConfigLoader
from morphiq.models import LogEntry
from morphiq.store.sqlite_store import SQLiteStore


@pytest.fixture
def config_factory(tmp_path: Path) -> Callable[..., Config]:
    def make_config(**overrides: Any) -> Config:
        values: dict[str, Any] = {
            "log_file_path": str(tmp_path / "access.log"),
            "firewall_backend": "mock",
            "db_path": str(tmp_path / "morphiq.db"),
            "pid_file_path": str(tmp_path / "morphiq.pid"),
            "morphiq_log_file": str(tmp_path / "morphiq.log"),
            "base_model_path": str(tmp_path / "base_model.joblib"),
            "isolation_forest_model_path": str(tmp_path / "if_model.joblib"),
            "llm_enabled": False,
            "dashboard_enabled": False,
        }
        values.update(overrides)
        return ConfigLoader.validate(values)

    return make_config


@pytest.fixture
def store(tmp_path: Path) -> SQLiteStore:
    database = SQLiteStore(str(tmp_path / "test.db"))
    database.initialize()
    yield database
    database.close()


@pytest.fixture
def log_entry() -> LogEntry:
    return LogEntry(
        source_ip="198.51.100.10",
        effective_ip="198.51.100.10",
        method="GET",
        path="/login",
        query_string="user=admin",
        status_code=401,
        user_agent="pytest",
        bytes_sent=128,
        raw_line='198.51.100.10 - - [01/Jan/2026:00:00:00 +0000] "GET /login?user=admin HTTP/1.1" 401 128 "-" "pytest"',
        timestamp=datetime.now(timezone.utc),
    )
