from __future__ import annotations

import pytest

from morphiq.config import ConfigLoader, ConfigValidationError


def test_config_uses_safe_runtime_values(config_factory):
    config = config_factory()

    assert config.firewall_backend == "mock"
    assert config.llm_enabled is False
    assert config.dashboard_enabled is False
    assert config.pid_file_path.endswith("morphiq.pid")


def test_config_compiles_heuristic_patterns(config_factory):
    config = config_factory(
        heuristic_patterns=[
            {
                "name": "SQL injection",
                "field": "path",
                "pattern": r"union\s+select",
                "description": "test rule",
            }
        ]
    )

    assert len(config.heuristic_patterns) == 1
    assert config.heuristic_patterns[0].pattern.search("/UNION SELECT/password")


def test_config_rejects_missing_log_path():
    with pytest.raises(ConfigValidationError, match="log_file_path"):
        ConfigLoader.validate({"log_file_path": ""})
