from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from morphiq.cli.main import app

runner = CliRunner()


def _write_config(path: Path, tmp_path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "log_file_path": str(tmp_path / "access.log"),
                "firewall_backend": "mock",
                "db_path": str(tmp_path / "cli.db"),
                "pid_file_path": str(tmp_path / "morphiq.pid"),
                "morphiq_log_file": str(tmp_path / "morphiq.log"),
                "llm_enabled": False,
                "dashboard_enabled": False,
            }
        )
    )


def test_status_command_reports_offline(tmp_path):
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, tmp_path)

    result = runner.invoke(app, ["status", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "OFFLINE" in result.output


def test_audit_command_handles_empty_database(tmp_path):
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, tmp_path)

    result = runner.invoke(app, ["audit", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "Showing 0 events" in result.output


def test_management_commands_work_with_empty_database(tmp_path):
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, tmp_path)

    ban_result = runner.invoke(app, ["ban", "list", "--config", str(config_path)])
    whitelist_result = runner.invoke(
        app,
        ["whitelist", "check", "127.0.0.1", "--config", str(config_path)],
    )
    unban_result = runner.invoke(
        app, ["unban", "203.0.113.90", "--config", str(config_path)]
    )

    assert ban_result.exit_code == 0, ban_result.output
    assert whitelist_result.exit_code == 0, whitelist_result.output
    assert "PROTECTED" in whitelist_result.output
    assert unban_result.exit_code == 0, unban_result.output
    assert "not currently banned" in unban_result.output


def test_feedback_and_retrain_commands(tmp_path):
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, tmp_path)

    feedback_result = runner.invoke(
        app,
        ["feedback", "203.0.113.91", "tp", "--config", str(config_path)],
    )
    retrain_result = runner.invoke(app, ["retrain", "--config", str(config_path)])

    assert feedback_result.exit_code == 0, feedback_result.output
    assert "Feedback recorded" in feedback_result.output
    assert retrain_result.exit_code == 0, retrain_result.output
    assert "0 samples" in retrain_result.output
