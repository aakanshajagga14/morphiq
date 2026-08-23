from __future__ import annotations

import asyncio

import pytest

from morphiq.daemon import Daemon


@pytest.mark.asyncio
async def test_daemon_pipeline_escalates_and_blocks(config_factory, log_entry):
    config = config_factory(
        heuristic_patterns=[
            {
                "name": "Protected login",
                "field": "path",
                "pattern": r"/login",
                "description": "integration-test rule",
            }
        ],
        poll_interval_s=1,
    )
    daemon = Daemon(config)
    daemon_task = asyncio.create_task(daemon.start())

    try:
        await asyncio.sleep(0.1)
        assert daemon_task.done() is False

        await daemon.raw_queue.put(log_entry)

        for _ in range(100):
            if daemon.store.get_active_bans():
                break
            await asyncio.sleep(0.02)

        bans = daemon.store.get_active_bans()
        stats = daemon.store.get_stats()

        assert [ban.ip for ban in bans] == [log_entry.effective_ip]
        assert stats.heuristic_flagged == 1
        assert stats.agent_invoked == 1
        assert stats.blocked == 1
    finally:
        daemon._request_stop()
        await asyncio.wait_for(daemon_task, timeout=5)
