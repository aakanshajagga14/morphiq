from __future__ import annotations

import pytest

from morphiq.fw.firewall_controller import FirewallController
from morphiq.llm_client import LLMClient
from morphiq.models import Action
from morphiq.pipeline.agent import Agent


@pytest.mark.asyncio
async def test_agent_fallback_blocks_and_audits(config_factory, store, log_entry):
    config = config_factory(llm_enabled=False)
    firewall = FirewallController(config, store)
    agent = Agent(config, store, firewall, LLMClient(config))

    decision = await agent.run(log_entry)

    assert decision.action is Action.BLOCK
    assert [ban.ip for ban in store.get_active_bans()] == [log_entry.effective_ip]
    audit = store.get_recent_audit(1)[0]
    assert audit.final_action == "block"
    assert audit.threat_label == "detector_escalation"
