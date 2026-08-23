from __future__ import annotations

from morphiq.fw.firewall_controller import FirewallController


def test_mock_firewall_blocks_and_unblocks(config_factory, store):
    firewall = FirewallController(config_factory(), store)

    assert firewall.block("203.0.113.10", "unit-test", 60)
    assert [ban.ip for ban in store.get_active_bans()] == ["203.0.113.10"]
    assert firewall.unblock("203.0.113.10")
    assert store.get_active_bans() == []


def test_firewall_never_blocks_loopback(config_factory, store):
    firewall = FirewallController(config_factory(), store)

    assert firewall.is_whitelisted("127.0.0.1")
    assert firewall.block("127.0.0.1", "should-not-block", 60) is False
