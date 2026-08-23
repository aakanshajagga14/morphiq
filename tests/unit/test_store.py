from __future__ import annotations

from datetime import datetime, timedelta, timezone

from morphiq.models import AuditEvent, BanRecord


def test_store_round_trips_traffic_and_stats(store, log_entry):
    store.insert_traffic(log_entry, retention_s=3600)
    store.increment_stat("total_parsed")
    store.increment_stat("total_parsed", 2)

    history = store.get_traffic_history(log_entry.effective_ip, limit=10)

    assert len(history) == 1
    assert history[0].status_code == 401
    assert store.get_stats().total_parsed == 3


def test_store_round_trips_bans_and_audit_json(store):
    now = datetime.now(timezone.utc)
    store.insert_ban(
        BanRecord(
            ip="203.0.113.9",
            reason="test",
            banned_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    )
    store.append_audit(
        AuditEvent(
            source_ip="203.0.113.9",
            entry_raw="GET /admin",
            threat_label="test",
            confidence=0.9,
            recommended_action="block",
            final_action="block",
            reasoning="unit test",
            execution_trace={"stage": "agent"},
            error=None,
            occurred_at=now,
        )
    )

    ban = store.get_active_bans()[0]
    audit = store.get_recent_audit(1)[0]

    assert ban.banned_at.tzinfo is not None
    assert audit.execution_trace == {"stage": "agent"}
    assert audit.final_action == "block"
