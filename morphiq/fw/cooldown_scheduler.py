from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from morphiq.config import Config
from morphiq.fw.firewall_controller import FirewallController
from morphiq.models import AuditEvent
from morphiq.store.sqlite_store import SQLiteStore

logger = logging.getLogger(__name__)

class CooldownScheduler:
    def __init__(self, config: Config, store: SQLiteStore, fw: FirewallController):
        self.config = config
        self.fw = fw
        self.store = store
        self._stop_event = asyncio.Event()

    async def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.config.poll_interval_s)
            except asyncio.CancelledError:
                break

            if self._stop_event.is_set():
                break

            active_bans = self.store.get_active_bans()
            now = datetime.now(timezone.utc)
            unbanned_count = 0

            for ban in active_bans:
                if ban.expires_at < now:
                    if self.fw.unblock(ban.ip):
                        audit_event = AuditEvent(
                            source_ip=ban.ip,
                            entry_raw="",
                            threat_label="expired_ban",
                            confidence=None,
                            recommended_action="unban",
                            final_action="unban",
                            reasoning="Ban duration elapsed",
                            execution_trace={"component": "cooldown_scheduler"},
                            error=None,
                            occurred_at=datetime.now(timezone.utc),
                        )
                        self.store.append_audit(audit_event)
                        unbanned_count += 1
                    else:
                        logger.error(f"Failed to unblock {ban.ip}, retaining ban for next cycle.")

            logger.info(f"Unbanned {unbanned_count} IPs this cycle.")

    def stop(self) -> None:
        self._stop_event.set()
