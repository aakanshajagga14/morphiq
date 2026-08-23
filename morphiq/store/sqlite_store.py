import sqlite3
import threading
from datetime import datetime
from morphiq.models import (
    LogEntry, TrafficRecord, BanRecord, AuditEvent,
    FeedbackEvent, ProbeEvent, DaemonStats
)

class SQLiteStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()

    def initialize(self) -> None:
        with self._lock:
            self._conn.execute('PRAGMA journal_mode=WAL')
            
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS traffic_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    effective_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    query_string TEXT DEFAULT '',
                    status_code INTEGER NOT NULL,
                    user_agent TEXT DEFAULT '',
                    bytes_sent INTEGER DEFAULT 0,
                    raw_line TEXT DEFAULT '',
                    observed_at TEXT NOT NULL
                )
            """)
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ip ON traffic_history(effective_ip)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_history(observed_at)")

            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS active_bans (
                    ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    banned_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
            """)

            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    entry_raw TEXT NOT NULL,
                    threat_label TEXT,
                    confidence REAL,
                    recommended_action TEXT,
                    final_action TEXT NOT NULL,
                    reasoning TEXT,
                    execution_trace TEXT,
                    error TEXT,
                    occurred_at TEXT NOT NULL
                )
            """)
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON threat_audit_log(occurred_at)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ip ON threat_audit_log(source_ip)")

            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS feedback_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    is_false_positive INTEGER NOT NULL,
                    context TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                )
            """)

            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS probe_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    distinct_paths INTEGER NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    flagged_at TEXT NOT NULL
                )
            """)

            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS daemon_stats (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            self._conn.commit()

    def insert_traffic(self, entry: LogEntry, retention_s: int) -> None:
        observed_at = entry.timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')
        with self._lock:
            self._conn.execute("""
                INSERT INTO traffic_history
                (source_ip, effective_ip, method, path, query_string, status_code, user_agent, bytes_sent, raw_line, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.source_ip, entry.effective_ip, entry.method, entry.path, entry.query_string,
                entry.status_code, entry.user_agent, entry.bytes_sent, entry.raw_line, observed_at
            ))
            self._conn.commit()
        self.prune_traffic_history(retention_s)

    def get_traffic_history(self, ip: str, limit: int) -> list[TrafficRecord]:
        with self._lock:
            cursor = self._conn.execute("""
                SELECT source_ip, method, path, status_code, user_agent, observed_at
                FROM traffic_history
                WHERE effective_ip = ?
                ORDER BY observed_at DESC
                LIMIT ?
            """, (ip, limit))
            rows = cursor.fetchall()
            
        return [
            TrafficRecord(
                source_ip=row[0],
                method=row[1],
                path=row[2],
                status_code=row[3],
                user_agent=row[4],
                observed_at=datetime.fromisoformat(row[5])
            ) for row in rows
        ]

    def get_request_frequency(self, ip: str, window_s: int) -> float:
        now = datetime.utcnow()
        cutoff = datetime.fromtimestamp(now.timestamp() - window_s).strftime('%Y-%m-%dT%H:%M:%S.%f')
        with self._lock:
            cursor = self._conn.execute("""
                SELECT COUNT(*) FROM traffic_history
                WHERE effective_ip = ? AND observed_at >= ?
            """, (ip, cutoff))
            count = cursor.fetchone()[0]
            
        if window_s == 0:
            return 0.0
        return (count / window_s) * 60.0

    def insert_ban(self, ban: BanRecord) -> None:
        banned_at = ban.banned_at.strftime('%Y-%m-%dT%H:%M:%S.%f')
        expires_at = ban.expires_at.strftime('%Y-%m-%dT%H:%M:%S.%f')
        with self._lock:
            self._conn.execute("""
                INSERT OR REPLACE INTO active_bans (ip, reason, banned_at, expires_at)
                VALUES (?, ?, ?, ?)
            """, (ban.ip, ban.reason, banned_at, expires_at))
            self._conn.commit()

    def get_active_bans(self) -> list[BanRecord]:
        with self._lock:
            cursor = self._conn.execute("SELECT ip, reason, banned_at, expires_at FROM active_bans")
            rows = cursor.fetchall()
            
        return [
            BanRecord(
                ip=row[0],
                reason=row[1],
                banned_at=datetime.fromisoformat(row[2]),
                expires_at=datetime.fromisoformat(row[3])
            ) for row in rows
        ]

    def delete_ban(self, ip: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM active_bans WHERE ip = ?", (ip,))
            self._conn.commit()

    def append_audit(self, event: AuditEvent) -> None:
        occurred_at = event.occurred_at.strftime('%Y-%m-%dT%H:%M:%S.%f')
        with self._lock:
            self._conn.execute("""
                INSERT INTO threat_audit_log
                (source_ip, entry_raw, threat_label, confidence, recommended_action, final_action, reasoning, execution_trace, error, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.source_ip, event.entry_raw, event.threat_label, event.confidence,
                event.recommended_action, event.final_action, event.reasoning,
                event.execution_trace, event.error, occurred_at
            ))
            self._conn.commit()

    def get_recent_audit(self, n: int) -> list[AuditEvent]:
        with self._lock:
            cursor = self._conn.execute("""
                SELECT id, source_ip, entry_raw, threat_label, confidence, recommended_action, final_action, reasoning, execution_trace, error, occurred_at
                FROM threat_audit_log
                ORDER BY occurred_at DESC
                LIMIT ?
            """, (n,))
            rows = cursor.fetchall()
            
        return [
            AuditEvent(
                id=row[0],
                source_ip=row[1],
                entry_raw=row[2],
                threat_label=row[3],
                confidence=row[4],
                recommended_action=row[5],
                final_action=row[6],
                reasoning=row[7],
                execution_trace=row[8],
                error=row[9],
                occurred_at=datetime.fromisoformat(row[10])
            ) for row in rows
        ]

    def prune_traffic_history(self, retention_s: int) -> None:
        now = datetime.utcnow()
        cutoff = datetime.fromtimestamp(now.timestamp() - retention_s).strftime('%Y-%m-%dT%H:%M:%S.%f')
        with self._lock:
            self._conn.execute("DELETE FROM traffic_history WHERE observed_at < ?", (cutoff,))
            self._conn.commit()

    def insert_feedback(self, event: FeedbackEvent) -> None:
        created_at = event.created_at.strftime('%Y-%m-%dT%H:%M:%S.%f')
        with self._lock:
            self._conn.execute("""
                INSERT INTO feedback_log (ip, is_false_positive, context, created_at)
                VALUES (?, ?, ?, ?)
            """, (event.ip, 1 if event.is_false_positive else 0, event.context, created_at))
            self._conn.commit()

    def get_feedback_for_ip(self, ip: str) -> list[FeedbackEvent]:
        with self._lock:
            cursor = self._conn.execute("""
                SELECT ip, is_false_positive, context, created_at
                FROM feedback_log
                WHERE ip = ?
            """, (ip,))
            rows = cursor.fetchall()
            
        return [
            FeedbackEvent(
                ip=row[0],
                is_false_positive=bool(row[1]),
                context=row[2],
                created_at=datetime.fromisoformat(row[3])
            ) for row in rows
        ]

    def insert_probe_event(self, event: ProbeEvent) -> None:
        window_start = event.window_start.strftime('%Y-%m-%dT%H:%M:%S.%f')
        window_end = event.window_end.strftime('%Y-%m-%dT%H:%M:%S.%f')
        flagged_at = event.flagged_at.strftime('%Y-%m-%dT%H:%M:%S.%f')
        with self._lock:
            self._conn.execute("""
                INSERT INTO probe_events (ip, distinct_paths, window_start, window_end, flagged_at)
                VALUES (?, ?, ?, ?, ?)
            """, (event.ip, event.distinct_paths, window_start, window_end, flagged_at))
            self._conn.commit()

    def get_recent_probes(self, limit: int) -> list[ProbeEvent]:
        with self._lock:
            cursor = self._conn.execute("""
                SELECT ip, distinct_paths, window_start, window_end, flagged_at
                FROM probe_events
                ORDER BY flagged_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            
        return [
            ProbeEvent(
                ip=row[0],
                distinct_paths=row[1],
                window_start=datetime.fromisoformat(row[2]),
                window_end=datetime.fromisoformat(row[3]),
                flagged_at=datetime.fromisoformat(row[4])
            ) for row in rows
        ]

    def get_stats(self) -> DaemonStats:
        with self._lock:
            cursor = self._conn.execute("SELECT key, value FROM daemon_stats")
            rows = cursor.fetchall()
            
        data = {row[0]: row[1] for row in rows}
        return DaemonStats(
            total_parsed=int(data.get("total_parsed", 0)),
            heuristic_flagged=int(data.get("heuristic_flagged", 0)),
            ml_escalated=int(data.get("ml_escalated", 0)),
            agent_invoked=int(data.get("agent_invoked", 0)),
            blocked=int(data.get("blocked", 0)),
            allowed=int(data.get("allowed", 0)),
            errors=int(data.get("errors", 0)),
            started_at=datetime.fromisoformat(data["started_at"]) if "started_at" in data else datetime.utcnow()
        )

    def update_stats(self, **kwargs) -> None:
        with self._lock:
            for key, value in kwargs.items():
                if isinstance(value, datetime):
                    value = value.strftime('%Y-%m-%dT%H:%M:%S.%f')
                else:
                    value = str(value)
                self._conn.execute("""
                    INSERT OR REPLACE INTO daemon_stats (key, value)
                    VALUES (?, ?)
                """, (key, value))
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
