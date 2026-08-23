import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque, Tuple

from morphiq.config import Config
from morphiq.models import LogEntry, ProbeEvent
from morphiq.store.sqlite_store import SQLiteStore


class ProbeDetector:
    def __init__(self, config: Config, store: SQLiteStore, heuristic_queue: asyncio.Queue, agent_queue: asyncio.Queue):
        self.config = config
        self.store = store
        self.heuristic_queue = heuristic_queue
        self.agent_queue = agent_queue
        self._windows: dict[str, Deque[Tuple[datetime, str]]] = defaultdict(deque)
        self._stop_event = asyncio.Event()

    def _prune_window(self, ip: str, now: datetime) -> None:
        window = self._windows[ip]
        while window:
            oldest_time, _ = window[0]
            if (now - oldest_time).total_seconds() > self.config.probe_window_s:
                window.popleft()
            else:
                break

    def check_probe(self, entry: LogEntry) -> bool:
        ip = entry.effective_ip
        now = entry.timestamp
        self._prune_window(ip, now)
        
        self._windows[ip].append((now, entry.path))
        
        distinct_paths = len(set(path for _, path in self._windows[ip]))
        return distinct_paths > self.config.probe_threshold

    def is_active_probe(self, ip: str) -> bool:
        now = datetime.now(timezone.utc)
        self._prune_window(ip, now)
        
        distinct_paths = len(set(path for _, path in self._windows[ip]))
        return distinct_paths > self.config.probe_threshold

    async def process(self, input_queue: asyncio.Queue) -> None:
        while not self._stop_event.is_set():
            entry = None
            try:
                entry = await asyncio.wait_for(input_queue.get(), timeout=1.0)
                
                is_probe = self.check_probe(entry)
                if is_probe:
                    logging.warning(f"Probe detected from {entry.effective_ip}")
                    
                    window = self._windows[entry.effective_ip]
                    window_start = window[0][0] if window else entry.timestamp
                    window_end = entry.timestamp
                    distinct_paths = len(set(path for _, path in window))
                    
                    probe_event = ProbeEvent(
                        ip=entry.effective_ip,
                        distinct_paths=distinct_paths,
                        window_start=window_start,
                        window_end=window_end,
                        flagged_at=datetime.now(timezone.utc)
                    )
                    self.store.insert_probe_event(probe_event)
                    await self.agent_queue.put(entry)
                else:
                    await self.heuristic_queue.put(entry)
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logging.error(f"Error in probe detector: {e}")
                self.store.increment_stat("errors")
            finally:
                if entry is not None:
                    input_queue.task_done()

    async def stop(self) -> None:
        self._stop_event.set()
