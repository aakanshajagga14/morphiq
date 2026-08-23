import asyncio
import logging
from typing import List

from morphiq.config import Config
from morphiq.models import FilterResult, LogEntry, PatternRule
from morphiq.store.sqlite_store import SQLiteStore


class HeuristicFilter:
    def __init__(
        self,
        config: Config,
        anomaly_queue: asyncio.Queue,
        store: SQLiteStore,
    ):
        self.config = config
        self.anomaly_queue = anomaly_queue
        self.store = store
        self._patterns: List[PatternRule] = config.heuristic_patterns
        self._stop_event = asyncio.Event()

    def reload_patterns(self, patterns: list[PatternRule]) -> None:
        self._patterns = patterns

    def evaluate(self, entry: LogEntry) -> FilterResult:
        for pattern in self._patterns:
            field_value = ""
            if pattern.field == "path":
                field_value = entry.path
            elif pattern.field == "user_agent":
                field_value = entry.user_agent
            elif pattern.field == "method":
                field_value = entry.method
            elif pattern.field == "query_string":
                field_value = entry.query_string
            elif pattern.field == "raw":
                field_value = entry.raw_line
                
            if field_value and pattern.pattern.search(field_value):
                logging.debug(f"Heuristic match: {pattern.name} on field {pattern.field}")
                return FilterResult.SUSPICIOUS
                
        return FilterResult.BENIGN

    async def process(self, input_queue: asyncio.Queue) -> None:
        while not self._stop_event.is_set():
            entry = None
            try:
                entry = await asyncio.wait_for(input_queue.get(), timeout=1.0)
                
                result = self.evaluate(entry)
                if result == FilterResult.SUSPICIOUS:
                    self.store.increment_stat("heuristic_flagged")
                    await self.anomaly_queue.put(entry)
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logging.error(f"Error in heuristic filter: {e}")
                self.store.increment_stat("errors")
            finally:
                if entry is not None:
                    input_queue.task_done()

    async def stop(self) -> None:
        self._stop_event.set()
