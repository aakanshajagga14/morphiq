import asyncio
import logging
from typing import List
from snoop.models import LogEntry, PatternRule, FilterResult
from snoop.config import Config

class HeuristicFilter:
    def __init__(self, config: Config, anomaly_queue: asyncio.Queue):
        self.config = config
        self.anomaly_queue = anomaly_queue
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
            try:
                entry = await asyncio.wait_for(input_queue.get(), timeout=1.0)
                
                result = self.evaluate(entry)
                if result == FilterResult.SUSPICIOUS:
                    await self.anomaly_queue.put(entry)
                    
                input_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logging.error(f"Error in heuristic filter: {e}")

    async def stop(self) -> None:
        self._stop_event.set()
