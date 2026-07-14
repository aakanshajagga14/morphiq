import asyncio
import logging
import math
import time
from datetime import datetime
from typing import Optional
import joblib
from sklearn.ensemble import IsolationForest
from snoop.models import LogEntry, FeatureVector
from snoop.config import Config
from snoop.store.sqlite_store import SQLiteStore

class AnomalyDetector:
    def __init__(self, config: Config, agent_queue: asyncio.Queue, store: SQLiteStore):
        self.config = config
        self.agent_queue = agent_queue
        self.store = store
        self._model: Optional[IsolationForest] = None
        self._heuristic_only_mode: bool = True
        self._stop_event = asyncio.Event()
        
        self._tokens = float(config.max_escalation_rate)
        self._last_refill = time.monotonic()
        
        self._try_load_model()

    def _encode_method(self, method: str) -> int:
        method = method.upper()
        mapping = {
            "GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
            "HEAD": 4, "OPTIONS": 5, "PATCH": 6
        }
        return mapping.get(method, 7)

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        entropy = 0.0
        length = len(s)
        counts = {}
        for char in s:
            counts[char] = counts.get(char, 0) + 1
            
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def extract_features(self, entry: LogEntry) -> FeatureVector:
        return FeatureVector(
            path_length=len(entry.path),
            query_entropy=self._shannon_entropy(entry.query_string),
            method_encoded=self._encode_method(entry.method),
            status_code=entry.status_code,
            user_agent_length=len(entry.user_agent),
            hour_of_day=entry.timestamp.hour,
            request_frequency=self.store.get_request_frequency(entry.effective_ip, 60)
        )

    def score(self, fv: FeatureVector) -> float:
        if not self._model:
            return 0.0
            
        vec = [
            fv.path_length,
            fv.query_entropy,
            fv.method_encoded,
            fv.status_code,
            fv.user_agent_length,
            fv.hour_of_day,
            fv.request_frequency
        ]
        
        score_val = self._model.score_samples([vec])[0]
        return float(-score_val)

    def should_escalate(self, score: float) -> bool:
        return score > self.config.anomaly_threshold

    def _consume_token(self) -> bool:
        now = time.monotonic()
        elapsed = now - self._last_refill
        
        refill_amount = elapsed * (self.config.max_escalation_rate / 60.0)
        self._tokens = min(float(self.config.max_escalation_rate), self._tokens + refill_amount)
        self._last_refill = now
        
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def _try_load_model(self) -> None:
        try:
            if self.config.isolation_forest_model_path:
                self._model = joblib.load(self.config.isolation_forest_model_path)
                self._heuristic_only_mode = False
                logging.info(f"Loaded isolation forest model from {self.config.isolation_forest_model_path}")
                return
        except Exception as e:
            logging.debug(f"Failed to load primary model: {e}")
            
        try:
            if self.config.base_model_path:
                self._model = joblib.load(self.config.base_model_path)
                self._heuristic_only_mode = False
                logging.info(f"Loaded base model from {self.config.base_model_path}")
                return
        except Exception as e:
            logging.debug(f"Failed to load base model: {e}")
            
        self._heuristic_only_mode = True

    async def retrain(self) -> None:
        with self.store._lock:
            cursor = self.store._conn.execute("""
                SELECT source_ip, effective_ip, method, path, query_string, status_code, user_agent, bytes_sent, raw_line, observed_at
                FROM traffic_history
            """)
            rows = cursor.fetchall()
            
        if len(rows) < self.config.min_training_samples:
            logging.info("Not enough samples to retrain model.")
            return
            
        vectors = []
        for row in rows:
            entry = LogEntry(
                source_ip=row[0],
                effective_ip=row[1],
                method=row[2],
                path=row[3],
                query_string=row[4],
                status_code=row[5],
                user_agent=row[6],
                bytes_sent=row[7],
                raw_line=row[8],
                timestamp=datetime.fromisoformat(row[9])
            )
            fv = self.extract_features(entry)
            vectors.append([
                fv.path_length,
                fv.query_entropy,
                fv.method_encoded,
                fv.status_code,
                fv.user_agent_length,
                fv.hour_of_day,
                fv.request_frequency
            ])
            
        if not vectors:
            return
            
        model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        model.fit(vectors)
        
        self._model = model
        self._heuristic_only_mode = False
        
        if self.config.isolation_forest_model_path:
            joblib.dump(model, self.config.isolation_forest_model_path)
            logging.info(f"Retrained and saved model to {self.config.isolation_forest_model_path}")

    async def process(self, anomaly_queue: asyncio.Queue) -> None:
        while not self._stop_event.is_set():
            try:
                entry = await asyncio.wait_for(anomaly_queue.get(), timeout=1.0)
                
                if self._heuristic_only_mode:
                    if self._consume_token():
                        await self.agent_queue.put(entry)
                        logging.debug(f"Heuristic escalation (no ML): {entry.effective_ip}")
                else:
                    fv = self.extract_features(entry)
                    score_val = self.score(fv)
                    
                    logging.debug(f"Anomaly score for {entry.effective_ip}: {score_val}")
                    
                    if self.should_escalate(score_val):
                        if self._consume_token():
                            await self.agent_queue.put(entry)
                            logging.debug(f"ML escalation (score {score_val}): {entry.effective_ip}")
                        else:
                            logging.debug(f"Rate limited ML escalation for {entry.effective_ip}")
                            
                anomaly_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logging.error(f"Error in anomaly detector: {e}")

    async def stop(self) -> None:
        self._stop_event.set()
