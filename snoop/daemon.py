from __future__ import annotations
import asyncio
import json
import logging
import logging.handlers
import os
import signal
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from snoop.models import *
from snoop.config import Config, ConfigLoader, ConfigWatcher, load_config
from snoop.store.sqlite_store import SQLiteStore
from snoop.fw.firewall_controller import FirewallController
from snoop.fw.cooldown_scheduler import CooldownScheduler
from snoop.pipeline.log_tailer import LogTailer
from snoop.pipeline.heuristic_filter import HeuristicFilter
from snoop.pipeline.anomaly_detector import AnomalyDetector
from snoop.pipeline.probe_detector import ProbeDetector
from snoop.pipeline.agent import Agent
from snoop.dashboard.server import DashboardServer
from snoop.llm_client import LLMClient

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "component": record.name,
            "event": record.getMessage()
        }
        if record.exc_info:
            log_entry["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

class Daemon:
    def __init__(self, config: Config):
        self.config = config
        self.raw_queue = asyncio.Queue(maxsize=config.queue_maxsize)
        self.heuristic_queue = asyncio.Queue(maxsize=config.queue_maxsize)
        self.anomaly_queue = asyncio.Queue(maxsize=config.queue_maxsize)
        self.agent_queue = asyncio.Queue(maxsize=config.queue_maxsize)
        
        self._stop_event = asyncio.Event()
        self._llm_loaded = False
        
        self.store = SQLiteStore(config.db_path)
        self.fw = FirewallController(config, self.store)
        self.cooldown_scheduler = CooldownScheduler(config, self.store, self.fw)
        self.log_tailer = LogTailer(config, self.raw_queue, self.store)
        self.probe_detector = ProbeDetector(config, self.store, self.heuristic_queue, self.agent_queue)
        self.heuristic_filter = HeuristicFilter(config, self.anomaly_queue)
        # NOTE: heuristic_filter.process() receives from heuristic_queue and forwards hits to anomaly_queue
        self.anomaly_detector = AnomalyDetector(config, self.agent_queue, self.store)
        
        self.llm_client = LLMClient(config)
        self.agent = Agent(config, self.store, self.fw, self.llm_client)

    def _setup_logging(self):
        root_logger = logging.getLogger()
        root_logger.setLevel(self.config.log_level)
        
        formatter = JsonFormatter()
        
        if self.config.snoop_log_file:
            log_path = Path(self.config.snoop_log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                self.config.snoop_log_file,
                maxBytes=10*1024*1024,
                backupCount=5
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        # Stream handler for daemon stdout (might fail if detached on Windows)
        if sys.stdout and not sys.stdout.closed:
            try:
                stream_handler = logging.StreamHandler(sys.stdout)
                stream_handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
                root_logger.addHandler(stream_handler)
            except Exception:
                pass

    def _write_pid(self) -> None:
        if self.config.pid_file_path:
            pid_path = Path(self.config.pid_file_path)
            pid_path.parent.mkdir(parents=True, exist_ok=True)
            pid_path.write_text(str(os.getpid()))

    def _remove_pid(self) -> None:
        if self.config.pid_file_path:
            pid_path = Path(self.config.pid_file_path)
            if pid_path.exists():
                try:
                    pid_path.unlink()
                except OSError:
                    pass

    def _check_already_running(self) -> bool:
        if not self.config.pid_file_path:
            return False
            
        pid_path = Path(self.config.pid_file_path)
        if not pid_path.exists():
            return False
            
        try:
            pid = int(pid_path.read_text().strip())
        except ValueError:
            return False
            
        if os.name == 'nt':
            try:
                res = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, shell=False, text=True)
                return str(pid) in res.stdout
            except Exception:
                return False
        else:
            try:
                os.kill(pid, 0)
                return True
            except OSError:
                return False

    async def _start_llm_background(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.llm_client.load)
        self._llm_loaded = True
        logging.info("LLM model loaded successfully")

    async def _agent_consumer(self) -> None:
        while not self._stop_event.is_set():
            try:
                entry = await asyncio.wait_for(self.agent_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
                
            try:
                result = await self.agent.run(entry)
                if result and result.action == Action.BLOCK:
                    self.store.update_stats(blocked=self.store.get_stats().blocked + 1)
                elif result and result.action == Action.ALLOW:
                    self.store.update_stats(allowed=self.store.get_stats().allowed + 1)
                stats = self.store.get_stats()
                self.store.update_stats(agent_invoked=stats.agent_invoked + 1)
            except Exception as e:
                logging.error(f"Error in agent_consumer: {e}", exc_info=True)
            finally:
                self.agent_queue.task_done()

    def _request_stop(self) -> None:
        logging.info("Shutdown requested")
        self._stop_event.set()

    async def start(self) -> None:
        self._setup_logging()
        self._write_pid()
        
        logging.info("Snoop IPS Daemon starting", extra={
            "log_level": self.config.log_level,
            "fw_backend": self.config.firewall_backend,
            "llm_enabled": self.config.llm_enabled
        })
        
        self.store.initialize()
        self.fw.restore_bans()
        
        tasks = []
        if self.config.llm_enabled:
            tasks.append(asyncio.create_task(self._start_llm_background()))
            
        tasks.extend([
            asyncio.create_task(self.log_tailer.start()),
            asyncio.create_task(self.probe_detector.process(self.raw_queue)),
            asyncio.create_task(self.heuristic_filter.process(self.heuristic_queue)),
            asyncio.create_task(self.anomaly_detector.process(self.anomaly_queue)),
            asyncio.create_task(self._agent_consumer()),
            asyncio.create_task(self.cooldown_scheduler.run())
        ])
        
        if getattr(self.config, 'dashboard_enabled', False):
            self.dashboard = DashboardServer(self.config, self.store, self.fw)
            tasks.append(asyncio.create_task(self.dashboard.start()))
            pass

        loop = asyncio.get_running_loop()
        if os.name == 'nt':
            signal.signal(signal.SIGINT, lambda *_: self._request_stop())
            signal.signal(signal.SIGTERM, lambda *_: self._request_stop())
            try:
                signal.signal(signal.SIGBREAK, lambda *_: self._request_stop())
            except AttributeError:
                pass
        else:
            loop.add_signal_handler(signal.SIGTERM, self._request_stop)
            loop.add_signal_handler(signal.SIGINT, self._request_stop)
            
        await self._stop_event.wait()
        await self.graceful_shutdown(tasks)

    async def graceful_shutdown(self, tasks: list[asyncio.Task]) -> None:
        logging.info("Shutdown initiated")
        
        try:
            await asyncio.wait_for(self.agent_queue.join(), timeout=10.0)
        except asyncio.TimeoutError:
            logging.warning("Timeout waiting for agent_queue to drain")
            
        for task in tasks:
            if not task.done():
                task.cancel()
                
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self._remove_pid()
        logging.info("Shutdown complete")

    def reload_config(self, new_config: Config) -> None:
        self.config.heuristic_patterns.clear()
        self.config.heuristic_patterns.extend(new_config.heuristic_patterns)
        self.config.anomaly_threshold = new_config.anomaly_threshold
        self.config.whitelist.clear()
        self.config.whitelist.extend(new_config.whitelist)
        logging.info("Config reloaded")

def run(config_path: str) -> None:
    try:
        config = load_config(config_path)
        daemon = Daemon(config)
        asyncio.run(daemon.start())
    except Exception as exc:
        import traceback
        fatal_log = Path(config_path).parent / "snoop-fatal.log"
        try:
            fatal_log = fatal_log.resolve()
        except Exception:
            fatal_log = Path("snoop-fatal.log")
        with open(fatal_log, "a") as fh:
            from datetime import datetime
            fh.write(f"\n{'='*60}\n")
            fh.write(f"FATAL CRASH at {datetime.utcnow().isoformat()}\n")
            fh.write(f"Config: {config_path}\n")
            fh.write(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Snoop IPS Daemon")
    parser.add_argument("--config", default=os.environ.get("SNOOP_CONFIG", "config.yaml"))
    args = parser.parse_args()
    run(args.config)
