from __future__ import annotations

import logging
import os
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from morphiq.models import PatternRule

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """
    Complete runtime configuration for the MorphIQ IPS daemon.

    All values originate from config.yaml (or environment overrides) and are
    validated before the daemon starts.  No numeric or string constants are
    ever hard-coded in the application code — everything is wired through
    this object.
    """

    # --- Log ingestion ---
    log_file_path: str
    log_format_preset: str          # "nginx_combined"|"apache_combined"|"iis_w3c"|"caddy_json"|"custom"
    log_format_regex: str           # used when log_format_preset == "custom"
    effective_ip_header: str        # "X-Forwarded-For"|"X-Real-IP"|"" (empty → use source_ip)

    # --- Firewall ---
    firewall_backend: str           # "windows"|"iptables"|"ufw"|"mock"
    whitelist: list[str]

    # --- ML pipeline ---
    anomaly_threshold: float
    max_escalation_rate: int
    min_training_samples: int
    base_model_path: str
    isolation_forest_model_path: str

    # --- LLM / agent ---
    llm_enabled: bool
    llm_base_url: str
    llm_model_path: str
    llm_timeout_s: float
    llm_max_tokens: int
    llm_n_ctx: int
    llm_n_threads: int
    max_traffic_history_context: int

    # --- Banning ---
    default_ban_duration_s: int

    # --- Storage ---
    db_path: str
    traffic_retention_s: int

    # --- Process management ---
    pid_file_path: str

    # --- Logging ---
    morphiq_log_file: str
    log_level: str

    # --- Internal queues / timing ---
    queue_maxsize: int
    config_reload_debounce_s: float
    poll_interval_s: int

    # --- Probe detection ---
    probe_window_s: int
    probe_threshold: int

    # --- Dashboard ---
    dashboard_enabled: bool
    dashboard_host: str
    dashboard_port: int

    # --- Heuristics ---
    heuristic_patterns: list[PatternRule]


# ---------------------------------------------------------------------------
# Validation error
# ---------------------------------------------------------------------------

class ConfigValidationError(Exception):
    """
    Raised when a config field contains an invalid type or value.

    Message format:  "config field '{field}': {problem}. Got: {got!r}"
    """

    @classmethod
    def for_field(
        cls,
        field_name: str,
        problem: str,
        got: object,
    ) -> "ConfigValidationError":
        return cls(
            f"config field '{field_name}': {problem}. Got: {got!r}"
        )


# ---------------------------------------------------------------------------
# ConfigLoader
# ---------------------------------------------------------------------------

_ALLOWED_LOG_PRESETS: frozenset[str] = frozenset(
    {"nginx_combined", "apache_combined", "iis_w3c", "caddy_json", "custom"}
)
_ALLOWED_FIREWALL_BACKENDS: frozenset[str] = frozenset(
    {"windows", "iptables", "ufw", "mock"}
)


class ConfigLoader:
    """
    Loads, merges, and validates configuration from a YAML file.

    Merge precedence (highest → lowest):
        1. YAML file values
        2. Built-in defaults (_DEFAULTS)

    The environment variable MORPHIQ_CONFIG may override the path given to
    load(), allowing container/CI deployments to inject a config path without
    touching the command line.
    """

    _DEFAULTS: dict[str, object] = {
        "log_file_path": "",          # required — no meaningful default
        "log_format_preset": "nginx_combined",
        "log_format_regex": "",
        "effective_ip_header": "X-Forwarded-For",
        "firewall_backend": "windows",
        "whitelist": [],
        "anomaly_threshold": 0.3,
        "max_escalation_rate": 10,
        "min_training_samples": 200,
        "base_model_path": "data/base_model.joblib",
        "isolation_forest_model_path": "data/if_model.joblib",
        "llm_enabled": True,
        "llm_base_url": "http://localhost:1234/v1",
        "llm_model_path": "models/model.gguf",
        "llm_timeout_s": 30.0,
        "llm_max_tokens": 256,
        "llm_n_ctx": 2048,
        "llm_n_threads": 4,
        "max_traffic_history_context": 20,
        "default_ban_duration_s": 3600,
        "db_path": "morphiq.db",
        "traffic_retention_s": 86400,
        "pid_file_path": "",
        "morphiq_log_file": "morphiq.log",
        "log_level": "INFO",
        "queue_maxsize": 1000,
        "config_reload_debounce_s": 5.0,
        "poll_interval_s": 60,
        "probe_window_s": 300,
        "probe_threshold": 15,
        "dashboard_enabled": False,
        "dashboard_host": "127.0.0.1",
        "dashboard_port": 7373,
        "heuristic_patterns": [],
    }

    # Integer fields (for type-coercion validation)
    _INT_FIELDS: frozenset[str] = frozenset({
        "max_escalation_rate",
        "min_training_samples",
        "llm_max_tokens",
        "llm_n_ctx",
        "llm_n_threads",
        "max_traffic_history_context",
        "default_ban_duration_s",
        "traffic_retention_s",
        "queue_maxsize",
        "poll_interval_s",
        "probe_window_s",
        "probe_threshold",
        "dashboard_port",
    })

    # Float fields
    _FLOAT_FIELDS: frozenset[str] = frozenset({
        "anomaly_threshold",
        "llm_timeout_s",
        "config_reload_debounce_s",
    })

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    @classmethod
    def load(cls, path: str) -> Config:
        """
        Read *path* (YAML), merge with defaults, validate, and return a
        fully-populated Config.

        If the MORPHIQ_CONFIG environment variable is set it takes precedence
        over the *path* argument.
        """
        resolved = os.environ.get("MORPHIQ_CONFIG", path)
        raw: dict[str, object] = dict(cls._DEFAULTS)  # start with defaults

        yaml_path = Path(resolved)
        if yaml_path.exists():
            with yaml_path.open("r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            if not isinstance(loaded, dict):
                raise ConfigValidationError(
                    f"config file '{resolved}' must contain a YAML mapping at the top level"
                )
            raw.update(loaded)
        else:
            logger.warning(
                "Config file '%s' not found — using built-in defaults only.", resolved
            )

        return cls.validate(raw)

    @classmethod
    def validate(cls, raw: dict[str, object]) -> Config:
        """
        Validate *raw* dict and return a Config instance.

        Raises ConfigValidationError on the first invalid field encountered.
        """
        # --- log_file_path: required ---
        lfp = raw.get("log_file_path", "")
        if not isinstance(lfp, str) or not lfp.strip():
            raise ConfigValidationError.for_field(
                "log_file_path",
                "must be a non-empty string pointing to the log file",
                lfp,
            )

        # --- log_format_preset ---
        preset = raw.get("log_format_preset", "nginx_combined")
        if preset not in _ALLOWED_LOG_PRESETS:
            raise ConfigValidationError.for_field(
                "log_format_preset",
                f"must be one of {sorted(_ALLOWED_LOG_PRESETS)}",
                preset,
            )

        # --- log_format_regex: required when preset == "custom" ---
        lfr = raw.get("log_format_regex", "")
        if preset == "custom" and (not isinstance(lfr, str) or not lfr.strip()):
            raise ConfigValidationError.for_field(
                "log_format_regex",
                "must be a non-empty regex string when log_format_preset is 'custom'",
                lfr,
            )

        # --- effective_ip_header ---
        eih = raw.get("effective_ip_header", "X-Forwarded-For")
        if not isinstance(eih, str):
            raise ConfigValidationError.for_field(
                "effective_ip_header",
                "must be a string (use empty string to disable)",
                eih,
            )

        # --- firewall_backend ---
        fb = raw.get("firewall_backend", "windows")
        if fb not in _ALLOWED_FIREWALL_BACKENDS:
            raise ConfigValidationError.for_field(
                "firewall_backend",
                f"must be one of {sorted(_ALLOWED_FIREWALL_BACKENDS)}",
                fb,
            )

        # --- whitelist ---
        wl = raw.get("whitelist", [])
        if not isinstance(wl, list) or not all(isinstance(x, str) for x in wl):
            raise ConfigValidationError.for_field(
                "whitelist", "must be a list of IP strings", wl
            )

        # --- anomaly_threshold ---
        at_val = raw.get("anomaly_threshold", 0.3)
        try:
            at_float = float(at_val)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raise ConfigValidationError.for_field(
                "anomaly_threshold", "must be a float", at_val
            )
        if not (0.0 <= at_float <= 1.0):
            raise ConfigValidationError.for_field(
                "anomaly_threshold", "must be between 0.0 and 1.0", at_float
            )

        # --- max_escalation_rate ---
        mer = raw.get("max_escalation_rate", 10)
        if not isinstance(mer, int) or mer <= 0:
            raise ConfigValidationError.for_field(
                "max_escalation_rate", "must be a positive integer", mer
            )

        # --- generic int fields ---
        validated_ints: dict[str, int] = {}
        for int_field in cls._INT_FIELDS - {"max_escalation_rate"}:
            val = raw.get(int_field, cls._DEFAULTS[int_field])
            if not isinstance(val, int):
                raise ConfigValidationError.for_field(
                    int_field, "must be an integer", val
                )
            validated_ints[int_field] = val

        # --- generic float fields ---
        validated_floats: dict[str, float] = {}
        for float_field in cls._FLOAT_FIELDS - {"anomaly_threshold"}:
            val = raw.get(float_field, cls._DEFAULTS[float_field])
            try:
                validated_floats[float_field] = float(val)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                raise ConfigValidationError.for_field(
                    float_field, "must be a float", val
                )

        # --- llm_enabled ---
        llm_enabled = raw.get("llm_enabled", True)
        if not isinstance(llm_enabled, bool):
            raise ConfigValidationError.for_field(
                "llm_enabled", "must be a boolean", llm_enabled
            )

        # --- dashboard_enabled ---
        dash_enabled = raw.get("dashboard_enabled", False)
        if not isinstance(dash_enabled, bool):
            raise ConfigValidationError.for_field(
                "dashboard_enabled", "must be a boolean", dash_enabled
            )

        # --- string fields with simple presence checks ---
        simple_str_fields = [
            "log_format_regex",
            "llm_base_url",
            "llm_model_path",
            "base_model_path",
            "isolation_forest_model_path",
            "db_path",
            "morphiq_log_file",
            "log_level",
            "dashboard_host",
        ]
        validated_strings: dict[str, str] = {}
        for sf in simple_str_fields:
            val = raw.get(sf, cls._DEFAULTS[sf])
            if not isinstance(val, str):
                raise ConfigValidationError.for_field(sf, "must be a string", val)
            validated_strings[sf] = val

        # --- pid_file_path auto-resolution ---
        pid_raw = raw.get("pid_file_path", "")
        if not isinstance(pid_raw, str):
            raise ConfigValidationError.for_field(
                "pid_file_path", "must be a string", pid_raw
            )
        if not pid_raw.strip():
            if sys.platform == "win32":
                base = os.environ.get("LOCALAPPDATA", "~")
                pid_path = str(Path(base).expanduser() / "MorphIQ" / "morphiq.pid")
            else:
                pid_path = str(Path("/tmp/morphiq.pid"))
        else:
            pid_path = pid_raw

        # --- heuristic_patterns ---
        patterns_raw = raw.get("heuristic_patterns", [])
        if not isinstance(patterns_raw, list):
            raise ConfigValidationError.for_field(
                "heuristic_patterns", "must be a list of pattern dicts", patterns_raw
            )
        compiled_patterns: list[PatternRule] = []
        for entry in patterns_raw:
            if not isinstance(entry, dict):
                logger.warning("heuristic_patterns: skipping non-dict entry: %r", entry)
                continue
            name = entry.get("name", "")
            field_name = entry.get("field", "")
            pattern_str = entry.get("pattern", "")
            description = entry.get("description", "")
            if not name or not field_name or not pattern_str:
                logger.warning(
                    "heuristic_patterns: entry missing name/field/pattern — skipping: %r",
                    entry,
                )
                continue
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE)
            except re.error as exc:
                logger.warning(
                    "heuristic_patterns: invalid regex in pattern '%s' (%s) — skipping",
                    name,
                    exc,
                )
                continue
            compiled_patterns.append(
                PatternRule(
                    name=name,
                    pattern=compiled,
                    field=field_name,
                    description=description,
                )
            )

        return Config(
            log_file_path=str(lfp).strip(),
            log_format_preset=str(preset),
            log_format_regex=validated_strings["log_format_regex"],
            effective_ip_header=str(eih),
            firewall_backend=str(fb),
            whitelist=list(wl),
            anomaly_threshold=at_float,
            max_escalation_rate=int(mer),
            min_training_samples=validated_ints["min_training_samples"],
            base_model_path=validated_strings["base_model_path"],
            isolation_forest_model_path=validated_strings["isolation_forest_model_path"],
            llm_enabled=llm_enabled,
            llm_base_url=validated_strings["llm_base_url"],
            llm_model_path=validated_strings["llm_model_path"],
            llm_timeout_s=validated_floats["llm_timeout_s"],
            llm_max_tokens=validated_ints["llm_max_tokens"],
            llm_n_ctx=validated_ints["llm_n_ctx"],
            llm_n_threads=validated_ints["llm_n_threads"],
            max_traffic_history_context=validated_ints["max_traffic_history_context"],
            default_ban_duration_s=validated_ints["default_ban_duration_s"],
            db_path=validated_strings["db_path"],
            traffic_retention_s=validated_ints["traffic_retention_s"],
            pid_file_path=pid_path,
            morphiq_log_file=validated_strings["morphiq_log_file"],
            log_level=validated_strings["log_level"],
            queue_maxsize=validated_ints["queue_maxsize"],
            config_reload_debounce_s=validated_floats["config_reload_debounce_s"],
            poll_interval_s=validated_ints["poll_interval_s"],
            probe_window_s=validated_ints["probe_window_s"],
            probe_threshold=validated_ints["probe_threshold"],
            dashboard_enabled=dash_enabled,
            dashboard_host=validated_strings["dashboard_host"],
            dashboard_port=validated_ints["dashboard_port"],
            heuristic_patterns=compiled_patterns,
        )


# ---------------------------------------------------------------------------
# ConfigWatcher
# ---------------------------------------------------------------------------

class _DebounceHandler(FileSystemEventHandler):
    """
    Watchdog event handler that fires a callback after a debounce period.

    Every filesystem modification event for the tracked filename resets the
    timer; the callback is only invoked once the file has been stable for
    *debounce_s* seconds.
    """

    def __init__(
        self,
        filename: str,
        debounce_s: float,
        callback: Callable[[], None],
    ) -> None:
        super().__init__()
        self._filename = filename
        self._debounce_s = debounce_s
        self._callback = callback
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    def on_modified(self, event: object) -> None:  # type: ignore[override]
        src = getattr(event, "src_path", "")
        if Path(src).name != self._filename:
            return
        self._reset_timer()

    def on_created(self, event: object) -> None:  # type: ignore[override]
        # Handle atomic-write patterns (write to tmp, rename → create)
        src = getattr(event, "src_path", "")
        if Path(src).name != self._filename:
            return
        self._reset_timer()

    def _reset_timer(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._debounce_s, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def _fire(self) -> None:
        logger.info("ConfigWatcher: config file change detected — reloading")
        try:
            self._callback()
        except Exception:
            logger.exception("ConfigWatcher: callback raised an exception")


class ConfigWatcher:
    """
    Watches the config file's parent directory for modifications and calls
    *callback* (after a debounce period) whenever the file changes.

    Usage::

        watcher = ConfigWatcher(
            config_path="/etc/morphiq/config.yaml",
            debounce_s=cfg.config_reload_debounce_s,
            callback=lambda: reload_config(),
        )
        watcher.start()
        # … daemon runs …
        watcher.stop()
    """

    def __init__(
        self,
        config_path: str,
        debounce_s: float,
        callback: Callable[[], None],
    ) -> None:
        self._config_path = Path(config_path).resolve()
        self._debounce_s = debounce_s
        self._callback = callback
        self._observer: Optional[Observer] = None

    def start(self) -> None:
        """Start the filesystem watcher thread."""
        handler = _DebounceHandler(
            filename=self._config_path.name,
            debounce_s=self._debounce_s,
            callback=self._callback,
        )
        self._observer = Observer()
        self._observer.schedule(
            handler,
            path=str(self._config_path.parent),
            recursive=False,
        )
        self._observer.start()
        logger.info(
            "ConfigWatcher: watching '%s' (debounce=%.1fs)",
            self._config_path,
            self._debounce_s,
        )

    def stop(self) -> None:
        """Stop the filesystem watcher thread cleanly."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None
            logger.info("ConfigWatcher: stopped")


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------

def load_config(path: Optional[str] = None) -> Config:
    """
    Load and validate configuration.

    Resolution order for the config file path:
        1. MORPHIQ_CONFIG environment variable
        2. *path* argument
        3. Falls back to "config.yaml" in the current working directory

    This is the canonical way for application code to obtain a Config object.
    """
    resolved = os.environ.get("MORPHIQ_CONFIG") or path or "config.yaml"
    return ConfigLoader.load(resolved)
