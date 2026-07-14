# Implementation Plan: snoop-ips-daemon

## Overview

Implement Snoop as an async Python daemon with a three-stage IPS pipeline (heuristic → anomaly → LangGraph agent), a local SQLite store, iptables/ufw firewall control, and a `snoop` CLI. Each task builds incrementally toward a fully wired daemon process.

## Tasks

- [ ] 1. Project structure, dependencies, and core data models
  - Create package layout: `snoop/`, `snoop/cli/`, `snoop/pipeline/`, `snoop/store/`, `snoop/fw/`, tests directory
  - Define `LogEntry`, `PatternRule`, `FilterResult`, `FeatureVector`, `BanRecord`, `AuditEvent`, `TrafficRecord`, `LLMAssessment`, `AgentDecision`, `Action` dataclasses and enums in `snoop/models.py`
  - Add `pyproject.toml` / `setup.cfg` with pinned dependencies: `aiofiles`, `watchdog`, `scikit-learn`, `joblib`, `langgraph`, `llama-cpp-python`, `PyYAML`, `typer`, `pytest`, `pytest-asyncio`, `hypothesis`, `pytest-mock`
  - _Requirements: 1.5, 3.2, 4.3, 5.5_

- [ ] 2. Config loading and validation
  - [ ] 2.1 Implement `Config` dataclass and `ConfigLoader` in `snoop/config.py`
    - Parse `config.yaml` with PyYAML; validate all required fields with type coercion
    - Raise `ConfigValidationError` with descriptive message on missing/invalid field; exit non-zero on fatal error
    - _Requirements: 11.1, 11.2, 11.3, 11.5_
  - [ ]* 2.2 Write property test for Config round-trip (Property 19)
    - **Property 19: Config round-trip serialization**
    - **Validates: Requirements 11.6**
  - [ ]* 2.3 Write unit tests for `ConfigLoader`
    - Test validation error messages for each required field; test missing config exits non-zero
    - _Requirements: 11.3, 11.5_

- [ ] 3. SQLite store
  - [ ] 3.1 Implement `SQLiteStore` in `snoop/store/sqlite_store.py`
    - Initialize schema (all three tables + indexes) on first connection; enable WAL mode
    - Implement `insert_traffic`, `get_traffic_history`, `insert_ban`, `get_active_bans`, `delete_ban`, `append_audit`, `get_recent_audit`, `prune_traffic_history`
    - Enforce append-only `threat_audit_log` (no update/delete methods exposed)
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_
  - [ ]* 3.2 Write property test for traffic retention (Property 16)
    - **Property 16: Traffic history retention is enforced after every write**
    - **Validates: Requirements 9.2**
  - [ ]* 3.3 Write unit tests for `SQLiteStore`
    - Test WAL mode; test append-only audit log (reject update/delete); test schema auto-creation; test `prune_traffic_history`
    - _Requirements: 9.2, 9.3, 9.4, 9.5_

- [ ] 4. Log tailing and parsing
  - [ ] 4.1 Implement `LogTailer` in `snoop/pipeline/log_tailer.py`
    - Use `aiofiles` for non-blocking reads; detect log rotation via inode check; retry every 5 s on unavailable file with journal warning
    - Parse lines using format rules from Config, extracting source IP, method, path, status code, User-Agent
    - Discard unparseable lines and increment `parse_error_counter`; emit `LogEntry` onto `heuristic_queue` within 500 ms
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_
  - [ ]* 4.2 Write property test for log parse round-trip (Property 1)
    - **Property 1: Log line parse round-trip**
    - **Validates: Requirements 1.5**
  - [ ]* 4.3 Write property test for malformed lines (Property 2)
    - **Property 2: Malformed lines increment counter and are dropped**
    - **Validates: Requirements 1.6**
  - [ ]* 4.4 Write unit tests for `LogTailer`
    - Test file rotation detection, parse-error counter, field extraction for known log formats
    - _Requirements: 1.2, 1.4, 1.5, 1.6_

- [ ] 5. Heuristic filter
  - [ ] 5.1 Implement `HeuristicFilter` in `snoop/pipeline/heuristic_filter.py`
    - Evaluate all `PatternRule` patterns against entry fields; return `SUSPICIOUS` iff any match, else `BENIGN`
    - Implement `reload_patterns()` with atomic swap (single assignment); target ≤ 10 ms per entry
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [ ]* 5.2 Write property test for heuristic filter correctness (Property 3)
    - **Property 3: Heuristic filter result is exactly SUSPICIOUS iff at least one pattern matches**
    - **Validates: Requirements 2.2, 2.3**
  - [ ]* 5.3 Write unit tests for `HeuristicFilter`
    - Test pattern matching with known-bad and known-good inputs; test `reload_patterns()` atomicity
    - _Requirements: 2.1, 2.4, 2.5_

- [ ] 6. Anomaly detector
  - [ ] 6.1 Implement `AnomalyDetector` in `snoop/pipeline/anomaly_detector.py`
    - Extract `FeatureVector` (path length, query entropy, method encoding, status code, user-agent length)
    - Score with `IsolationForest` from scikit-learn; serialize/load model with `joblib`
    - Implement token-bucket rate limiter capped at `max_escalation_rate` per minute
    - On startup with no model: train from `traffic_history` or fall back to heuristic-only mode if insufficient data
    - Implement `retrain()` that trains in-memory and atomically replaces active model
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_
  - [ ]* 6.2 Write property test for feature vector validity (Property 4)
    - **Property 4: Feature extraction produces valid numeric vectors**
    - **Validates: Requirements 3.2**
  - [ ]* 6.3 Write property test for escalation threshold boundary (Property 5)
    - **Property 5: Escalation threshold is a sharp boundary**
    - **Validates: Requirements 3.3, 3.4**
  - [ ]* 6.4 Write property test for rate limiter ceiling (Property 6)
    - **Property 6: Rate limiter never exceeds configured maximum**
    - **Validates: Requirements 3.5**
  - [ ]* 6.5 Write unit tests for `AnomalyDetector`
    - Test feature extraction for edge inputs; test fallback to heuristic-only mode; test `retrain()` atomicity
    - _Requirements: 3.2, 3.5, 3.7_

- [ ] 7. Checkpoint — Ensure all tests pass so far
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. LLM client
  - [ ] 8.1 Implement `LLMClient` in `snoop/llm_client.py`
    - Load Gemma 2B via `llama-cpp-python` from model path in Config; block Agent until ready
    - Run inference in `ThreadPoolExecutor`; enforce 30 s timeout via `asyncio.wait_for`
    - On model load failure: log fatal error, set `agent_enabled = False`; daemon continues in heuristic+anomaly mode
    - _Requirements: 5.1, 5.2, 5.3_
  - [ ]* 8.2 Write property test for prompt completeness (Property 9)
    - **Property 9: Prompt always contains required context**
    - **Validates: Requirements 5.4**
  - [ ]* 8.3 Write property test for LLM assessment schema (Property 10)
    - **Property 10: Valid LLM assessments always contain required fields**
    - **Validates: Requirements 5.5**
  - [ ]* 8.4 Write unit tests for `LLMClient`
    - Test model load failure path; test 30 s timeout enforcement (mocked inference)
    - _Requirements: 5.1, 5.2, 5.3_

- [ ] 9. LangGraph Agent
  - [ ] 9.1 Implement `Agent` in `snoop/pipeline/agent.py` with LangGraph state machine
    - Wire `investigate_node → reason_node → act_node` using `StateGraph(AgentState)`
    - `investigate_node`: query `SQLiteStore` for source IP traffic history
    - `reason_node`: build structured prompt, call `LLMClient.infer()`, parse JSON response; on timeout or parse error → `assessment = None`
    - `act_node`: if `assessment is None` or unparseable → `Action.ALLOW`; otherwise delegate to `FirewallController`
    - Write full trace + assessment + action to `threat_audit_log` on every invocation
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_
  - [ ]* 9.2 Write property test for act node always valid (Property 7)
    - **Property 7: Act node always produces a valid action; defaults to ALLOW on bad input**
    - **Validates: Requirements 4.4, 4.5**
  - [ ]* 9.3 Write property test for audit log completeness (Property 8)
    - **Property 8: Every agent invocation appends exactly one audit record**
    - **Validates: Requirements 4.7**
  - [ ]* 9.4 Write unit tests for `Agent`
    - Test LangGraph graph structure (node order); test timeout fallback; test malformed LLM output fallback
    - _Requirements: 4.1, 4.5, 4.6, 4.7_

- [ ] 10. Firewall controller
  - [ ] 10.1 Implement `FirewallController` in `snoop/fw/firewall_controller.py`
    - Validate every IP with `ipaddress.ip_address()` before any subprocess call; reject and log invalid input
    - Check whitelist (always includes `127.0.0.1` and `::1`) synchronously before any block; log whitelist-protection event on match
    - Execute iptables or ufw commands as argument lists (`shell=False`); support both backends via Config
    - On successful block: write record to `active_bans` with `reason`, `banned_at`, `expires_at`
    - Implement `restore_bans()` to re-apply all unexpired `active_bans` rules on daemon start
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 7.1, 7.2, 7.3, 7.4, 7.6_
  - [ ]* 10.2 Write property test for IP validation gatekeeper (Property 11)
    - **Property 11: IP validation is the gatekeeper — no invalid IP reaches the firewall**
    - **Validates: Requirements 6.2, 6.3**
  - [ ]* 10.3 Write property test for block persistence (Property 12)
    - **Property 12: Successful block is fully persisted with all required fields**
    - **Validates: Requirements 6.4**
  - [ ]* 10.4 Write property test for whitelist protection (Property 13)
    - **Property 13: Whitelisted IPs are never blocked**
    - **Validates: Requirements 7.3, 7.4**
  - [ ]* 10.5 Write unit tests for `FirewallController`
    - Test iptables vs. ufw backend selection; test whitelist CIDR matching; test `restore_bans()` on startup
    - _Requirements: 6.2, 6.5, 6.6, 7.3, 7.4_

- [ ] 11. Cooldown scheduler
  - [ ] 11.1 Implement `CooldownScheduler` in `snoop/fw/cooldown_scheduler.py`
    - Poll `active_bans` every `poll_interval_s` seconds for expired bans (`expires_at < now`)
    - On expired ban: call `FirewallController.unblock()`; on success delete row and append unban event to `threat_audit_log`
    - On unblock failure: retain row, log failure, retry next cycle
    - Apply `config.default_ban_duration_s` when `AgentDecision.assessment.ban_duration_seconds` is `None`
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_
  - [ ]* 11.2 Write property test for cooldown cleanup (Property 14)
    - **Property 14: Expired bans are fully cleaned up on each polling cycle**
    - **Validates: Requirements 8.2, 8.3**
  - [ ]* 11.3 Write property test for ban duration fallback (Property 15)
    - **Property 15: Ban duration falls back to configured default when not specified**
    - **Validates: Requirements 8.5**
  - [ ]* 11.4 Write unit tests for `CooldownScheduler`
    - Test retry on failed unblock; test no-op on empty `active_bans`
    - _Requirements: 8.1, 8.4_

- [ ] 12. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. CLI
  - [ ] 13.1 Implement `snoop` CLI in `snoop/cli/main.py` using `typer`
    - `snoop status`: daemon state (PID file + process liveness), active ban count, pipeline stage counters
    - `snoop audit [--limit N]`: return `min(N, M)` most recent `threat_audit_log` records ordered by `occurred_at` DESC
    - `snoop ban list`: display all `active_bans` records (IP, reason, expiry)
    - `snoop unban <ip>`: call `FirewallController.unblock()` + delete `active_bans` record; informative message + exit 0 if IP not banned
    - `snoop whitelist check <ip>`: call `FirewallController.is_whitelisted()`
    - If daemon offline: `status` shows "offline"; all other commands display message and exit non-zero
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_
  - [ ]* 13.2 Write property test for audit order and count (Property 17)
    - **Property 17: snoop audit --limit N returns correct count and order**
    - **Validates: Requirements 10.2**
  - [ ]* 13.3 Write property test for whitelist check consistency (Property 18)
    - **Property 18: Whitelist check is consistent with is_whitelisted()**
    - **Validates: Requirements 10.6**
  - [ ]* 13.4 Write unit tests for CLI
    - Test `snoop unban` for non-banned IP; test offline daemon message; test `snoop status` output format
    - _Requirements: 10.5, 10.7_

- [ ] 14. Config hot-reload watcher
  - Implement `ConfigWatcher` using `watchdog` (inotify) in `snoop/config.py`
  - Debounce file change events to 5 s; on change call `daemon.reload_config()`
  - `reload_config()` updates whitelist, heuristic patterns, and anomaly threshold without restarting
  - _Requirements: 2.5, 7.5, 11.4_

- [ ] 15. Daemon supervisor and lifecycle management
  - [ ] 15.1 Implement `Daemon` class in `snoop/daemon.py`
    - Wire all components: `LogTailer → heuristic_queue → HeuristicFilter → anomaly_queue → AnomalyDetector → agent_queue → Agent`
    - Start `CooldownScheduler` as periodic asyncio task; start `ConfigWatcher` thread
    - Write PID file on start; remove on clean exit; block second-instance launch (PID file + process liveness check)
    - Register `SIGTERM → stop()` (complete in-flight agent invocation, flush SQLite writes, exit within 10 s) and `SIGHUP → reload_config()`
    - Log all operational events to stderr (systemd journal) using structured log lines
    - _Requirements: 12.1, 12.2, 12.3, 12.5, 12.6_
  - [ ]* 15.2 Write unit tests for daemon lifecycle
    - Test SIGTERM clean shutdown; test second-instance rejection; test SIGHUP config reload
    - _Requirements: 12.1, 12.2, 12.3, 12.5_

- [ ] 16. systemd unit file
  - Create `snoop.service` unit file template
  - Configure `Restart=on-failure`, dedicated non-root user, `StandardError=journal`
  - _Requirements: 12.4_

- [ ] 17. Integration wiring and end-to-end tests
  - [ ]* 17.1 Write integration test: full pipeline log line → firewall rule
    - Inject a log line, verify it passes heuristic → anomaly → agent → `active_bans` record (mocked subprocess)
    - _Requirements: 1.3, 2.3, 3.3, 4.4, 6.1, 6.4_
  - [ ]* 17.2 Write integration test: daemon startup restores active bans
    - Pre-populate `active_bans`, start daemon, verify `restore_bans()` re-applies DROP rules
    - _Requirements: 6.6_
  - [ ]* 17.3 Write integration test: SIGTERM graceful shutdown within 10 s
    - _Requirements: 12.2_
  - [ ]* 17.4 Write integration test: CLI commands against populated SQLite test database
    - Cover `status`, `audit`, `ban list`, `unban`, `whitelist check`
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.6_

- [ ] 18. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements for traceability
- Property tests use `hypothesis` and are tagged with their design document property number
- All subprocess calls use argument lists (`shell=False`) — no string interpolation with user input
- The LLM stage is fail-open: timeouts and parse errors always default to `Action.ALLOW`
- The whitelist is the only fail-closed component in the system
