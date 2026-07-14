# Requirements Document

## Introduction

Snoop is an autonomous, hybrid Intrusion Prevention System (IPS) running as a background Python daemon on Linux servers. It protects web applications from complex and zero-day attacks by processing incoming requests through a three-stage pipeline: high-speed heuristic filtering, structural anomaly detection via an unsupervised ML model, and a LangGraph-orchestrated AI agent that investigates context and enforces firewall rules. Snoop targets Linux system administrators, DevOps engineers, and self-hosters who need intelligent, privacy-preserving, zero-configuration defense.

## Glossary

- **Daemon**: The Snoop background process that monitors logs and coordinates all pipeline stages.
- **Log_Tailer**: The async component responsible for reading and streaming new lines from web server access logs.
- **Heuristic_Filter**: The first pipeline stage; performs lightweight keyword and regex pattern matching against incoming log entries.
- **Anomaly_Detector**: The second pipeline stage; an IsolationForest model that scores request feature vectors for structural anomalousness.
- **Agent**: The third pipeline stage; a LangGraph-orchestrated workflow that uses a local LLM to investigate, reason about, and act on suspected threats.
- **LLM**: The local 2B-parameter Gemma model served via llama-cpp-python used by the Agent for semantic threat analysis.
- **Firewall_Controller**: The component that executes iptables/ufw commands to block or unblock IP addresses.
- **Cooldown_Scheduler**: The component that tracks ban expiry times and issues unban commands when durations elapse.
- **SQLite_Store**: The embedded SQLite database used for traffic history, active bans, and the threat audit log.
- **Whitelist**: The set of IP addresses and CIDR subnets defined in config.yaml that are permanently exempt from any blocking action.
- **CLI**: The command-line interface (`snoop`) used to inspect daemon status, review the audit log, and manage bans.
- **Config**: The `config.yaml` file that defines the whitelist, log path, log format parsing rules, and tunable parameters.
- **traffic_history**: SQLite table storing a rolling buffer of recent traffic entries used as context for the Agent.
- **active_bans**: SQLite table tracking currently blocked IP addresses, ban reasons, and expiry timestamps.
- **threat_audit_log**: Append-only SQLite table recording every analyzed threat event and the action taken.

---

## Requirements

### Requirement 1: Real-Time Log Tailing

**User Story:** As a system administrator, I want Snoop to continuously monitor web server access logs in real time, so that no malicious request goes undetected due to a polling delay.

#### Acceptance Criteria

1. WHEN the Daemon starts, THE Log_Tailer SHALL open the log file path specified in Config and begin streaming new log lines asynchronously.
2. WHEN the monitored log file is rotated or replaced, THE Log_Tailer SHALL detect the change and reopen the new file without requiring a daemon restart.
3. WHEN a new log line is written to the monitored file, THE Log_Tailer SHALL emit the parsed log entry to the pipeline within 500ms.
4. IF the monitored log file is temporarily unavailable, THEN THE Log_Tailer SHALL retry file access at 5-second intervals and log a warning to the system journal on each failed attempt.
5. THE Log_Tailer SHALL parse log lines using the format rules defined in Config, extracting at minimum: source IP address, HTTP method, request path, response status code, and User-Agent.
6. IF a log line does not match the configured format, THEN THE Log_Tailer SHALL discard the line and increment a parse-error counter without halting the pipeline.

---

### Requirement 2: Heuristic Pre-Filter

**User Story:** As a system administrator, I want a fast, rule-based filter to instantly discard clearly benign traffic, so that the ML model and LLM are only invoked for genuinely suspicious requests.

#### Acceptance Criteria

1. THE Heuristic_Filter SHALL evaluate every parsed log entry against a set of configurable keyword and regex patterns before the entry reaches the Anomaly_Detector.
2. WHEN a parsed log entry matches none of the heuristic patterns, THE Heuristic_Filter SHALL mark the entry as benign and drop it from further processing.
3. WHEN a parsed log entry matches one or more heuristic patterns, THE Heuristic_Filter SHALL mark the entry as suspicious and forward it to the Anomaly_Detector.
4. THE Heuristic_Filter SHALL complete evaluation of a single log entry within 10ms on standard server hardware.
5. WHERE heuristic pattern sets are updated in Config, THE Heuristic_Filter SHALL reload the updated patterns within 60 seconds without restarting the Daemon.

---

### Requirement 3: Structural Anomaly Detection

**User Story:** As a system administrator, I want an ML model to detect structurally unusual requests, so that novel attack patterns not covered by static rules are still escalated for deeper investigation.

#### Acceptance Criteria

1. THE Anomaly_Detector SHALL maintain a trained IsolationForest model that scores each suspicious log entry forwarded by the Heuristic_Filter.
2. WHEN an entry is received, THE Anomaly_Detector SHALL extract a numeric feature vector from the log entry fields (including request path length, query string entropy, HTTP method encoding, and response status code) and compute an anomaly score.
3. WHEN the anomaly score exceeds the configured anomaly threshold, THE Anomaly_Detector SHALL forward the entry to the Agent for investigation.
4. WHEN the anomaly score does not exceed the configured anomaly threshold, THE Anomaly_Detector SHALL discard the entry.
5. THE Anomaly_Detector SHALL limit Agent invocations to no more than the configured maximum escalation rate (requests per minute) to prevent LLM CPU exhaustion under high-volume attack conditions.
6. THE Anomaly_Detector SHALL support retraining the IsolationForest model from stored traffic_history data via a CLI-triggered or scheduled operation, without interrupting active monitoring.
7. WHERE no trained model file exists on startup, THE Anomaly_Detector SHALL train an initial model from any existing traffic_history data, and SHALL operate in heuristic-only mode if insufficient training data is available.

---

### Requirement 4: LangGraph Agent Orchestration

**User Story:** As a system administrator, I want the AI analyst to follow a strict, deterministic Investigate → Reason → Act workflow, so that the LLM always gathers evidence before making a blocking decision.

#### Acceptance Criteria

1. THE Agent SHALL implement the workflow as a LangGraph state machine with the explicit node sequence: Investigate → Reason → Act.
2. WHEN the Agent is invoked with a suspicious log entry, THE Agent SHALL first execute the Investigate node, which queries the SQLite_Store for the source IP's traffic_history before proceeding to the Reason node.
3. WHEN the Investigate node completes, THE Agent SHALL execute the Reason node, which presents the LLM with the suspicious entry and retrieved history to produce a structured threat assessment.
4. WHEN the Reason node completes, THE Agent SHALL execute the Act node, which translates the LLM's assessment into a concrete action (block or allow).
5. IF the LLM returns a malformed or unparseable assessment, THEN THE Agent SHALL default to the allow action and record the failure in the threat_audit_log.
6. THE Agent SHALL enforce a maximum LLM inference timeout of 30 seconds per invocation; IF the timeout is exceeded, THEN THE Agent SHALL default to the allow action and log the timeout event.
7. THE Agent SHALL record the full LangGraph execution trace, the LLM's reasoning, and the final action in the threat_audit_log upon completing each workflow cycle.

---

### Requirement 5: Local LLM Inference

**User Story:** As a system administrator, I want all AI inference to run locally on the server CPU, so that no request data or IP information is ever transmitted to an external service.

#### Acceptance Criteria

1. THE LLM SHALL be served exclusively via llama-cpp-python using a locally stored Gemma 2B model file, with no external API calls made during inference.
2. WHEN the Daemon starts, THE LLM SHALL load the model file from the path specified in Config and confirm successful loading before the Agent processes any entries.
3. IF the model file is missing or fails to load, THEN THE Daemon SHALL log a fatal error, disable the Agent stage, and continue operating in heuristic-and-anomaly-only mode.
4. THE LLM SHALL accept a structured prompt containing the suspicious log entry, the source IP's traffic history summary, and explicit instructions to output a structured JSON threat assessment.
5. THE LLM SHALL produce a threat assessment that includes at minimum: a threat classification label, a confidence indicator, and a recommended action field.

---

### Requirement 6: Firewall Enforcement

**User Story:** As a system administrator, I want Snoop to autonomously add and remove firewall rules, so that confirmed malicious IPs are blocked at the network level without requiring manual intervention.

#### Acceptance Criteria

1. WHEN the Agent issues a block action for an IP address, THE Firewall_Controller SHALL execute the appropriate iptables or ufw DROP rule for that IP within 2 seconds of the action being issued.
2. THE Firewall_Controller SHALL sanitize every IP address parameter using strict IPv4/IPv6 format validation before constructing any subprocess command, to prevent command injection.
3. IF an IP address fails format validation, THEN THE Firewall_Controller SHALL reject the block request, log the invalid input, and take no system action.
4. WHEN a block rule is successfully applied, THE Firewall_Controller SHALL record the IP address, ban reason, ban timestamp, and expiry timestamp in the active_bans table of the SQLite_Store.
5. THE Firewall_Controller SHALL support both iptables and ufw backends, selectable via Config.
6. WHEN the Daemon starts, THE Firewall_Controller SHALL re-apply all unexpired rules from the active_bans table to restore the firewall state after a restart.

---

### Requirement 7: Whitelist Safeguard

**User Story:** As a system administrator, I want a mandatory whitelist of protected IPs, so that Snoop can never block my own admin access or internal services regardless of what the AI decides.

#### Acceptance Criteria

1. THE Daemon SHALL load the whitelist of IP addresses and CIDR subnets from Config on startup.
2. BEFORE any firewall rule is generated, THE Firewall_Controller SHALL evaluate the target IP against the Whitelist.
3. IF the target IP matches any entry in the Whitelist, THEN THE Firewall_Controller SHALL unconditionally abort the block action and log a whitelist-protection event.
4. THE Whitelist SHALL always include 127.0.0.1 and ::1 as protected entries, regardless of Config contents.
5. WHEN the Config file is updated, THE Daemon SHALL reload the Whitelist within 60 seconds without restarting.
6. THE Whitelist evaluation SHALL be performed as a synchronous, in-process check with no external dependencies, ensuring it cannot be bypassed by pipeline failures.

---

### Requirement 8: Automated Cooldown and Unban Management

**User Story:** As a system administrator, I want banned IPs to be automatically unblocked after a configurable cooldown period, so that transient false positives do not permanently disrupt legitimate users.

#### Acceptance Criteria

1. THE Cooldown_Scheduler SHALL poll the active_bans table at a configurable interval (default: 60 seconds) for bans whose expires_at timestamp has elapsed.
2. WHEN an expired ban is detected, THE Cooldown_Scheduler SHALL instruct the Firewall_Controller to remove the corresponding DROP rule.
3. WHEN the DROP rule is successfully removed, THE Cooldown_Scheduler SHALL delete the corresponding record from the active_bans table and append an unban event to the threat_audit_log.
4. IF removal of a firewall rule fails, THEN THE Cooldown_Scheduler SHALL retain the active_bans record, log the failure, and retry removal on the next polling cycle.
5. THE ban duration for each block action SHALL be sourced from the Agent's threat assessment, with a configurable default duration applied when the assessment does not specify one.

---

### Requirement 9: SQLite Data Store

**User Story:** As a system administrator, I want all state and audit data stored in a local SQLite database, so that I can query the threat history and ban log without installing any external database service.

#### Acceptance Criteria

1. THE SQLite_Store SHALL maintain three tables: traffic_history, active_bans, and threat_audit_log, with schemas sufficient to support all queries issued by the Daemon, Agent, and CLI.
2. THE SQLite_Store SHALL enforce a rolling retention window on the traffic_history table, deleting entries older than the configured retention period (default: 24 hours) during each write cycle.
3. THE threat_audit_log table SHALL be append-only; THE SQLite_Store SHALL reject any update or delete operations against it.
4. WHEN the Daemon starts and the SQLite database file does not exist, THE SQLite_Store SHALL create the file and initialize all tables with the correct schemas automatically.
5. THE SQLite_Store SHALL use WAL (Write-Ahead Logging) mode to allow concurrent read access from the CLI without blocking Daemon writes.

---

### Requirement 10: Terminal CLI

**User Story:** As a system administrator, I want a command-line interface for Snoop, so that I can inspect daemon status, review the threat audit log, and manage bans from the terminal without editing database files directly.

#### Acceptance Criteria

1. THE CLI SHALL provide a `snoop status` command that displays the current Daemon state, the number of active bans, and the counts of entries processed per pipeline stage since the last start.
2. THE CLI SHALL provide a `snoop audit` command that retrieves and displays the N most recent records from the threat_audit_log, where N is configurable via a command-line flag (default: 20).
3. THE CLI SHALL provide a `snoop ban list` command that displays all records in the active_bans table including IP address, ban reason, and expiry time.
4. THE CLI SHALL provide a `snoop unban <ip>` command that instructs the Firewall_Controller to remove the DROP rule for the specified IP and deletes the corresponding active_bans record.
5. WHEN `snoop unban` is invoked for an IP not present in the active_bans table, THE CLI SHALL display an informative message indicating the IP is not currently banned, without returning a non-zero exit code.
6. THE CLI SHALL provide a `snoop whitelist check <ip>` command that reports whether a given IP is protected by the Whitelist.
7. IF the Daemon is not running when a CLI command is issued, THEN THE CLI SHALL display a clear message indicating the Daemon is offline and exit with a non-zero exit code for all commands except `snoop status`.

---

### Requirement 11: Configuration Management

**User Story:** As a system administrator, I want a single YAML configuration file for all Snoop settings, so that I can tune behavior without modifying source code or restarting the daemon for most changes.

#### Acceptance Criteria

1. THE Daemon SHALL read all runtime parameters from a `config.yaml` file at a well-known path on startup.
2. THE Config SHALL support the following parameters at minimum: log file path, log format parsing rules, firewall backend (iptables or ufw), whitelist entries, anomaly threshold, maximum escalation rate, LLM model file path, default ban duration, and traffic history retention period.
3. IF the `config.yaml` file is missing or unparseable on startup, THEN THE Daemon SHALL log a fatal error and exit with a non-zero exit code.
4. THE Daemon SHALL monitor `config.yaml` for changes and reload the Whitelist, heuristic patterns, and anomaly threshold within 60 seconds of a file modification, without restarting.
5. THE Config SHALL include a YAML parser that validates all required fields and their types on load, reporting the first validation error encountered as a descriptive message.
6. FOR ALL valid config.yaml files, serializing the parsed Config object back to YAML and re-parsing it SHALL produce an equivalent Config object (round-trip property).

---

### Requirement 12: Daemon Lifecycle Management

**User Story:** As a system administrator, I want the Snoop daemon to start, stop, and restart cleanly, so that it integrates with standard Linux service management tools like systemd.

#### Acceptance Criteria

1. THE Daemon SHALL write a PID file to a configurable path on startup and remove the PID file on clean shutdown.
2. WHEN the Daemon receives SIGTERM, THE Daemon SHALL complete any in-progress Agent invocation, flush pending SQLite writes, and exit cleanly within 10 seconds.
3. WHEN the Daemon receives SIGHUP, THE Daemon SHALL reload Config and the Whitelist without interrupting active monitoring.
4. THE Daemon SHALL provide a systemd unit file template that starts the process as a service, restarts it on failure, and runs it under a dedicated non-root user account.
5. IF the Daemon is already running (PID file exists and process is live), THEN a second launch attempt SHALL log an error and exit with a non-zero exit code without starting a second instance.
6. THE Daemon SHALL log all operational events (startup, shutdown, pipeline stage escalations, ban/unban events, errors) to the system journal via stderr using structured log lines.
