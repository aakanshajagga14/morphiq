# Graph Report - C:\Users\Dell\ANTIGRAVITY_CODE\Snoop  (2026-06-21)

## Corpus Check
- 27 files · ~12,065 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 213 nodes · 444 edges · 21 communities detected
- Extraction: 54% EXTRACTED · 46% INFERRED · 0% AMBIGUOUS · INFERRED: 204 edges (avg confidence: 0.64)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]

## God Nodes (most connected - your core abstractions)
1. `SQLiteStore` - 44 edges
2. `Daemon` - 26 edges
3. `FirewallController` - 22 edges
4. `Agent` - 22 edges
5. `DashboardServer` - 20 edges
6. `AnomalyDetector` - 20 edges
7. `PatternRule` - 19 edges
8. `Config` - 17 edges
9. `LLMClient` - 17 edges
10. `JsonFormatter` - 16 edges

## Surprising Connections (you probably didn't know these)
- `Loads, merges, and validates configuration from a YAML file.      Merge preceden` --uses--> `PatternRule`  [INFERRED]
  C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\config.py → C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\models.py
- `Load and validate configuration.      Resolution order for the config file path:` --uses--> `PatternRule`  [INFERRED]
  C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\config.py → C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\models.py
- `JsonFormatter` --uses--> `Config`  [INFERRED]
  C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\daemon.py → C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\config.py
- `Daemon` --uses--> `Config`  [INFERRED]
  C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\daemon.py → C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\config.py
- `LLMClient` --uses--> `Config`  [INFERRED]
  C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\llm_client.py → C:\Users\Dell\ANTIGRAVITY_CODE\Snoop\snoop\config.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.1
Nodes (19): Agent, AgentStateDict, Enum, LLMClient, Action, AgentDecision, FeedbackEvent, FilterResult (+11 more)

### Community 1 - "Community 1"
Cohesion: 0.12
Nodes (19): Config, ConfigValidationError, ConfigWatcher, _DebounceHandler, for_field(), load(), Read *path* (YAML), merge with defaults, validate, and return a         fully-po, Validate *raw* dict and return a Config instance.          Raises ConfigValidati (+11 more)

### Community 2 - "Community 2"
Cohesion: 0.09
Nodes (8): setup(), DaemonStats, Live counters updated by the daemon main loop., DashboardServer, dumps(), json_serial(), JSON serializer for objects not serializable by default json code, setup_interactive()

### Community 3 - "Community 3"
Cohesion: 0.12
Nodes (6): AnomalyDetector, LogTailer, FeatureVector, LogEntry, A single parsed HTTP access-log line., Numeric representation of a log entry for ML models.

### Community 4 - "Community 4"
Cohesion: 0.13
Nodes (5): CooldownScheduler, FirewallController, whitelist_check(), AuditEvent, Persisted record of every agent decision.

### Community 5 - "Community 5"
Cohesion: 0.18
Nodes (14): load_config(), Load and validate configuration.      Resolution order for the config file path:, audit(), ban_list(), dashboard(), feedback(), retrain(), start() (+6 more)

### Community 6 - "Community 6"
Cohesion: 0.24
Nodes (5): ConfigLoader, Loads, merges, and validates configuration from a YAML file.      Merge preceden, Daemon, JsonFormatter, run()

### Community 7 - "Community 7"
Cohesion: 0.31
Nodes (1): ProbeDetector

### Community 8 - "Community 8"
Cohesion: 0.33
Nodes (1): HeuristicFilter

### Community 9 - "Community 9"
Cohesion: 0.53
Nodes (5): handle_attack(), handle_home(), handle_login(), Writes a line to the access log in Nginx format., write_log()

### Community 10 - "Community 10"
Cohesion: 1.0
Nodes (1): Allow running as: python -m snoop

### Community 11 - "Community 11"
Cohesion: 1.0
Nodes (0): 

### Community 12 - "Community 12"
Cohesion: 1.0
Nodes (0): 

### Community 13 - "Community 13"
Cohesion: 1.0
Nodes (0): 

### Community 14 - "Community 14"
Cohesion: 1.0
Nodes (0): 

### Community 15 - "Community 15"
Cohesion: 1.0
Nodes (0): 

### Community 16 - "Community 16"
Cohesion: 1.0
Nodes (0): 

### Community 17 - "Community 17"
Cohesion: 1.0
Nodes (0): 

### Community 18 - "Community 18"
Cohesion: 1.0
Nodes (0): 

### Community 19 - "Community 19"
Cohesion: 1.0
Nodes (0): 

### Community 20 - "Community 20"
Cohesion: 1.0
Nodes (0): 

## Knowledge Gaps
- **17 isolated node(s):** `Writes a line to the access log in Nginx format.`, `Read *path* (YAML), merge with defaults, validate, and return a         fully-po`, `Validate *raw* dict and return a Config instance.          Raises ConfigValidati`, `A single parsed HTTP access-log line.`, `A compiled regex rule used by the heuristic filter.` (+12 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 10`** (2 nodes): `__main__.py`, `Allow running as: python -m snoop`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 11`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 12`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 13`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 14`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 15`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 16`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 17`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 18`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 19`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 20`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `SQLiteStore` connect `Community 5` to `Community 0`, `Community 2`, `Community 3`, `Community 4`, `Community 6`, `Community 7`?**
  _High betweenness centrality (0.239) - this node is a cross-community bridge._
- **Why does `Daemon` connect `Community 6` to `Community 0`, `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 5`, `Community 7`, `Community 8`?**
  _High betweenness centrality (0.132) - this node is a cross-community bridge._
- **Why does `Config` connect `Community 1` to `Community 0`, `Community 2`, `Community 3`, `Community 4`, `Community 6`, `Community 7`, `Community 8`?**
  _High betweenness centrality (0.129) - this node is a cross-community bridge._
- **Are the 25 inferred relationships involving `SQLiteStore` (e.g. with `JsonFormatter` and `Daemon`) actually correct?**
  _`SQLiteStore` has 25 INFERRED edges - model-reasoned connections that need verification._
- **Are the 13 inferred relationships involving `Daemon` (e.g. with `Config` and `ConfigLoader`) actually correct?**
  _`Daemon` has 13 INFERRED edges - model-reasoned connections that need verification._
- **Are the 13 inferred relationships involving `FirewallController` (e.g. with `JsonFormatter` and `Daemon`) actually correct?**
  _`FirewallController` has 13 INFERRED edges - model-reasoned connections that need verification._
- **Are the 15 inferred relationships involving `Agent` (e.g. with `JsonFormatter` and `Daemon`) actually correct?**
  _`Agent` has 15 INFERRED edges - model-reasoned connections that need verification._