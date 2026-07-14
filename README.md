# Snoop IPS

**Snoop IPS** is an AI-powered Intrusion Prevention System (IPS) that acts as a highly intelligent firewall and threat detection engine. It monitors web server logs in real-time to detect, analyze, and automatically block malicious traffic.

Instead of relying solely on static rules like traditional tools, Snoop combines heuristic pattern matching with Machine Learning (Anomaly Detection) and Local Large Language Models (LLMs) to make context-aware security decisions.

## 🌟 Key Features

* **Real-time Log Monitoring**: Continuously tails web server logs (Nginx, Apache, IIS, etc.) to evaluate incoming requests.
* **Multi-Layered Threat Detection**:
  * **Layer 1 - Heuristics**: Instantly flags known attack signatures like SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, and Command Injection.
  * **Layer 2 - Anomaly Detection**: Uses an Isolation Forest machine learning model to detect unusual traffic patterns based on request frequency, path lengths, and query entropy.
  * **Layer 3 - LLM Threat Assessment**: Suspicious requests are escalated to a local LLM (like Gemma or Llama 3 running via LM Studio). The LLM acts as an AI security analyst, reviewing the request context, traffic history, and payload to determine if it's a true threat or a false positive.
* **Automated Banning**: Automatically bans malicious IPs via the configured firewall backend (e.g., Windows Firewall via `netsh`) when a threat is confirmed.
* **Interactive Web Dashboard**: A modern, real-time React dashboard to view traffic statistics, active bans, and the AI's threat audit logs.
* **Fully Configurable**: Easily tweak thresholds, LLM endpoints, and detection rules via `config.yaml`.
* **Privacy First**: All data is processed locally.

## 🏗 Architecture

Snoop is composed of two main components:
1. **The Daemon (`snoop start`)**: A background process that tails logs, processes requests through the 3-stage detection pipeline, queries the local LLM, manages the SQLite database (`snoop.db`), and issues firewall blocks.
2. **The Dashboard**: A web interface served by an `aiohttp` server running on port 3000, providing real-time insights into the IPS's operations.

## 🚀 Getting Started

### Prerequisites
* Python 3.11+
* (Optional) **LM Studio** or another local LLM provider exposing an OpenAI-compatible API on port 1234.

### Configuration
All settings are managed in `config.yaml` located in the root directory.

Key configurations to check:
* `log_file_path`: Path to the web server log file you want to monitor.
* `llm_enabled`: Set to `true` to enable AI analysis, or `false` to run in heuristic-only mode.
* `llm_base_url`: URL of your local LLM server (default is `http://localhost:1234/v1` for LM Studio).
* `dashboard_port`: Port for the web dashboard (default 3000).

### Running Snoop

Snoop includes a CLI tool to manage the daemon process.

```bash
# Start the Snoop daemon and dashboard in the background
snoop start

# Stop the running Snoop daemon
snoop stop
```

Once started, the dashboard will be available at: **http://127.0.0.1:3000**

## 🤖 Using the AI (Local LLM)
If you want to use the AI analysis feature:
1. Open **LM Studio**.
2. Load a fast, instruct-tuned model (e.g., Gemma 2B or Llama 3 8B).
3. Start the Local Server on port `1234`.
4. Ensure `llm_enabled: true` in your `config.yaml`.
5. Run `snoop start`.

*Note: If you experience crashes with specific models (like Gemma 4) in LM Studio, try reducing `Parallel Requests` to `1` and lowering the `Context Length` to `4096`, or switch to a more stable model.*

## 🧪 Demo Mode
To test Snoop without a real web server, you can point `log_file_path` to `demo_access.log` and use a script to append simulated malicious and benign requests to the log file. Snoop will immediately pick them up and analyze them on the dashboard!

## License

MIT License. See `LICENSE` for details.
