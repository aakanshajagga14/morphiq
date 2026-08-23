from __future__ import annotations
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.table import Table
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn

def setup_interactive(config_path: str = "config.yaml") -> None:
    console = Console()
    
    banner = """╔══════════════════════════════════╗
║  🛡️  MORPHIQ IPS SETUP WIZARD  🛡️  ║
║  AI-powered intrusion prevention  ║
╚══════════════════════════════════╝"""
    console.print(Panel(banner, style="bold blue"))
    
    config_dict = {}
    
    console.print("\n[bold]Step 1: Log File Configuration[/bold]")
    detected_logs = []
    if os.name == 'nt':
        candidates = [
            r"C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log",
            r"C:\Program Files\nginx\logs\access.log",
            r"C:\Program Files (x86)\nginx\logs\access.log"
        ]
    else:
        candidates = [
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log"
        ]
    
    for c in candidates:
        detected_logs.append(c)
        
    for i, path in enumerate(detected_logs, 1):
        console.print(f"{i}. {path}")
    console.print(f"{len(detected_logs) + 1}. Enter custom path")
    
    choice = Prompt.ask("Choose log file path", choices=[str(i) for i in range(1, len(detected_logs) + 2)])
    if int(choice) == len(detected_logs) + 1:
        log_path = Prompt.ask("Enter full path to log file")
    else:
        log_path = detected_logs[int(choice) - 1]
    config_dict["log_file_path"] = log_path
    
    format_preset = Prompt.ask(
        "Log format preset",
        choices=["nginx_combined", "apache_combined", "iis_w3c", "caddy_json"],
        default="nginx_combined",
    )
    config_dict["log_format_preset"] = format_preset
    config_dict["log_format_regex"] = ""
    
    console.print("\n[bold]Step 2: Effective IP Header[/bold]")
    is_proxied = Confirm.ask("Is your server behind a reverse proxy or CDN? (e.g. Cloudflare, Nginx proxy)")
    if is_proxied:
        ip_header = Prompt.ask("Which header contains the real client IP?", default="X-Forwarded-For")
        config_dict["effective_ip_header"] = ip_header
    else:
        config_dict["effective_ip_header"] = ""
        
    console.print("\n[bold]Step 3: LLM Configuration[/bold]")
    enable_llm = Confirm.ask("Enable LLM for advanced threat detection?", default=True)
    config_dict["llm_enabled"] = enable_llm
    if enable_llm:
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        gguf_files = list(models_dir.glob("*.gguf"))
        if gguf_files:
            model_path = gguf_files[0]
            if Confirm.ask(f"Found model: {model_path}. Use it?", default=True):
                config_dict["llm_model_path"] = str(model_path)
            else:
                config_dict["llm_model_path"] = Prompt.ask("Enter path to model .gguf file")
        else:
            console.print("[yellow]No .gguf model found in ./models/[/yellow]")
            console.print("We recommend: Gemma 2B Q4_K_M")
            config_dict["llm_model_path"] = Prompt.ask("Enter path to model .gguf file", default="models/gemma-2b-q4.gguf")
    else:
        config_dict["llm_model_path"] = ""
            
    console.print("\n[bold]Step 4: IP Whitelist[/bold]")
    local_ips = ["127.0.0.1", "::1"]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
        
    console.print(f"Auto-detected IPs: {', '.join(local_ips)}")
    extra_ips = Prompt.ask("Add more IPs to whitelist (comma-separated)", default="")
    wl = set(local_ips)
    if extra_ips:
        for ip in extra_ips.split(","):
            wl.add(ip.strip())
    config_dict["whitelist"] = sorted(wl)
    
    console.print("\n[bold]Step 5: Firewall Backend[/bold]")
    suggested_backend = "windows" if os.name == 'nt' else "iptables"
    if os.name == 'nt':
        import ctypes
        try:
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                console.print("[yellow]WARNING: You are not running as Administrator. Windows Firewall modifications will fail.[/yellow]")
        except Exception:
            pass
            
    backend = Prompt.ask("Select firewall backend", choices=["windows", "iptables", "mock"], default=suggested_backend)
    config_dict["firewall_backend"] = backend
    
    console.print("\n[bold]Step 6: Dashboard[/bold]")
    dash_enabled = Confirm.ask("Enable web dashboard?", default=True)
    config_dict["dashboard_enabled"] = dash_enabled
    if dash_enabled:
        config_dict["dashboard_port"] = int(Prompt.ask("Dashboard port", default="8080"))
        config_dict["dashboard_host"] = "127.0.0.1"
    else:
        config_dict["dashboard_port"] = 8080
        config_dict["dashboard_host"] = "127.0.0.1"
        
    config_dict["db_path"] = "morphiq.db"
    config_dict["pid_file_path"] = "morphiq.pid"
    config_dict["morphiq_log_file"] = "logs/morphiq.log"
    config_dict["log_level"] = "INFO"
    config_dict["queue_maxsize"] = 10000
    config_dict["anomaly_threshold"] = 0.85
    config_dict["default_ban_duration_s"] = 3600
    
    patterns = [
        {"name": "SQL Injection", "field": "path", "pattern": r"(union\s+select|select\s+.*\s+from|drop\s+table|;\s*--)", "description": "Common SQL injection tokens."},
        {"name": "Cross-Site Scripting", "field": "path", "pattern": r"(<script|javascript:|onerror\s*=|onload\s*=)", "description": "Common script-injection tokens."},
        {"name": "Path Traversal", "field": "path", "pattern": r"(\.\./|%2e%2e%2f|%2e%2e/|%2e%2e%5c)", "description": "Parent-directory traversal attempts."},
        {"name": "Command Injection", "field": "path", "pattern": r"(;\s*(ls|cat|id|whoami|wget|curl|bash|sh|cmd|powershell))", "description": "Common shell command injection tokens."},
        {"name": "Malicious User Agent", "field": "user_agent", "pattern": r"(nikto|sqlmap|nmap|dirbuster|wpscan|masscan|zgrab)", "description": "Known offensive scanner user agents."},
        {"name": "Suspicious Request Method", "field": "method", "pattern": r"(TRACE|TRACK|CONNECT)", "description": "Rarely required HTTP methods."},
    ]
    config_dict["heuristic_patterns"] = patterns

    yaml_str = yaml.dump(config_dict, sort_keys=False)
    console.print("\n[bold]Configuration Preview:[/bold]")
    console.print(Syntax(yaml_str, "yaml", theme="monokai"))
    
    if Confirm.ask(f"Write configuration to {config_path}?"):
        with open(config_path, "w") as f:
            f.write(yaml_str)
        console.print(f"[green]Configuration saved to {config_path}[/green]")
        
    if os.name == 'nt' and Confirm.ask("Do you want MorphIQ to start automatically on login?"):
        python_exe = sys.executable
        cmd = f'schtasks /Create /TN "MorphIQ IPS" /TR "\\"{python_exe}\\" -m morphiq.daemon --config {config_path}" /SC ONLOGON /RL HIGHEST /F'
        console.print(f"Running: {cmd}")
        subprocess.run(cmd, shell=False)
        console.print("[green]Auto-start configured.[/green]")

    table = Table(title="Setup Complete")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")
    for k, v in config_dict.items():
        if k != "heuristic_patterns":
            table.add_row(k, str(v))
    console.print(table)
    
    console.print("\n[bold]Next Steps:[/bold]")
    console.print("1. Run: [cyan]morphiq start[/cyan] (as Administrator)")
    console.print("2. View status: [cyan]morphiq status[/cyan]")
    if dash_enabled:
        console.print("3. View dashboard: [cyan]morphiq dashboard[/cyan]")

if __name__ == "__main__":
    setup_interactive()
