from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from morphiq.cli.setup_wizard import setup_interactive
from morphiq.config import load_config
from morphiq.fw.firewall_controller import FirewallController
from morphiq.models import FeedbackEvent
from morphiq.pipeline.anomaly_detector import AnomalyDetector
from morphiq.store.sqlite_store import SQLiteStore

app = typer.Typer(
    name="morphiq",
    help="[bold blue]MorphIQ IPS[/bold blue] — local-first, AI-assisted intrusion prevention",
    rich_markup_mode="rich",
    add_completion=False,
)
console = Console()

CONFIG_PATH: str = os.environ.get("MORPHIQ_CONFIG", "config.yaml")

@app.command("setup")
def setup(config: Optional[str] = typer.Option(None, "--config")):
    cfg_path = config if config else CONFIG_PATH
    setup_interactive(cfg_path)

@app.command("start")
def start(config: Optional[str] = typer.Option(None, "--config")):
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1)
        
    pid_file = Path(cfg.pid_file_path)
    if pid_file.exists():
        console.print(f"[red]Daemon appears to be running (PID file exists at {pid_file}).[/red]")
        raise typer.Exit(1)
        
    python_exe = sys.executable
    if python_exe.lower().endswith("morphiq.exe"):
        python_exe = str(Path(python_exe).parent.parent / "python.exe")

    abs_cfg = str(Path(cfg_path).resolve())
    cwd = str(Path.cwd())

    if os.name == 'nt':
        # pythonw.exe is a Windows GUI-subsystem process with NO console.
        # This means it cannot receive CTRL_C, CTRL_CLOSE, or any console
        # event from the parent — the most reliable background launch on Windows.
        pythonw = Path(python_exe).parent / "pythonw.exe"
        launcher = str(pythonw) if pythonw.exists() else python_exe
        CREATE_NO_WINDOW = 0x08000000
        subprocess.Popen(
            [launcher, "-m", "morphiq.daemon", "--config", abs_cfg],
            cwd=cwd,
            creationflags=CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )
    else:
        subprocess.Popen(
            [python_exe, "-m", "morphiq.daemon", "--config", abs_cfg],
            cwd=cwd, start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )

    # Poll up to 20s for the daemon to write its own PID file
    console.print("[dim]Waiting for daemon to start...[/dim]")
    for _ in range(20):
        time.sleep(1)
        if pid_file.exists():
            pid = pid_file.read_text().strip()
            console.print(f"[green]MorphIQ IPS started successfully (PID: {pid}).[/green]")
            return
    console.print("[red]Daemon did not start in time. Check morphiq.log for details.[/red]")
    raise typer.Exit(1)

@app.command("stop")
def stop(config: Optional[str] = typer.Option(None, "--config")):
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1)
        
    pid_file = Path(cfg.pid_file_path)
    if not pid_file.exists():
        console.print("[yellow]PID file not found. Is MorphIQ running?[/yellow]")
        raise typer.Exit(1)
        
    try:
        pid = int(pid_file.read_text().strip())
    except ValueError:
        console.print("[red]PID file is corrupt.[/red]")
        raise typer.Exit(1)

    if os.name == 'nt':
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
            
    for _ in range(10):
        if not pid_file.exists():
            break
        time.sleep(1)
        
    if pid_file.exists():
        try:
            pid_file.unlink()
        except OSError:
            pass
            
    console.print("[green]MorphIQ IPS stopped.[/green]")

@app.command("status")
def status(config: Optional[str] = typer.Option(None, "--config")):
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
        store = SQLiteStore(cfg.db_path)
        store.initialize()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
        
    pid_file = Path(cfg.pid_file_path)
    is_running = False
    pid = ""
    if pid_file.exists():
        try:
            pid = pid_file.read_text().strip()
            if os.name == 'nt':
                res = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, shell=False)
                is_running = pid in res.stdout
            else:
                os.kill(int(pid), 0)
                is_running = True
        except Exception:
            is_running = False

    status_color = "green" if is_running else "red"
    status_text = f"ONLINE [{pid}]" if is_running else "OFFLINE"
    
    daemon_stats = store.get_stats()
    stats = {
        "Total Parsed": daemon_stats.total_parsed,
        "Heuristic Flagged": daemon_stats.heuristic_flagged,
        "ML Escalated": daemon_stats.ml_escalated,
        "Agent Invoked": daemon_stats.agent_invoked,
        "Blocked": daemon_stats.blocked,
        "Allowed": daemon_stats.allowed,
    }
    
    bans = store.get_active_bans()
    
    table = Table(show_header=False, box=None)
    for k, v in stats.items():
        table.add_row(f"[bold]{k}:[/bold]", str(v))
    table.add_row("[bold]Active Bans:[/bold]", str(len(bans)))
    
    panel = Panel(
        table,
        title=f"[{status_color}]Daemon: {status_text}[/{status_color}]",
        border_style=status_color
    )
    console.print(panel)

@app.command("audit")
def audit(limit: int = 20, config: Optional[str] = typer.Option(None, "--config")):
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
        store = SQLiteStore(cfg.db_path)
        store.initialize()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
        
    events = store.get_recent_audit(limit)
    
    table = Table("ID", "Time", "IP", "Action", "Threat Label", "Confidence", "Reasoning")
    for ev in events:
        action_str = ev.final_action
        color = "red" if action_str == "block" else "green"
        reasoning = (ev.reasoning[:47] + "...") if ev.reasoning and len(ev.reasoning) > 50 else (ev.reasoning or "")
        conf = f"{ev.confidence:.2f}" if ev.confidence is not None else "N/A"
        table.add_row(
            str(ev.id),
            ev.occurred_at.isoformat(timespec="seconds"),
            ev.source_ip,
            f"[{color}]{ev.final_action}[/{color}]",
            ev.threat_label or "N/A",
            conf,
            reasoning
        )
        
    console.print(table)
    console.print(f"Showing {len(events)} events")

ban_app = typer.Typer()
app.add_typer(ban_app, name="ban", help="Manage bans")

@ban_app.command("list")
def ban_list(config: Optional[str] = typer.Option(None, "--config")):
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
        store = SQLiteStore(cfg.db_path)
        store.initialize()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
        
    bans = store.get_active_bans()
    table = Table("IP", "Reason", "Banned At", "Expires At", "Time Remaining")
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    for ban in bans:
        rem = (ban.expires_at - now).total_seconds()
        rem_str = f"{int(rem)}s"
        if rem < 300:
            rem_str = f"[red]{rem_str}[/red]"
        table.add_row(
            ban.ip,
            ban.reason,
            ban.banned_at.isoformat(timespec="seconds"),
            ban.expires_at.isoformat(timespec="seconds"),
            rem_str
        )
    console.print(table)

@app.command("unban")
def unban(ip: str, config: Optional[str] = typer.Option(None, "--config")):
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        console.print("[red]Invalid IP address.[/red]")
        raise typer.Exit(1)
        
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
        store = SQLiteStore(cfg.db_path)
        store.initialize()
        
        bans = [b.ip for b in store.get_active_bans()]
        if ip not in bans:
            console.print(f"[yellow]IP {ip} is not currently banned.[/yellow]")
            raise typer.Exit(0)
            
        fw = FirewallController(cfg, store)
        if not fw.unblock(ip):
            raise RuntimeError(f"failed to remove firewall rule for {ip}")
        console.print(f"[green]Successfully unbanned {ip}.[/green]")
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

whitelist_app = typer.Typer()
app.add_typer(whitelist_app, name="whitelist", help="Manage whitelist")

@whitelist_app.command("check")
def whitelist_check(ip: str, config: Optional[str] = typer.Option(None, "--config")):
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        console.print("[red]Invalid IP address.[/red]")
        raise typer.Exit(1)
        
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
        store = SQLiteStore(cfg.db_path)
        store.initialize()
        fw = FirewallController(cfg, store)
        if fw.is_whitelisted(ip):
            console.print("[green]PROTECTED[/green]")
        else:
            console.print("[yellow]NOT PROTECTED[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

@app.command("feedback")
def feedback(ip: str, verdict: str, config: Optional[str] = typer.Option(None, "--config")):
    import datetime
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        console.print("[red]Invalid IP address.[/red]")
        raise typer.Exit(1)
        
    if verdict not in ['fp', 'tp']:
        console.print("[red]Verdict must be 'fp' (false positive) or 'tp' (true positive).[/red]")
        raise typer.Exit(1)
        
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
        store = SQLiteStore(cfg.db_path)
        store.initialize()
        now = datetime.datetime.now(datetime.timezone.utc)
        ev = FeedbackEvent(
            ip=ip,
            is_false_positive=(verdict=='fp'),
            context=f"Manual feedback: {verdict}",
            created_at=now
        )
        store.insert_feedback(ev)
        console.print("[green]Feedback recorded. Next retrain will incorporate this.[/green]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

@app.command("retrain")
def retrain(config: Optional[str] = typer.Option(None, "--config")):
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
        store = SQLiteStore(cfg.db_path)
        store.initialize()
        
        import asyncio
        detector = AnomalyDetector(cfg, asyncio.Queue(), store)
        
        with console.status("[bold green]Retraining model...[/bold green]"):
            num_samples = asyncio.run(detector.retrain())
            
        console.print(f"[green]Model retrained with {num_samples} samples.[/green]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

@app.command("dashboard")
def dashboard(config: Optional[str] = typer.Option(None, "--config")):
    cfg_path = config if config else CONFIG_PATH
    try:
        cfg = load_config(cfg_path)
        if not getattr(cfg, 'dashboard_enabled', False):
            console.print("[red]Enable dashboard in config.yaml: dashboard_enabled: true[/red]")
            raise typer.Exit(1)
            
        host = cfg.dashboard_host
        port = cfg.dashboard_port
        import webbrowser
        webbrowser.open(f"http://{host}:{port}")
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
