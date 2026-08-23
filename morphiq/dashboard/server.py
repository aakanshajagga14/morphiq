from __future__ import annotations
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Any, Dict

from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import Response, StreamResponse

from morphiq.config import Config
from morphiq.store.sqlite_store import SQLiteStore
from morphiq.fw.firewall_controller import FirewallController

logger = logging.getLogger(__name__)

def json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default json code"""
    import dataclasses
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

def dumps(obj: Any) -> str:
    return json.dumps(obj, default=json_serial)

class DashboardServer:
    def __init__(self, config: Config, store: SQLiteStore, fw: FirewallController):
        self.config = config
        self.store = store
        self.fw = fw
        self.app = web.Application(middlewares=[self.cors_middleware])
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        
        self.static_dir = Path(__file__).parent / 'static'
        self.setup_routes()
        
    @web.middleware
    async def cors_middleware(self, request: Request, handler: Any) -> StreamResponse:
        response = await handler(request)
        if isinstance(response, StreamResponse):
            port = self.config.dashboard_port if hasattr(self.config, 'dashboard_port') else 8080
            response.headers['Access-Control-Allow-Origin'] = f"http://localhost:{port}"
            response.headers['Access-Control-Allow-Methods'] = "GET, POST, OPTIONS"
            response.headers['Access-Control-Allow-Headers'] = "Content-Type"
        return response

    def setup_routes(self) -> None:
        self.app.router.add_get('/', self.handle_index)
        self.app.router.add_get('/api/status', self.handle_status)
        self.app.router.add_get('/api/bans', self.handle_bans)
        self.app.router.add_get('/api/audit', self.handle_audit)
        self.app.router.add_get('/api/probes', self.handle_probes)
        self.app.router.add_post('/api/unban', self.handle_unban)
        self.app.router.add_options('/api/unban', self.handle_options)
        self.app.router.add_get('/api/stream', self.handle_stream)
        
        # Static files fallback
        if self.static_dir.exists():
            self.app.router.add_static('/static/', path=self.static_dir, name='static')

    async def handle_options(self, request: Request) -> Response:
        return Response(status=204)

    async def handle_index(self, request: Request) -> Response:
        index_file = self.static_dir / 'index.html'
        if index_file.exists():
            return web.FileResponse(index_file)
        return web.Response(text="Dashboard UI not found", status=404)

    def is_daemon_alive(self) -> bool:
        pid_file = Path(self.config.pid_file_path) if hasattr(self.config, 'pid_file_path') else Path("morphiq.pid")
        if not pid_file.exists():
            return False
        try:
            pid = int(pid_file.read_text().strip())
            # Simple check if process exists (works on Windows via os.kill sending 0 is not supported, 
            # so we just try to read process via psutil if available, otherwise just assume true if pid exists,
            # but standard trick on Windows is trying to open handle or assume alive if file recent)
            # We'll use a basic check or just return True if pid exists and modified recently.
            if os.name == 'nt':
                import ctypes
                kernel32 = ctypes.windll.kernel32
                SYNCHRONIZE = 0x00100000
                process = kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
                if process != 0:
                    kernel32.CloseHandle(process)
                    return True
                return False
            else:
                os.kill(pid, 0)
                return True
        except Exception:
            return False

    async def handle_status(self, request: Request) -> Response:
        stats = self.store.get_stats()
        active_bans = len(self.store.get_active_bans())
        return web.json_response({
            "daemon_alive": self.is_daemon_alive(),
            "stats": stats,
            "active_bans_count": active_bans
        }, dumps=dumps)

    async def handle_bans(self, request: Request) -> Response:
        bans = self.store.get_active_bans()
        return web.json_response([ban.__dict__ for ban in bans], dumps=dumps)

    async def handle_audit(self, request: Request) -> Response:
        limit = int(request.query.get('limit', 50))
        audits = self.store.get_recent_audit(n=limit)
        return web.json_response([a.__dict__ for a in audits], dumps=dumps)

    async def handle_probes(self, request: Request) -> Response:
        limit = int(request.query.get('limit', 20))
        # Assuming store has get_recent_probes
        probes = getattr(self.store, 'get_recent_probes', lambda limit: [])(limit)
        return web.json_response(probes, dumps=dumps)

    async def handle_unban(self, request: Request) -> Response:
        try:
            data = await request.json()
            ip = data.get("ip")
            if not ip:
                return web.json_response({"success": False, "message": "IP is required"}, status=400)
            
            # Validate basic IP string
            import ipaddress
            ipaddress.ip_address(ip)
            
            # Unblock
            success = self.fw.unblock(ip)
            if success:
                self.store.delete_ban(ip)
                return web.json_response({"success": True, "message": f"IP {ip} unbanned"})
            else:
                return web.json_response({"success": False, "message": "Failed to unban IP in firewall"}, status=500)
                
        except ValueError:
            return web.json_response({"success": False, "message": "Invalid IP address"}, status=400)
        except Exception as e:
            logger.error(f"Error unbanning IP: {e}")
            return web.json_response({"success": False, "message": str(e)}, status=500)

    async def handle_stream(self, request: Request) -> StreamResponse:
        response = web.StreamResponse(
            status=200,
            reason='OK',
            headers={
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*'
            }
        )
        await response.prepare(request)
        
        last_audit_id = 0
        audits = self.store.get_recent_audit(n=1)
        if audits:
            last_audit_id = getattr(audits[0], 'id', 0)

        try:
            while True:
                stats = self.store.get_stats()
                
                # Fetch new audits
                recent_audits = self.store.get_recent_audit(n=10)
                new_audits = []
                for a in recent_audits:
                    a_id = getattr(a, 'id', 0)
                    if a_id > last_audit_id:
                        new_audits.append(a)
                
                if new_audits:
                    last_audit_id = max(getattr(a, 'id', 0) for a in new_audits)
                    
                data = {
                    "stats": stats,
                    "new_audits": [a.__dict__ for a in new_audits]
                }
                
                await response.write(f"data: {dumps(data)}\n\n".encode('utf-8'))
                await asyncio.sleep(2.0)
        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            pass
        finally:
            return response

    async def start(self) -> None:
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        host = getattr(self.config, 'dashboard_host', '127.0.0.1')
        port = getattr(self.config, 'dashboard_port', 8080)
        
        try:
            self.site = web.TCPSite(self.runner, host, port)
            await self.site.start()
            logger.info(f"Dashboard server started at http://{host}:{port}")
        except OSError as e:
            logger.error(f"Dashboard failed to bind on {host}:{port} — {e}. Is another instance running? Change dashboard_port in config.yaml.")

    async def stop(self) -> None:
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        logger.info("Dashboard server stopped")
