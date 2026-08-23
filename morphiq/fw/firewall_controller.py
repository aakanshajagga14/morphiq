from __future__ import annotations
import ipaddress
import logging
import subprocess
import sys
import os
import ctypes
from datetime import datetime, timezone, timedelta
from typing import Optional

from morphiq.config import Config
from morphiq.store.sqlite_store import SQLiteStore
from morphiq.models import BanRecord

logger = logging.getLogger(__name__)

class FirewallController:
    _MANDATORY_WHITELIST = frozenset(['127.0.0.1', '::1', '0:0:0:0:0:0:0:1'])

    def __init__(self, config: Config, store: SQLiteStore):
        self.config = config
        self.store = store

    def is_whitelisted(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        if ip in self._MANDATORY_WHITELIST:
            return True

        for entry in self.config.whitelist:
            if ip == entry:
                return True
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if ip_obj in network:
                    return True
            except ValueError:
                pass

        return False

    def block(self, ip: str, reason: str, duration_s: int) -> bool:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False

        if self.is_whitelisted(ip):
            logger.info(f"Whitelist-protection: skipped blocking protected IP {ip}")
            return False

        active_bans = self.store.get_active_bans()
        if any(ban.ip == ip for ban in active_bans):
            logger.info(f"IP {ip} is already banned.")
            return True

        cmd = self._block_cmd(ip)
        if cmd is not None:
            if not self._run_cmd(cmd):
                return False

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=duration_s)
        record = BanRecord(
            ip=ip,
            reason=reason,
            created_at=now,
            expires_at=expires_at
        )
        self.store.insert_ban(record)
        return True

    def unblock(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False

        cmd = self._unblock_cmd(ip)
        if cmd is not None:
            if not self._run_cmd(cmd):
                return False

        self.store.delete_ban(ip)
        return True

    def restore_bans(self) -> None:
        active_bans = self.store.get_active_bans()
        now = datetime.now(timezone.utc)
        valid_bans = [ban for ban in active_bans if ban.expires_at > now]

        for ban in valid_bans:
            cmd = self._block_cmd(ban.ip)
            if cmd is not None:
                self._run_cmd(cmd)
            logger.info(f"Restored ban for {ban.ip}")

    def _block_cmd(self, ip: str) -> Optional[list[str]]:
        if self.config.fw_backend == "windows":
            return ["netsh", "advfirewall", "firewall", "add", "rule", f"name=MorphIQ-Block-{ip}", "dir=in", "action=block", f"remoteip={ip}", "protocol=any"]
        elif self.config.fw_backend == "iptables":
            return ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        elif self.config.fw_backend == "ufw":
            return ["ufw", "insert", "1", "deny", "from", ip]
        elif self.config.fw_backend == "mock":
            return None
        return None

    def _unblock_cmd(self, ip: str) -> Optional[list[str]]:
        if self.config.fw_backend == "windows":
            return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=MorphIQ-Block-{ip}"]
        elif self.config.fw_backend == "iptables":
            return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        elif self.config.fw_backend == "ufw":
            return ["ufw", "delete", "deny", "from", ip]
        elif self.config.fw_backend == "mock":
            return None
        return None

    def _run_cmd(self, cmd: list[str]) -> bool:
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, shell=False)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {cmd}. Error: {e.stderr}")
            return False

    @staticmethod
    def check_admin() -> bool:
        if sys.platform == 'win32':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0
