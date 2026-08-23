import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiofiles

from morphiq.config import Config
from morphiq.models import LogEntry
from morphiq.store.sqlite_store import SQLiteStore

LOG_PRESETS = {
    'nginx_combined': re.compile(
        r'(?P<source_ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+)(?: (?P<protocol>\S+))?" '
        r'(?P<status_code>\d{3}) (?P<bytes_sent>\d+|-) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    ),
    'apache_combined': re.compile(
        r'(?P<source_ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+)(?: (?P<protocol>\S+))?" '
        r'(?P<status_code>\d{3}) (?P<bytes_sent>\d+|-) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
}

class LogTailer:
    def __init__(self, config: Config, output_queue: asyncio.Queue, store: SQLiteStore):
        self.config = config
        self.output_queue = output_queue
        self.store = store
        self.parse_error_count = 0
        self._stop_event = asyncio.Event()

        if self.config.log_format_preset == 'custom':
            self.regex = re.compile(self.config.log_format_regex)
        else:
            self.regex = LOG_PRESETS.get(self.config.log_format_preset)

    async def start(self) -> None:
        path = Path(self.config.log_file_path)
        while not self._stop_event.is_set():
            if not path.exists():
                logging.warning(f"Log file not found: {path}")
                await asyncio.sleep(5)
                continue

            try:
                inode = os.stat(path).st_ino
                size = os.stat(path).st_size
                
                async with aiofiles.open(path, mode='r') as f:
                    await f.seek(0, os.SEEK_END)
                    while not self._stop_event.is_set():
                        line = await f.readline()
                        if not line:
                            try:
                                current_stat = os.stat(path)
                                if current_stat.st_ino != inode or current_stat.st_size < size:
                                    break
                                size = current_stat.st_size
                            except FileNotFoundError:
                                break
                                
                            await asyncio.sleep(0.1)
                            continue
                            
                        entry = self._parse_line(line.strip())
                        if entry:
                            self.store.insert_traffic(
                                entry, self.config.traffic_retention_s
                            )
                            self.store.increment_stat("total_parsed")
                            await self.output_queue.put(entry)
                        else:
                            self.parse_error_count += 1
            except Exception as e:
                logging.error(f"Error tailing log file: {e}")
                await asyncio.sleep(5)

    async def stop(self) -> None:
        self._stop_event.set()

    def _parse_line(self, line: str) -> Optional[LogEntry]:
        if not line or line.startswith('#'):
            return None

        if self.config.log_format_preset == 'caddy_json':
            try:
                data = json.loads(line)
                request = data.get('request', {})
                source_ip = request.get('remote_ip', '')
                method = request.get('method', '')
                path = request.get('uri', '')
                query_string = request.get('query', '')
                status_code = int(data.get('status', 0))
                user_agent = request.get('headers', {}).get('User-Agent', [''])[0]
                bytes_sent = int(data.get('size', 0))
                
                effective_ip = source_ip
                if self.config.effective_ip_header:
                    header_val = request.get('headers', {}).get(self.config.effective_ip_header, [])
                    if header_val:
                        effective_ip = header_val[0].split(',')[0].strip()
                    else:
                        header_match = re.search(rf'{self.config.effective_ip_header}: (\S+)', line, re.IGNORECASE)
                        if header_match:
                            effective_ip = header_match.group(1).split(',')[0].strip()

                return LogEntry(
                    source_ip=source_ip,
                    effective_ip=effective_ip,
                    method=method,
                    path=path,
                    query_string=query_string,
                    status_code=status_code,
                    user_agent=user_agent,
                    bytes_sent=bytes_sent,
                    raw_line=line,
                    timestamp=datetime.now(timezone.utc)
                )
            except Exception:
                return None
                
        elif self.config.log_format_preset == 'iis_w3c':
            parts = line.split('\t')
            if len(parts) < 9:
                return None
            try:
                source_ip = parts[2]
                method = parts[3]
                path = parts[4]
                query_string = parts[5] if parts[5] != '-' else ''
                status_code = int(parts[6])
                user_agent = parts[7].replace('+', ' ')
                bytes_sent = int(parts[8]) if parts[8] != '-' else 0

                effective_ip = source_ip
                if self.config.effective_ip_header:
                    header_match = re.search(rf'{self.config.effective_ip_header}: (\S+)', line, re.IGNORECASE)
                    if header_match:
                        effective_ip = header_match.group(1).split(',')[0].strip()

                return LogEntry(
                    source_ip=source_ip,
                    effective_ip=effective_ip,
                    method=method,
                    path=path,
                    query_string=query_string,
                    status_code=status_code,
                    user_agent=user_agent,
                    bytes_sent=bytes_sent,
                    raw_line=line,
                    timestamp=datetime.now(timezone.utc)
                )
            except Exception:
                return None
        else:
            if not self.regex:
                return None
            match = self.regex.match(line)
            if not match:
                return None
            
            d = match.groupdict()
            source_ip = d.get('source_ip', '')
            method = d.get('method', '')
            path_full = d.get('path', '')
            if '?' in path_full:
                path, query_string = path_full.split('?', 1)
            else:
                path = path_full
                query_string = d.get('query_string', '')
                
            try:
                status_code = int(d.get('status_code', 0))
            except ValueError:
                status_code = 0
                
            try:
                bytes_sent = int(d.get('bytes_sent', 0))
            except ValueError:
                bytes_sent = 0
                
            user_agent = d.get('user_agent', '')
            
            effective_ip = source_ip
            if self.config.effective_ip_header:
                header_match = re.search(rf'{self.config.effective_ip_header}: (\S+)', line, re.IGNORECASE)
                if header_match:
                    effective_ip = header_match.group(1).split(',')[0].strip()
                elif self.config.effective_ip_header in d:
                    effective_ip = d[self.config.effective_ip_header]

            return LogEntry(
                source_ip=source_ip,
                effective_ip=effective_ip,
                method=method,
                path=path,
                query_string=query_string,
                status_code=status_code,
                user_agent=user_agent,
                bytes_sent=bytes_sent,
                raw_line=line,
                timestamp=datetime.now(timezone.utc)
            )
