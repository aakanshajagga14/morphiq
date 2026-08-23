from __future__ import annotations

import asyncio

from morphiq.pipeline.log_tailer import LogTailer


def test_parses_nginx_combined_log(config_factory, store):
    config = config_factory(log_format_preset="nginx_combined")
    tailer = LogTailer(config, asyncio.Queue(), store)
    line = (
        '203.0.113.8 - - [01/Jan/2026:12:00:00 +0000] '
        '"GET /search?q=morphiq HTTP/1.1" 200 512 "-" "pytest-agent"'
    )

    entry = tailer._parse_line(line)

    assert entry is not None
    assert entry.effective_ip == "203.0.113.8"
    assert entry.path == "/search"
    assert entry.query_string == "q=morphiq"
    assert entry.status_code == 200
