"""
data_exfiltration.py — Data Exfiltration Simulator

Simulates suspicious outbound data transfer by sending randomly-generated
data chunks to a remote server via HTTP POST or raw TCP.

How it works
------------
1. Generates random binary data of a configurable chunk size.
2. Sends each chunk to the target over HTTP POST (or raw TCP if no HTTP
   endpoint is available).
3. Repeats for a configurable number of chunks or until the duration expires.

IDS relevance
-------------
Large volumes of outbound data — especially binary / random entropy —
from a host that normally produces little egress traffic is a strong
indicator of data exfiltration by malware or an insider threat.
"""

import os
import random
import socket
import time
import urllib.request
import urllib.error

from network_sim.modules.base import AttackModule
from network_sim.config import DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_COUNT, USER_AGENTS


class DataExfiltrationSimulator(AttackModule):
    """Simulate suspicious outbound data exfiltration."""

    MODULE_NAME = "DataExfil"

    def __init__(self, target: str, port: int = 80, duration: int = 30, **kwargs):
        super().__init__(target, port, duration, **kwargs)
        self.chunk_size = kwargs.get("chunk_size", DEFAULT_CHUNK_SIZE)
        self.chunk_count = kwargs.get("chunk_count", DEFAULT_CHUNK_COUNT)
        self.protocol = kwargs.get("protocol", "http")  # "http" or "tcp"

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self) -> dict:
        self.logger.info(
            "Starting data exfiltration → %s:%d  |  protocol: %s  |  "
            "chunk_size: %d B  |  chunks: %d",
            self.target, self.port, self.protocol.upper(),
            self.chunk_size, self.chunk_count,
        )
        self._start_timer()

        for i in range(1, self.chunk_count + 1):
            if self.is_stopped or self._time_exceeded():
                break

            payload = os.urandom(self.chunk_size)  # random binary data

            if self.protocol == "tcp":
                success = self._send_tcp(payload)
            else:
                success = self._send_http(payload)

            self.stats["packets_sent"] += 1
            if success:
                self.stats["bytes_sent"] += len(payload)
                self.stats["connections"] += 1
                self.logger.info(
                    "Chunk %d/%d sent — %d bytes", i, self.chunk_count, len(payload)
                )
            else:
                self.stats["errors"] += 1
                self.logger.warning("Chunk %d/%d FAILED", i, self.chunk_count)

            # Small random delay to look slightly more natural
            time.sleep(random.uniform(0.05, 0.3))

        self._stop_timer()
        self.logger.info(
            "Exfiltration complete — %d bytes sent across %d chunk(s)",
            self.stats["bytes_sent"],
            self.stats["packets_sent"],
        )
        self.print_summary()
        return self.stats

    # ── Transport methods ─────────────────────────────────────────────────

    def _send_http(self, data: bytes) -> bool:
        """POST data to the target HTTP endpoint."""
        try:
            url = (
                self.target
                if self.target.startswith("http")
                else f"http://{self.target}:{self.port}"
            )
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/octet-stream")
            req.add_header("User-Agent", random.choice(USER_AGENTS))
            with urllib.request.urlopen(req, timeout=5) as resp:
                _ = resp.read()
            return True
        except Exception as exc:
            self.logger.debug("HTTP send error: %s", exc)
            return False

    def _send_tcp(self, data: bytes) -> bool:
        """Send raw bytes over a TCP socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            sock.sendall(data)
            sock.close()
            return True
        except Exception as exc:
            self.logger.debug("TCP send error: %s", exc)
            return False
