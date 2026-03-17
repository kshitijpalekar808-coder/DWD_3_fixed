"""
port_scan.py — Port Scan Simulator

Simulates port-scanning behaviour by attempting TCP connections across a range
of ports on the target host.  Two scan speeds are supported:

  • **fast**    — minimal delay between probes (≈ 10 ms)
  • **stealth** — randomised delay (0.5 – 2 s) to mimic slow, evasive scans

How it works
------------
For each port in the configured range the module calls ``socket.connect_ex()``
with a short timeout.  A return code of 0 means the port is *open*; any other
value means *closed / filtered*.  Every attempt is logged with its result.

IDS relevance
-------------
Rapid sequential connection attempts to many ports are a classic indicator of
reconnaissance.  The stealth mode lets you test whether an IDS can still detect
a scan that is deliberately slowed down.
"""

import random
import socket
import time

from network_sim.modules.base import AttackModule
from network_sim.config import FAST_DELAY, STEALTH_DELAY_RANGE, DEFAULT_TIMEOUT


class PortScanSimulator(AttackModule):
    """Simulate TCP port scanning against a target host."""

    MODULE_NAME = "PortScan"

    def __init__(self, target: str, port: int = 0, duration: int = 0, **kwargs):
        super().__init__(target, port, duration, **kwargs)
        self.speed = kwargs.get("speed", "fast")  # "fast" or "stealth"
        self.ports = self._parse_ports(kwargs.get("ports", "1-1024"))
        self.timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.open_ports: list[int] = []

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self) -> dict:
        self.logger.info(
            "Starting %s port scan on %s  |  ports: %d  |  speed: %s",
            self.speed.upper(),
            self.target,
            len(self.ports),
            self.speed,
        )
        self._start_timer()

        for port_number in self.ports:
            if self.is_stopped:
                break

            result = self._probe_port(port_number)
            self.stats["connections"] += 1
            self.stats["packets_sent"] += 1

            if result == 0:
                self.open_ports.append(port_number)
                self.logger.info("Port %5d — OPEN", port_number)
            else:
                self.logger.debug("Port %5d — closed / filtered", port_number)

            # Throttle according to scan speed
            delay = (
                FAST_DELAY
                if self.speed == "fast"
                else random.uniform(*STEALTH_DELAY_RANGE)
            )
            time.sleep(delay)

        self._stop_timer()
        self.logger.info(
            "Scan complete — %d open port(s) found out of %d probed",
            len(self.open_ports),
            self.stats["connections"],
        )
        self.print_summary()
        return self.stats

    # ── Helpers ───────────────────────────────────────────────────────────

    def _probe_port(self, port_number: int) -> int:
        """Attempt a TCP connect to *port_number* and return the OS error code
        (0 = open)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port_number))
            sock.close()
            return result
        except socket.error as exc:
            self.logger.debug("Socket error on port %d: %s", port_number, exc)
            self.stats["errors"] += 1
            return -1

    @staticmethod
    def _parse_ports(port_spec: str) -> list[int]:
        """Parse a port specification like ``"22,80,443"`` or ``"1-1024"``."""
        ports: list[int] = []
        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(part))
        return ports
