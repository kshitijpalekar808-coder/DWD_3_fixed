"""
detectors/port_scan.py — Detects PortScanSimulator traffic.

Signature: a single IP connects to 5+ distinct ports (honeypot) within 8 s.
"""

import time
from collections import defaultdict

from shared_state import state
from detectors.base import BaseDetector


class PortScanDetector(BaseDetector):
    NAME     = "Port Scan"
    INTERVAL = 0.8

    PORT_THRESHOLD = 5     # distinct ports
    TIME_WINDOW    = 8.0   # seconds

    def analyse(self) -> None:
        cutoff = time.time() - self.TIME_WINDOW
        # Group honeypot events by source IP
        ports_by_ip: dict[str, set[int]] = defaultdict(set)

        for evt in state.recent_events(self.TIME_WINDOW):
            if evt.event_type != "honeypot_connect":
                continue
            if evt.timestamp >= cutoff:
                ports_by_ip[evt.src_ip].add(evt.port)

        for ip, ports in ports_by_ip.items():
            if len(ports) >= self.PORT_THRESHOLD:
                self._fire(
                    severity    = "HIGH",
                    attack_type = "Port Scan",
                    src_ip      = ip,
                    description = (
                        f"Reconnaissance detected — {len(ports)} ports probed "
                        f"in {self.TIME_WINDOW:.0f}s "
                        f"(ports: {', '.join(str(p) for p in sorted(ports)[:8])}…)"
                    ),
                    auto_block  = True,
                )
