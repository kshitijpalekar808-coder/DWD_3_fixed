"""
shared_state.py — Thread-safe event bus shared across all SentinelAI components.
"""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class NetworkEvent:
    """Every inbound connection or HTTP request becomes a NetworkEvent."""
    timestamp: float
    src_ip: str
    event_type: str          # 'http_request' | 'honeypot_connect'
    port: int
    method: Optional[str] = None
    path: Optional[str] = None
    content_length: int = 0
    content_type: str = ""
    user_agent: str = ""
    status_code: int = 200


@dataclass
class Alert:
    """Fired by a detector when an attack pattern is confirmed."""
    timestamp: float
    severity: str            # 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    attack_type: str         # e.g. 'Port Scan', 'Brute Force', …
    src_ip: str
    description: str
    auto_blocked: bool = False


# ── Singleton shared state ────────────────────────────────────────────────────

class SharedState:
    def __init__(self):
        self.lock = threading.Lock()

        # Ring buffers — keep memory bounded
        self.events: deque[NetworkEvent] = deque(maxlen=50_000)
        self.alerts: deque[Alert]        = deque(maxlen=1_000)

        self.blocked_ips: set[str] = set()
        self.config: dict = {"autoblock": True, "server_port": 5000}

        self.stats = {
            "total_requests":   0,
            "blocked_requests": 0,
            "total_alerts":     0,
            "alerts_by_type":   {},
            "start_time":       time.time(),
        }

    # ── Write helpers ─────────────────────────────────────────────────────

    def add_event(self, event: NetworkEvent) -> None:
        with self.lock:
            self.events.append(event)
            self.stats["total_requests"] += 1

    def add_alert(self, alert: Alert) -> None:
        with self.lock:
            self.alerts.append(alert)
            self.stats["total_alerts"] += 1
            t = alert.attack_type
            self.stats["alerts_by_type"][t] = self.stats["alerts_by_type"].get(t, 0) + 1
            if alert.auto_blocked and self.config.get("autoblock", True):
                self.blocked_ips.add(alert.src_ip)

    def block_ip(self, ip: str) -> None:
        with self.lock:
            self.blocked_ips.add(ip)

    # ── Read helpers ──────────────────────────────────────────────────────

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def recent_events(self, seconds: float = 30) -> list[NetworkEvent]:
        cutoff = time.time() - seconds
        with self.lock:
            return [e for e in self.events if e.timestamp >= cutoff]

    def recent_alerts(self, n: int = 30) -> list[Alert]:
        with self.lock:
            return list(self.alerts)[-n:]

    def snapshot_stats(self) -> dict:
        with self.lock:
            return dict(self.stats)


# Module-level singleton — import this everywhere
state = SharedState()
