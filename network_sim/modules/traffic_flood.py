"""
traffic_flood.py — Traffic Flood / Mini-DDoS Simulator

Generates a high volume of HTTP GET requests (or raw TCP connections) against
a target server to simulate volumetric denial-of-service behaviour.

How it works
------------
1. Spawns a configurable number of worker threads (default 10).
2. Each thread fires HTTP GET requests as fast as possible, up to the
   configured requests-per-second (RPS) cap.
3. Runs for a configurable duration, then stops all threads gracefully.

IDS relevance
-------------
A sudden spike in inbound request volume — especially from a single source —
is a primary indicator of a DoS / DDoS attack.  The configurable RPS lets you
test detection thresholds.
"""

import random
import threading
import time
import urllib.request
import urllib.error

from network_sim.modules.base import AttackModule
from network_sim.config import DEFAULT_RPS, FLOOD_THREADS, USER_AGENTS


class TrafficFloodSimulator(AttackModule):
    """Simulate high-frequency HTTP / TCP traffic flood."""

    MODULE_NAME = "TrafficFlood"

    def __init__(self, target: str, port: int = 80, duration: int = 30, **kwargs):
        super().__init__(target, port, duration, **kwargs)
        self.rps = kwargs.get("rps", DEFAULT_RPS)
        self.threads_count = kwargs.get("threads", FLOOD_THREADS)
        self._lock = threading.Lock()

    # ── Main entry ────────────────────────────────────────────────────────

    def run(self) -> dict:
        url = self.target if self.target.startswith("http") else f"http://{self.target}:{self.port}"
        self.logger.info(
            "Starting traffic flood → %s  |  target RPS: %d  |  threads: %d  |  duration: %ds",
            url, self.rps, self.threads_count, self.duration,
        )
        self._start_timer()

        # Per-thread RPS share
        per_thread_rps = max(1, self.rps // self.threads_count)

        workers = []
        for i in range(self.threads_count):
            t = threading.Thread(
                target=self._worker, args=(url, per_thread_rps), daemon=True, name=f"flood-{i}"
            )
            workers.append(t)
            t.start()

        # Wait for duration or until stopped
        try:
            end_time = time.time() + self.duration
            while time.time() < end_time and not self.is_stopped:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

        for t in workers:
            t.join(timeout=3)

        self._stop_timer()
        self.logger.info(
            "Flood complete — %d requests sent, %d errors",
            self.stats["packets_sent"],
            self.stats["errors"],
        )
        self.print_summary()
        return self.stats

    # ── Worker thread ─────────────────────────────────────────────────────

    def _worker(self, url: str, target_rps: int) -> None:
        """Send HTTP GETs at roughly *target_rps* until stopped."""
        interval = 1.0 / target_rps if target_rps > 0 else 0.01

        while not self.is_stopped:
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", random.choice(USER_AGENTS))
                with urllib.request.urlopen(req, timeout=3) as resp:
                    _ = resp.read()

                with self._lock:
                    self.stats["packets_sent"] += 1
                    self.stats["connections"] += 1
            except Exception:
                with self._lock:
                    self.stats["packets_sent"] += 1
                    self.stats["errors"] += 1

            time.sleep(interval)
