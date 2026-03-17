"""
c2_beacon.py — Command & Control Beaconing Simulator

Simulates malware-style C2 beaconing by sending periodic HTTP requests to
a remote "C2 server" at regular intervals with random jitter.

How it works
------------
1. At each beacon interval the module sends an HTTP GET (or POST with a
   small JSON payload) to the target URL — mimicking a compromised host
   checking in for commands.
2. Jitter (±30 % by default) is added to the interval so the timing is not
   perfectly periodic, which is how real malware families behave to evade
   simple interval-based detection.
3. Each request uses a randomly selected User-Agent string.

IDS relevance
-------------
Periodic outbound HTTP beacons — especially to unusual domains or IPs —
are a hallmark of RATs, botnets, and other C2 frameworks.  An IDS should
flag recurring requests with near-constant intervals even when jitter is
present.
"""

import json
import random
import time
import urllib.request
import urllib.error

from network_sim.modules.base import AttackModule
from network_sim.config import DEFAULT_BEACON_INTERVAL, BEACON_JITTER, USER_AGENTS


class C2BeaconSimulator(AttackModule):
    """Simulate periodic C2 beaconing behaviour."""

    MODULE_NAME = "C2Beacon"

    def __init__(self, target: str, port: int = 80, duration: int = 60, **kwargs):
        super().__init__(target, port, duration, **kwargs)
        self.interval = kwargs.get("interval", DEFAULT_BEACON_INTERVAL)
        self.jitter = kwargs.get("jitter", BEACON_JITTER)

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self) -> dict:
        url = (
            self.target
            if self.target.startswith("http")
            else f"http://{self.target}:{self.port}"
        )
        self.logger.info(
            "Starting C2 beaconing → %s  |  interval: %.1fs  |  jitter: ±%.0f%%  |  duration: %ds",
            url, self.interval, self.jitter * 100, self.duration,
        )
        self._start_timer()
        beacon_num = 0

        while not self.is_stopped and not self._time_exceeded():
            beacon_num += 1
            status = self._send_beacon(url, beacon_num)
            self.stats["packets_sent"] += 1
            self.stats["connections"] += 1

            if status >= 0:
                self.logger.info(
                    "Beacon #%d → HTTP %d  (elapsed %.1fs)",
                    beacon_num, status, self._elapsed(),
                )
            else:
                self.stats["errors"] += 1
                self.logger.warning(
                    "Beacon #%d → FAILED  (elapsed %.1fs)",
                    beacon_num, self._elapsed(),
                )

            # Sleep with jitter
            jittered = self.interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(max(0.1, jittered))

        self._stop_timer()
        self.logger.info(
            "Beaconing complete — %d beacons sent over %.1fs",
            beacon_num, self._elapsed() if self.stats["start_time"] else 0,
        )
        self.print_summary()
        return self.stats

    # ── Helpers ───────────────────────────────────────────────────────────

    def _send_beacon(self, url: str, seq: int) -> int:
        """Send a single beacon request.  Returns HTTP status or -1."""
        try:
            # Small JSON payload mimicking a check-in message
            payload = json.dumps({
                "id": f"host-{random.randint(1000,9999)}",
                "seq": seq,
                "ts": time.time(),
            }).encode("utf-8")

            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", random.choice(USER_AGENTS))

            with urllib.request.urlopen(req, timeout=5) as resp:
                self.stats["bytes_sent"] += len(payload)
                return resp.status
        except urllib.error.HTTPError as exc:
            self.stats["bytes_sent"] += len(payload) if 'payload' in dir() else 0
            return exc.code
        except Exception as exc:
            self.logger.debug("Beacon error: %s", exc)
            return -1
