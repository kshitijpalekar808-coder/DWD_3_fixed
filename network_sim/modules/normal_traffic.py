"""
normal_traffic.py — Normal Traffic Generator

Generates benign-looking HTTP traffic to simulate typical web browsing
behaviour.  This module is used as a **baseline** alongside attack modules
so that an IDS / anomaly-detection model can learn the difference between
normal and malicious traffic patterns.

How it works
------------
1. Picks a random URL from a configurable list.
2. Sends an HTTP GET with a randomised User-Agent.
3. Waits a random amount of time (1 – 5 s by default) to mimic human
   reading / browsing pace.
4. Repeats until the duration expires or the module is stopped.

IDS relevance
-------------
Provides a "negative class" signal for supervised ML models — traffic that
should NOT trigger alerts.  Mixing this with attack traffic tests the
model's ability to distinguish between benign and malicious flows.
"""

import random
import time
import urllib.request
import urllib.error

from network_sim.modules.base import AttackModule
from network_sim.config import NORMAL_URLS, NORMAL_DELAY_RANGE, USER_AGENTS


class NormalTrafficGenerator(AttackModule):
    """Generate benign web-browsing traffic as a baseline."""

    MODULE_NAME = "NormalTraffic"

    def __init__(self, target: str = "", port: int = 80, duration: int = 60, **kwargs):
        super().__init__(target or "various", port, duration, **kwargs)
        self.urls = kwargs.get("urls", NORMAL_URLS)

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self) -> dict:
        self.logger.info(
            "Starting normal traffic generation  |  URLs: %d  |  duration: %ds",
            len(self.urls), self.duration,
        )
        self._start_timer()
        request_num = 0

        while not self.is_stopped and not self._time_exceeded():
            request_num += 1
            url = random.choice(self.urls)
            status = self._browse(url)

            self.stats["packets_sent"] += 1
            self.stats["connections"] += 1

            if status >= 0:
                self.logger.info(
                    "Request #%d → GET %s → HTTP %d", request_num, url, status
                )
            else:
                self.stats["errors"] += 1
                self.logger.debug(
                    "Request #%d → GET %s → FAILED", request_num, url
                )

            # Human-like delay between page views
            time.sleep(random.uniform(*NORMAL_DELAY_RANGE))

        self._stop_timer()
        self.logger.info(
            "Normal traffic generation complete — %d requests over %.1fs",
            request_num, self._elapsed() if self.stats["start_time"] else 0,
        )
        self.print_summary()
        return self.stats

    # ── Helpers ───────────────────────────────────────────────────────────

    def _browse(self, url: str) -> int:
        """Send a single HTTP GET and return the status code (or -1)."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", random.choice(USER_AGENTS))
            req.add_header("Accept", "text/html,application/xhtml+xml")
            req.add_header("Accept-Language", "en-US,en;q=0.9")

            with urllib.request.urlopen(req, timeout=5) as resp:
                _ = resp.read()
                self.stats["bytes_sent"] += 0  # GET request — no body sent
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception as exc:
            self.logger.debug("Browse error for %s: %s", url, exc)
            return -1
