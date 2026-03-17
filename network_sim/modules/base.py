"""
base.py — Abstract base class for all attack simulation modules.

Every module inherits from ``AttackModule`` and must implement ``run()``.
The base class provides:
  • A shared logger
  • A ``stats`` dictionary for tracking metrics
  • A threading ``Event`` for graceful shutdown via ``stop()``
"""

import threading
import time
from abc import ABC, abstractmethod

from network_sim.logger import get_logger


class AttackModule(ABC):
    """Base class that all attack / traffic modules must extend."""

    # Human-readable name shown in logs and summaries
    MODULE_NAME: str = "base"

    def __init__(self, target: str, port: int = 80, duration: int = 30, **kwargs):
        """
        Parameters
        ----------
        target : str
            Target host or URL.
        port : int
            Target port (where applicable).
        duration : int
            Maximum runtime in seconds (0 = unlimited / module decides).
        **kwargs :
            Module-specific options.
        """
        self.target = target
        self.port = port
        self.duration = duration
        self.options = kwargs
        self.logger = get_logger(self.MODULE_NAME)

        # Metrics counters — each module updates these as it runs
        self.stats: dict = {
            "packets_sent": 0,
            "connections": 0,
            "errors": 0,
            "bytes_sent": 0,
            "start_time": None,
            "end_time": None,
        }

        # Threading event to signal graceful shutdown
        self._stop_event = threading.Event()

    # ── Public API ────────────────────────────────────────────────────────

    @abstractmethod
    def run(self) -> dict:
        """Execute the simulation and return the ``stats`` dict on completion."""
        ...

    def stop(self) -> None:
        """Signal the module to stop gracefully."""
        self.logger.info("Stop signal received — shutting down …")
        self._stop_event.set()

    @property
    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _start_timer(self) -> None:
        self.stats["start_time"] = time.time()

    def _stop_timer(self) -> None:
        self.stats["end_time"] = time.time()

    def _elapsed(self) -> float:
        """Seconds elapsed since ``_start_timer()`` was called."""
        if self.stats["start_time"] is None:
            return 0.0
        return time.time() - self.stats["start_time"]

    def _time_exceeded(self) -> bool:
        """Return True if the configured duration has been exceeded."""
        if self.duration <= 0:
            return False
        return self._elapsed() >= self.duration

    def print_summary(self) -> None:
        """Pretty-print a run summary to the console."""
        elapsed = (self.stats["end_time"] or time.time()) - (
            self.stats["start_time"] or time.time()
        )
        self.logger.info("=" * 60)
        self.logger.info("  SIMULATION SUMMARY — %s", self.MODULE_NAME)
        self.logger.info("=" * 60)
        self.logger.info("  Target         : %s:%s", self.target, self.port)
        self.logger.info("  Duration       : %.2f s", elapsed)
        self.logger.info("  Packets sent   : %d", self.stats["packets_sent"])
        self.logger.info("  Connections    : %d", self.stats["connections"])
        self.logger.info("  Bytes sent     : %d", self.stats["bytes_sent"])
        self.logger.info("  Errors         : %d", self.stats["errors"])
        self.logger.info("=" * 60)
