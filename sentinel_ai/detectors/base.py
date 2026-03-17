"""
detectors/base.py — Abstract base for all SentinelAI detectors.
"""
 
import threading
import time
from abc import ABC, abstractmethod
 
from shared_state import state, Alert
 
 
class BaseDetector(ABC):
    """
    Each detector runs in its own thread, polls shared_state.events on a
    configurable interval, and fires Alerts when its pattern is matched.
    """
 
    NAME     : str   = "Base"
    INTERVAL : float = 1.0      # seconds between analysis passes
 
    def __init__(self):
        self._alerted_keys: dict[str, float] = {}   # "ip:NAME" → last-alert timestamp
        self._cooldown = 15.0                        # seconds before re-alerting same IP+type
 
    # ── Public API ────────────────────────────────────────────────────────
 
    def start(self) -> None:
        t = threading.Thread(target=self._loop, daemon=True, name=f"det-{self.NAME}")
        t.start()
 
    # ── Internal ──────────────────────────────────────────────────────────
 
    def _loop(self) -> None:
        while True:
            try:
                self.analyse()
            except Exception:
                pass
            time.sleep(self.INTERVAL)
 
    @abstractmethod
    def analyse(self) -> None:
        """Inspect recent events and fire alerts as needed."""
        ...
 
    def _can_alert(self, ip: str) -> bool:
        key = f"{ip}:{self.NAME}"
        last = self._alerted_keys.get(key, 0)
        return (time.time() - last) >= self._cooldown
 
    def _fire(
        self,
        severity: str,
        attack_type: str,
        src_ip: str,
        description: str,
        auto_block: bool = True,
    ) -> None:
        if not self._can_alert(src_ip):
            return
        key = f"{src_ip}:{self.NAME}"
        self._alerted_keys[key] = time.time()
        blocked = auto_block and state.config.get("autoblock", True)
        alert = Alert(
            timestamp    = time.time(),
            severity     = severity,
            attack_type  = attack_type,
            src_ip       = src_ip,
            description  = description,
            auto_blocked = blocked,
        )
        state.add_alert(alert)