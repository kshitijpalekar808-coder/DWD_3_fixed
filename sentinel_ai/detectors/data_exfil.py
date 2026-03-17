"""
detectors/data_exfil.py — Detects DataExfiltrationSimulator traffic.
"""
 
import time
from collections import defaultdict
 
from shared_state import state
from detectors.base import BaseDetector
 
BYTES_THRESHOLD = 4 * 1024    # 4 KB
COUNT_THRESHOLD = 4
TIME_WINDOW     = 30.0
 
 
class DataExfilDetector(BaseDetector):
    NAME     = "Data Exfil"
    INTERVAL = 1.0
 
    def analyse(self) -> None:
        bytes_by_ip: dict[str, int] = defaultdict(int)
        count_by_ip: dict[str, int] = defaultdict(int)
 
        for evt in state.recent_events(TIME_WINDOW):
            if evt.event_type != "http_request" or evt.method != "POST":
                continue
            is_binary = "octet-stream" in evt.content_type
            is_large  = evt.content_length > 256
            is_target = any(p in (evt.path or "") for p in ("/upload", "/data"))
 
            if is_binary or (is_large and is_target):
                bytes_by_ip[evt.src_ip] += evt.content_length
                count_by_ip[evt.src_ip] += 1
 
        for ip in set(bytes_by_ip) | set(count_by_ip):
            total = bytes_by_ip[ip]
            count = count_by_ip[ip]
            if total >= BYTES_THRESHOLD or count >= COUNT_THRESHOLD:
                self._fire(
                    severity    = "HIGH",
                    attack_type = "Data Exfiltration",
                    src_ip      = ip,
                    description = (
                        f"Suspicious outbound data — {count} binary POST(s), "
                        f"{total / 1024:.1f} KB transferred in {TIME_WINDOW:.0f}s"
                    ),
                    auto_block  = True,
                )
 