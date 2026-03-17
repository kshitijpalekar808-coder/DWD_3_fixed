"""
detectors/c2_beacon.py — Detects C2BeaconSimulator traffic.
"""
 
import time
import statistics
from collections import defaultdict
 
from shared_state import state
from detectors.base import BaseDetector
 
MIN_BEACONS  = 3
TIME_WINDOW  = 60.0
CV_THRESHOLD = 0.55
 
 
class C2BeaconDetector(BaseDetector):
    NAME     = "C2 Beacon"
    INTERVAL = 2.0
 
    def analyse(self) -> None:
        ts_by_ip: dict[str, list[float]] = defaultdict(list)
 
        for evt in state.recent_events(TIME_WINDOW):
            if evt.event_type != "http_request":
                continue
            is_beacon_path = evt.path in ("/beacon", "/", "") or evt.path is None
            is_post = evt.method == "POST"
            if is_post and is_beacon_path:
                ts_by_ip[evt.src_ip].append(evt.timestamp)
 
        for ip, timestamps in ts_by_ip.items():
            if len(timestamps) < MIN_BEACONS:
                continue
 
            timestamps.sort()
            intervals = [
                timestamps[i+1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]
 
            if len(intervals) < 2:
                continue
 
            mean = statistics.mean(intervals)
            if mean < 0.5:
                continue
 
            stdev = statistics.stdev(intervals)
            cv = stdev / mean if mean > 0 else 1.0
 
            if cv <= CV_THRESHOLD:
                self._fire(
                    severity    = "CRITICAL",
                    attack_type = "C2 Beaconing",
                    src_ip      = ip,
                    description = (
                        f"Malware beacon pattern — {len(timestamps)} check-ins, "
                        f"interval μ={mean:.1f}s σ={stdev:.2f}s CV={cv:.2f} "
                        f"(CV<{CV_THRESHOLD} = suspiciously periodic)"
                    ),
                    auto_block  = True,
                )
 