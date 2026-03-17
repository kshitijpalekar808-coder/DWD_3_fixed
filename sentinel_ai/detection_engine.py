"""
detection_engine.py — Starts all detector threads.
"""

from detectors.port_scan     import PortScanDetector
from detectors.brute_force   import BruteForceDetector
from detectors.traffic_flood import TrafficFloodDetector
from detectors.data_exfil    import DataExfilDetector
from detectors.c2_beacon     import C2BeaconDetector

DETECTORS = [
    PortScanDetector,
    BruteForceDetector,
    TrafficFloodDetector,
    DataExfilDetector,
    C2BeaconDetector,
]


def start_detection() -> None:
    """Instantiate and start every detector.  Blocks forever."""
    import time
    for cls in DETECTORS:
        cls().start()
    while True:
        time.sleep(60)
