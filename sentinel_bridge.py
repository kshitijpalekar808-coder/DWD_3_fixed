"""
sentinel_bridge.py — Connects SentinelAI to DWD_3's SocketIO.

TWO MODES — auto-detected:

MODE A (recommended): SentinelAI starts INSIDE app.py
  - sentinel_ai/ folder sits next to app.py
  - Just run: python app.py
  - SentinelAI target server starts on port 6100 automatically

MODE B (standalone): You run sentinel_ai.py separately first
  - Terminal 1: cd sentinel_ai && python sentinel_ai.py --port 6100 --no-autoblock
  - Terminal 2: python app.py
  - Bridge connects to the already-running shared_state via import

In both modes the bridge polls shared_state every 0.5s and forwards
every new Alert to all browsers via SocketIO (sentinel_alert event).

Attack endpoints (port 6100):
  /          -> traffic flood
  /login     -> brute force
  /beacon    -> C2 beacon
  /upload    -> data exfil
  TCP ports  -> honeypot (port scan)
"""

import sys, os, time, threading, logging

logger = logging.getLogger("dwd.sentinel_bridge")

_HERE = os.path.dirname(os.path.abspath(__file__))
_SENTINEL_DIR = os.path.join(_HERE, "sentinel_ai")

# Always put sentinel_ai/ on sys.path so shared_state is importable
if _SENTINEL_DIR not in sys.path:
    sys.path.insert(0, _SENTINEL_DIR)

# Correct HTTP paths per attack type (SentinelAI target_server.py endpoints)
SENTINEL_PATHS = {
    "brute_force":       "/login",
    "c2_beacon":         "/beacon",
    "data_exfiltration": "/upload",
    "traffic_flood":     "/",
    "port_scan":         None,  # raw TCP
}


def resolve_target(attack_type: str, base_url: str, sentinel_port: int) -> str:
    """Return the full URL an attack module should hit on SentinelAI."""
    path = SENTINEL_PATHS.get(attack_type)
    if not base_url.startswith("http"):
        base_url = f"http://{base_url}:{sentinel_port}"
    if path and path != "/":
        from urllib.parse import urlparse as _up
        if _up(base_url).path in ("", "/"):
            return base_url.rstrip("/") + path
    return base_url


def start_sentinel(socketio, host: str = "0.0.0.0",
                   port: int = 6100, autoblock: bool = False) -> bool:
    """
    Start SentinelAI internally (Mode A) OR connect to already-running
    instance (Mode B).  Returns True if bridge is active.
    """
    try:
        from shared_state import state

        # Check if sentinel is already running (Mode B — standalone)
        # shared_state is a module-level singleton, so if sentinel_ai.py already
        # imported and configured it, state.config will have server_port set
        already_running = state.config.get("server_port", 5000) != 5000

        if not already_running:
            # Mode A — start everything internally
            from target_server import start_server
            from honeypot import start_honeypot
            from detection_engine import start_detection

            state.config["autoblock"]   = autoblock
            state.config["server_port"] = port
            state.config["server_host"] = host

            threading.Thread(target=start_server, args=(host, port),
                             daemon=True, name="sentinel-target").start()
            threading.Thread(target=start_honeypot,
                             daemon=True, name="sentinel-honeypot").start()
            threading.Thread(target=start_detection,
                             daemon=True, name="sentinel-detectors").start()

            logger.info("SentinelAI started internally — target :%d | honeypot 28 ports | 5 detectors", port)
        else:
            logger.info("SentinelAI already running on :%d — bridge connecting",
                        state.config.get("server_port", port))

        # Start bridge in both modes
        threading.Thread(target=_bridge, args=(socketio, state),
                         daemon=True, name="sentinel-bridge").start()
        return True

    except Exception as e:
        logger.warning("SentinelAI bridge failed: %s", e)
        return False


def _bridge(socketio, state) -> None:
    """Poll shared_state every 0.5s, forward new alerts + stats to browsers."""
    last_alert_ts   = 0.0
    last_stats_emit = 0.0

    while True:
        try:
            now = time.time()

            # Forward new alerts
            with state.lock:
                all_alerts = list(state.alerts)

            for alert in all_alerts:
                if alert.timestamp > last_alert_ts:
                    last_alert_ts = alert.timestamp
                    socketio.emit("sentinel_alert", {
                        "timestamp":    alert.timestamp,
                        "severity":     alert.severity,
                        "attack_type":  alert.attack_type,
                        "src_ip":       alert.src_ip,
                        "description":  alert.description,
                        "auto_blocked": alert.auto_blocked,
                    })
                    logger.info("[SENTINEL] %s from %s — %s",
                                alert.attack_type, alert.src_ip, alert.severity)

            # Stats snapshot every 2s
            if now - last_stats_emit >= 2.0:
                last_stats_emit = now
                snap = state.snapshot_stats()
                socketio.emit("sentinel_stats", {
                    "total_requests":   snap["total_requests"],
                    "blocked_requests": snap["blocked_requests"],
                    "total_alerts":     snap["total_alerts"],
                    "alerts_by_type":   snap["alerts_by_type"],
                    "blocked_ips":      list(state.blocked_ips),
                    "uptime":           now - snap["start_time"],
                })

        except Exception as e:
            logger.debug("Bridge error: %s", e)

        time.sleep(0.5)
