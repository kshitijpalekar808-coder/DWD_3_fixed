#!/usr/bin/env python3
"""
sentinel_ai.py — SentinelAI: Real-Time Intrusion Detection & Response
Blue Team counterpart to the Cyber Attack Simulation Toolkit.

Usage
-----
  python sentinel_ai.py                        # listen on port 5000
  python sentinel_ai.py --port 8080            # custom port
  python sentinel_ai.py --no-autoblock         # alert only, don't block IPs

Red Team (attack sim) should target this machine's IP on the configured port:
  python attack_simulator.py --mode portscan --target <BLUE_IP>
  python attack_simulator.py --mode brute    --target http://<BLUE_IP>:5000/login
  python attack_simulator.py --mode flood    --target http://<BLUE_IP>:5000
  python attack_simulator.py --mode exfil    --target <BLUE_IP> --port 5000
  python attack_simulator.py --mode c2       --target http://<BLUE_IP>:5000/beacon
"""

import argparse
import sys
import threading
import time


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelAI — Blue Team IDS/IPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--port",         "-p", type=int, default=5000,    help="Server port (default: 5000)")
    parser.add_argument("--host",               default="0.0.0.0",         help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--no-autoblock", action="store_true",             help="Disable automatic IP blocking")
    args = parser.parse_args()

    # ── Configure shared state ────────────────────────────────────────────
    from shared_state import state
    state.config["autoblock"]    = not args.no_autoblock
    state.config["server_port"]  = args.port
    state.config["server_host"]  = args.host

    print("\n  [*] SentinelAI starting up…")

    # ── Target web server ─────────────────────────────────────────────────
    from target_server import start_server
    threading.Thread(
        target=start_server, args=(args.host, args.port),
        daemon=True, name="flask-server"
    ).start()
    print(f"  [✓] Target server  →  http://{args.host}:{args.port}")

    # ── Honeypot ──────────────────────────────────────────────────────────
    from honeypot import start_honeypot
    threading.Thread(target=start_honeypot, daemon=True, name="honeypot").start()
    print("  [✓] Honeypot       →  28 common ports")

    # ── Detection engine ──────────────────────────────────────────────────
    from detection_engine import start_detection
    threading.Thread(target=start_detection, daemon=True, name="detection").start()
    print("  [✓] Detectors      →  PortScan | BruteForce | Flood | Exfil | C2")
    print(f"  [✓] Auto-block     →  {'ENABLED' if not args.no_autoblock else 'DISABLED'}")

    time.sleep(1.2)   # let threads spin up

    # ── Live dashboard (blocks) ───────────────────────────────────────────
    from dashboard import run_dashboard
    try:
        run_dashboard()
    except KeyboardInterrupt:
        print("\n  [*] SentinelAI stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
