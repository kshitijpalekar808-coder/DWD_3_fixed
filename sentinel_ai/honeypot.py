"""
honeypot.py — Multi-port TCP honeypot for catching port scans.

The attack simulator's PortScanSimulator probes many ports with TCP connect().
The honeypot opens listeners on ~30 common ports so those probes land somewhere
and are recorded as NetworkEvents.
"""

import select
import socket
import threading
import time

from shared_state import state, NetworkEvent

# Ports the honeypot listens on (excluding the main server port)
HONEYPOT_PORTS = [
    21, 22, 23, 25, 53, 110, 135, 139, 143, 389,
    443, 445, 993, 995, 1433, 1521, 2222, 3306,
    3389, 4444, 5432, 5900, 6379, 8080, 8443, 8888,
    9200, 27017,
]


def _port_listener(port: int, server_sock: socket.socket) -> None:
    """Accept connections on a single honeypot port, log each one."""
    while True:
        try:
            ready, _, _ = select.select([server_sock], [], [], 1.0)
            if not ready:
                continue
            conn, addr = server_sock.accept()
            src_ip = addr[0]
            conn.close()

            evt = NetworkEvent(
                timestamp  = time.time(),
                src_ip     = src_ip,
                event_type = "honeypot_connect",
                port       = port,
            )
            state.add_event(evt)
        except Exception:
            break


def start_honeypot() -> None:
    """Bind to every HONEYPOT_PORT and spawn a listener thread for each."""
    active = 0
    for port in HONEYPOT_PORTS:
        # Skip the main server port
        if port == state.config.get("server_port", 5000):
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            t = threading.Thread(
                target=_port_listener,
                args=(port, sock),
                daemon=True,
                name=f"honeypot-{port}",
            )
            t.start()
            active += 1
        except OSError:
            pass   # port already in use — skip silently

    # Keep the thread alive
    while True:
        time.sleep(60)
