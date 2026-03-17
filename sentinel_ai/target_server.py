"""
target_server.py — The "victim" web server that the attack simulator targets.
"""
 
import logging
import time
 
from flask import Flask, request, Response, g
 
from shared_state import state, NetworkEvent
 
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)
 
app = Flask(__name__)
 
 
@app.before_request
def _intercept():
    ip = request.remote_addr or "0.0.0.0"
    if state.is_blocked(ip):
        with state.lock:
            state.stats["blocked_requests"] += 1
        return Response("Forbidden — blocked by SentinelAI", status=403)
    # Read body now so content_length is accurate for after_request logging
    body = request.get_data(cache=True)
    g.req_ip       = ip
    g.req_time     = time.time()
    g.req_body_len = len(body)
 
 
@app.after_request
def _log_request(response):
    ip = getattr(g, "req_ip", request.remote_addr or "0.0.0.0")
    # Use cached body length (read in before_request) for accurate content_length
    body_len = getattr(g, "req_body_len", request.content_length or 0)
    evt = NetworkEvent(
        timestamp      = getattr(g, "req_time", time.time()),
        src_ip         = ip,
        event_type     = "http_request",
        port           = state.config.get("server_port", 5000),
        method         = request.method,
        path           = request.path,
        content_length = body_len,
        content_type   = request.content_type or "",
        user_agent     = request.user_agent.string or "",
        status_code    = response.status_code,
    )
    state.add_event(evt)
    return response
 
 
# ── Routes ────────────────────────────────────────────────────────────────────
 
@app.route("/", methods=["GET", "POST"])
def index():
    _ = request.get_data(cache=False)
    return Response("SentinelAI Target Server — Online", status=200)
 
 
@app.route("/login", methods=["GET", "POST"])
def login():
    _ = request.get_data(cache=False)
    return Response("Unauthorized", status=401)
 
 
@app.route("/upload", methods=["GET", "POST"])
def upload():
    _ = request.get_data(cache=False)
    return Response("OK", status=200)
 
 
@app.route("/beacon", methods=["GET", "POST"])
def beacon():
    _ = request.get_data(cache=False)
    return Response('{"cmd":"sleep"}', status=200, content_type="application/json")
 
 
@app.route("/data", methods=["GET", "POST"])
def data():
    _ = request.get_data(cache=False)
    return Response("OK", status=200)
 
 
def start_server(host: str = "0.0.0.0", port: int = 5000) -> None:
    app.run(host=host, port=port, threaded=True, use_reloader=False)
 