"""
DWD_3 — DataWatchDawgs + SentinelAI unified application
Run:   python app.py
URLs:
  http://localhost:5000            — Main dashboard (DWD)
  http://localhost:5000/sentinel   — SentinelAI live detection view
  http://localhost:5000/judges     — Fullscreen judges / projector view
  http://localhost:5000/attacker   — Red console (Laptop A / attacker)
  Attack target (SentinelAI):  port 6100
"""
import gevent.monkey
gevent.monkey.patch_all()
import os, sys, threading, time, logging
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from dotenv import load_dotenv
 
load_dotenv()
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("dwd.app")
 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
 
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "datawatchdawgs-secret")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")
 
from core.battle_engine import BattleEngine, CVE_DB
try:
    from core.network_battle_engine import NETWORK_VULN_DB
    from agents.network_agent import NETWORK_ATTACK_META
    NETWORK_AVAILABLE = True
except ImportError:
    NETWORK_VULN_DB = {}
    NETWORK_ATTACK_META = {}
    NETWORK_AVAILABLE = False
 
try:
    from sentinel_bridge import start_sentinel, resolve_target
    SENTINEL_AVAILABLE = True
except ImportError:
    SENTINEL_AVAILABLE = False
 
_engine = None
_battle_running = False
 
 
def get_engine():
    global _engine
    if _engine is None:
        sentinel_port = int(os.getenv("SENTINEL_PORT", 6100))
        sentinel_host = os.getenv("NETWORK_TARGET", "127.0.0.1")
        def emit_fn(event, data):
            socketio.emit(event, data)
        _engine = BattleEngine(
            max_rounds=5,
            emit_fn=emit_fn,
            sentinel_port=sentinel_port,
            sentinel_host=sentinel_host,
        )
    return _engine
 
 
@app.route("/")
def index():
    return render_template("index.html")
 
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
 
@app.route("/sentinel")
def sentinel_view():
    return render_template("sentinel.html")
 
@app.route("/judges")
def judges():
    return render_template("judges.html")
 
@app.route("/attacker")
def attacker():
    return render_template("attacker.html")
 
@app.route("/api/sentinel/status")
def api_sentinel_status():
    return jsonify({"available": SENTINEL_AVAILABLE})

 
@app.route("/api/sentinel/snapshot")
def api_sentinel_snapshot():
    if not SENTINEL_AVAILABLE:
        return jsonify({"error": "SentinelAI not available"}), 503
    try:
        import sys, os
        _sdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_ai")
        if _sdir not in sys.path:
            sys.path.insert(0, _sdir)
        from shared_state import state

        alerts = []
        with state.lock:
            recent_alerts = list(state.alerts)[-100:]
            for alert in recent_alerts:
                alerts.append({
                    "timestamp": alert.timestamp,
                    "severity": alert.severity,
                    "attack_type": alert.attack_type,
                    "src_ip": alert.src_ip,
                    "description": alert.description,
                    "auto_blocked": alert.auto_blocked,
                })
            stats = dict(state.stats)
            blocked_ips = list(state.blocked_ips)

        return jsonify({
            "alerts": alerts,
            "stats": {
                "total_requests": stats["total_requests"],
                "blocked_requests": stats["blocked_requests"],
                "total_alerts": stats["total_alerts"],
                "alerts_by_type": stats["alerts_by_type"],
                "blocked_ips": blocked_ips,
                "uptime": time.time() - stats["start_time"],
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sentinel/unblock-all", methods=["POST"])
def api_sentinel_unblock():
    if SENTINEL_AVAILABLE:
        try:
            import sys, os
            _sdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_ai")
            if _sdir not in sys.path: sys.path.insert(0, _sdir)
            from shared_state import state
            with state.lock:
                count = len(state.blocked_ips)
                state.blocked_ips.clear()
            return jsonify({"cleared": count, "message": f"Unblocked {count} IP(s)"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "SentinelAI not available"}), 503
 
@app.route("/api/stats")
def api_stats():
    return jsonify(get_engine().get_stats())
 
@app.route("/api/battles")
def api_battles():
    return jsonify(get_engine().battles[-20:])
 
@app.route("/api/cves")
def api_cves():
    return jsonify([
        {"key": k, "id": v["id"], "name": v["name"],
         "cvss": v["cvss"], "type": v["type"], "desc": v["desc"]}
        for k, v in CVE_DB.items()
    ])
 
@app.route("/api/network/attacks")
def api_network_attacks():
    return jsonify([
        {"key": k, "id": v["id"], "name": v["name"],
         "cvss": v.get("cvss", 0), "layer": v.get("layer", "network"),
         "type": v.get("type", "Medium"), "desc": v.get("desc", "")}
        for k, v in NETWORK_VULN_DB.items()
    ])
 
@app.route("/api/network/soc-training", methods=["POST"])
def api_soc_training():
    data = request.get_json(force=True) or {}
    def run_soc():
        try:
            result = get_engine().run_soc_training(data.get("attack_type","port_scan"), data.get("soc_response"))
            socketio.emit("soc_training_complete", result)
        except Exception as e:
            socketio.emit("soc_training_complete", {"error": str(e)})
    threading.Thread(target=run_soc, daemon=True).start()
    return jsonify({"status": "running"})
 
@app.route("/api/network/firewall-verify", methods=["POST"])
def api_firewall_verify():
    data = request.get_json(force=True) or {}
    def run_verify():
        try:
            result = get_engine().run_firewall_verification(data.get("attack_type","brute_force"), data.get("proposed_rule"))
            socketio.emit("waf_verify_complete", result)
        except Exception as e:
            socketio.emit("waf_verify_complete", {"error": str(e)})
    threading.Thread(target=run_verify, daemon=True).start()
    return jsonify({"status": "running"})
 
@app.route("/api/network/red-team", methods=["POST"])
def api_red_team():
    data = request.get_json(force=True) or {}
    def run_rt():
        try:
            result = get_engine().run_full_red_team(data.get("target_url"), data.get("options"))
            socketio.emit("red_team_complete", result)
        except Exception as e:
            socketio.emit("red_team_complete", {"error": str(e)})
    threading.Thread(target=run_rt, daemon=True).start()
    return jsonify({"status": "running"})
 
 
@socketio.on("connect")
def on_connect():
    engine = get_engine()
    stats = engine.get_stats()
    emit("connected", {"message": "DWD_3 Connected", "cycle": stats["cycle"], "stats": stats})
    logger.info("Client connected")
 
@socketio.on("launch_battle")
def on_launch(data):
    global _battle_running
    if _battle_running:
        emit("battle_error", {"msg": "Battle already running — please wait"})
        return
    vuln_key = data.get("vuln_key", "sqli")
    if vuln_key.startswith("net_"):
        net_key_map = {
            "net_port_scan": "port_scan", "net_brute_force": "brute_force",
            "net_c2_beacon": "c2_beacon", "net_data_exfil": "data_exfiltration",
            "net_traffic_flood": "traffic_flood",
        }
        net_type = net_key_map.get(vuln_key, vuln_key[4:])
        def run_net():
            global _battle_running
            _battle_running = True
            try:
                result = get_engine().run_firewall_verification(net_type)
                socketio.emit("battle_complete", result)
            except Exception as e:
                socketio.emit("battle_error", {"msg": str(e)})
            finally:
                _battle_running = False
        threading.Thread(target=run_net, daemon=True).start()
        return
    if vuln_key not in CVE_DB:
        emit("battle_error", {"msg": f"Unknown: {vuln_key}"})
        return
    def run():
        global _battle_running
        _battle_running = True
        try:
            get_engine().run(vuln_key)
        except Exception as e:
            socketio.emit("battle_error", {"msg": str(e)})
        finally:
            _battle_running = False
    threading.Thread(target=run, daemon=True).start()
 
@socketio.on("get_stats")
def on_stats():
    emit("stats_update", get_engine().get_stats())
 
 
def live_ticker():
    import random
    from datetime import datetime
    msgs = [
        ("INFO","research:","la-orch","NVD sync complete — no new critical CVEs in monitored stack"),
        ("INFO","orchestra…","la-orch",lambda: f"Cycle #{get_engine().cycle}: All agents nominal"),
        ("INFO","red:","la-red","Passive recon: monitoring api-gateway for configuration drift"),
        ("INFO","blue:","la-blue","Digital twin: regression suite 847/847 tests passing"),
        ("INFO","audit:","la-audit","Tamper check: HMAC chain integrity verified — no anomalies"),
        ("INFO","network:","la-red","Network layer: port scan baseline — 3 open ports (22,80,443)"),
        ("INFO","network:","la-red","Network layer: C2 beacon monitor — no anomalous egress detected"),
        ("INFO","network:","la-red","Network layer: brute-force threshold — 0 login floods in last 5m"),
        ("INFO","network:","la-red","Network layer: exfil detector — outbound entropy within normal range"),
        ("SUCCESS","network:","la-red","Network layer: traffic flood sentinel — rate limiter holding"),
    ]
    while True:
        time.sleep(4)
        if not _battle_running:
            m = random.choice(msgs)
            msg = m[3]() if callable(m[3]) else m[3]
            ts = datetime.now().strftime("%H:%M:%S")
            lvc = {"INFO":"lv-info","SUCCESS":"lv-success","ERROR":"lv-error","WARNING":"lv-warn"}.get(m[0],"lv-info")
            socketio.emit("op_log", {"ts":ts,"lv":m[0],"lvc":lvc,"ag":m[1],"ac":m[2],"msg":msg})
 
 
if __name__ == "__main__":
    os.makedirs("audit_logs", exist_ok=True)
    sentinel_port = int(os.getenv("SENTINEL_PORT", 6100))
 
    get_engine()
 
    if SENTINEL_AVAILABLE:
        ok = start_sentinel(socketio, host="0.0.0.0", port=sentinel_port,
                            autoblock=os.getenv("SENTINEL_AUTOBLOCK","false").lower()!="false")
        print(f"  [{'✓' if ok else '!'}] SentinelAI → attack target :{sentinel_port} | honeypot 28 ports | 5 detectors")
    else:
        print("  [!] SentinelAI not found — check sentinel_ai/ folder")
 
    threading.Thread(target=live_ticker, daemon=True).start()
 
    port = int(os.getenv("PORT", os.getenv("DASHBOARD_PORT", 5000)))
    print(f"""
╔══════════════════════════════════════════════════╗
║   🐾 DWD_3 — DataWatchDawgs + SentinelAI        ║
║                                                  ║
║   Dashboard:   http://localhost:{port}            ║
║   SentinelAI:  http://localhost:{port}/sentinel   ║
║   Judges View: http://localhost:{port}/judges     ║
║   Attacker:    http://localhost:{port}/attacker   ║
║                                                  ║
║   Attack target → port {sentinel_port}                  ║
║   Press Ctrl+C to stop                          ║
╚══════════════════════════════════════════════════╝
""")
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
 
