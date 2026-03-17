import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "")
    # VULNERABLE: shell injection
    result = subprocess.run(
        f"echo pinging {host}",
        shell=True, capture_output=True, text=True, timeout=5
    )
    return jsonify({"output": result.stdout + result.stderr})

@app.route("/log", methods=["POST"])
def log():
    message = request.form.get("message", "")
    # VULNERABLE: simulates Log4Shell pattern
    if "${jndi:" in message.lower() or "${" in message:
        return jsonify({
            "error": "JNDI lookup attempted",
            "message": message,
            "vulnerable": True,
            "detail": "Log4j JNDI lookup executed"
        }), 500
    return jsonify({"logged": message})

@app.route("/execute", methods=["POST"])
def execute():
    cmd = request.form.get("cmd", "")
    # VULNERABLE: direct command execution
    try:
        out = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=5
        )
        return jsonify({"output": out.stdout, "error": out.stderr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"status": "vulnerable", "type": "rce"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8083, debug=False)