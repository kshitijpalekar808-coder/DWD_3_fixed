"""
DataWatchDawgs — Real Docker Battlefield Manager
Builds and runs actual vulnerable containers.
Applies real patches by rewriting app code.
"""
import os, time, subprocess, logging, requests, shutil, tempfile
from dataclasses import dataclass
from typing import Optional, Dict

logger = logging.getLogger("dwd.docker")

PORTS = {"sqli":8081,"xss":8082,"rce":8083,"ssrf":8084,"path":8085}
TARGETS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "targets")

# Patched versions of each app
PATCHED_APPS = {
"sqli": '''
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT)")
    db.execute("INSERT INTO users VALUES (1,'admin','secret123','admin')")
    db.execute("INSERT INTO users VALUES (2,'user','pass456','user')")
    db.commit()
    return db

@app.route("/search")
def search():
    q = request.args.get("q", "")
    try:
        db = get_db()
        # PATCHED: parameterized query
        results = db.execute("SELECT * FROM users WHERE username = ?", (q,)).fetchall()
        return jsonify({"results": [list(r) for r in results]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    try:
        db = get_db()
        # PATCHED: parameterized query
        r = db.execute("SELECT * FROM users WHERE username=? AND password=?", (u,p)).fetchone()
        if r:
            return jsonify({"status": "ok", "user": r[1], "role": r[3]})
        return jsonify({"status": "fail"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    try:
        # PATCHED: validate integer input
        uid = int(uid)
        db = get_db()
        r = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        return jsonify({"user": list(r) if r else None})
    except ValueError:
        return jsonify({"error": "Invalid ID"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/health")
def health():
    return jsonify({"status": "patched", "type": "sqli"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
''',

"xss": '''
from flask import Flask, request, jsonify
from markupsafe import escape

app = Flask(__name__)
comments = []

@app.route("/")
def index():
    name = request.args.get("name", "")
    # PATCHED: escape output
    return f"<html><body><h1>Hello {escape(name)}</h1></body></html>"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # PATCHED: escape output
    return f"<html><body><p>Results for: {escape(q)}</p></body></html>"

@app.route("/comment", methods=["POST"])
def comment():
    body = request.form.get("body", "")
    # PATCHED: escape before storing
    comments.append(str(escape(body)))
    return jsonify({"status": "ok"})

@app.route("/comments")
def get_comments():
    html = "<html><body>"
    for c in comments:
        html += f"<div>{c}</div>"
    html += "</body></html>"
    return html

@app.route("/health")
def health():
    return jsonify({"status": "patched", "type": "xss"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082, debug=False)
''',

"rce": '''
import re, subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
ALLOWED_HOSTS = re.compile(r"^[a-zA-Z0-9.-]+$")

@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "")
    # PATCHED: validate input, no shell=True
    if not ALLOWED_HOSTS.match(host):
        return jsonify({"error": "Invalid host"}), 400
    result = subprocess.run(
        ["echo", "pinging", host],
        capture_output=True, text=True, timeout=5
    )
    return jsonify({"output": result.stdout})

@app.route("/log", methods=["POST"])
def log():
    message = request.form.get("message", "")
    # PATCHED: block JNDI patterns
    if "${" in message:
        return jsonify({"error": "Invalid characters in message"}), 400
    return jsonify({"logged": message})

@app.route("/execute", methods=["POST"])
def execute():
    # PATCHED: endpoint disabled
    return jsonify({"error": "Endpoint disabled for security"}), 403

@app.route("/health")
def health():
    return jsonify({"status": "patched", "type": "rce"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8083, debug=False)
''',

"ssrf": '''
import ipaddress, socket, requests as req
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)
ALLOWED_DOMAINS = {"example.com", "httpbin.org"}
BLOCKED_CIDRS = ["169.254.0.0/16","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not allowed: {parsed.hostname}")
    try:
        ip = socket.gethostbyname(parsed.hostname)
        for cidr in BLOCKED_CIDRS:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                raise ValueError(f"Private IP blocked: {ip}")
    except socket.gaierror:
        raise ValueError("Could not resolve hostname")

@app.route("/fetch", methods=["POST"])
def fetch():
    url = request.form.get("url", "")
    try:
        is_safe_url(url)
        resp = req.get(url, timeout=3)
        return jsonify({"status": resp.status_code, "content": resp.text[:200]})
    except ValueError as e:
        return jsonify({"error": str(e), "blocked": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/pdf", methods=["POST"])
def pdf():
    url = request.form.get("url", "")
    try:
        is_safe_url(url)
        return jsonify({"pdf_generated": True, "url": url})
    except ValueError as e:
        return jsonify({"error": str(e), "blocked": True}), 403

@app.route("/health")
def health():
    return jsonify({"status": "patched", "type": "ssrf"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8084, debug=False)
''',

"path": '''
import os, re
from flask import Flask, request, jsonify

app = Flask(__name__)
BASE_DIR = "/app/files"
SAFE_NAME = re.compile(r"^[a-zA-Z0-9_.-]+$")

def safe_path(filename):
    if not SAFE_NAME.match(filename):
        raise ValueError("Invalid filename")
    full = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not full.startswith(os.path.realpath(BASE_DIR)):
        raise ValueError("Path traversal detected")
    return full

@app.route("/read")
def read():
    filename = request.args.get("file", "")
    try:
        path = safe_path(filename)
        with open(path, "r") as f:
            return jsonify({"file": filename, "content": f.read()})
    except ValueError as e:
        return jsonify({"error": str(e), "blocked": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route("/upload", methods=["POST"])
def upload():
    filename = request.form.get("filename", "")
    content = request.form.get("content", "")
    try:
        path = safe_path(filename)
        with open(path, "w") as f:
            f.write(content)
        return jsonify({"saved": filename})
    except ValueError as e:
        return jsonify({"error": str(e), "blocked": True}), 403

@app.route("/health")
def health():
    return jsonify({"status": "patched", "type": "path"})

if __name__ == "__main__":
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(f"{BASE_DIR}/secret.txt", "w") as f:
        f.write("SECRET_KEY=prod-secret-abc123")
    app.run(host="0.0.0.0", port=8085, debug=False)
'''
}


@dataclass
class Target:
    vuln_type: str
    port: int
    url: str
    container_name: str
    running: bool = False
    patched: bool = False


class DockerManager:
    def __init__(self):
        self.docker_available = self._check_docker()
        self._targets: Dict[str, Target] = {}
        if self.docker_available:
            logger.info("Docker available — real battlefield active")
        else:
            logger.warning("Docker not available — simulation mode")

    def _check_docker(self) -> bool:
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def deploy_vulnerable(self, vuln_type: str) -> Target:
        port = PORTS[vuln_type]
        name = f"dwd-{vuln_type}-vulnerable"
        url = f"http://localhost:{port}"

        if not self.docker_available:
            target = Target(vuln_type, port, url, name, running=False)
            self._targets[vuln_type] = target
            return target

        # Stop any existing container
        self._stop(name)

        # Build from targets directory
        target_dir = os.path.join(TARGETS_DIR, vuln_type)
        if not os.path.exists(target_dir):
            logger.warning(f"Target dir not found: {target_dir}")
            target = Target(vuln_type, port, url, name, running=False)
            self._targets[vuln_type] = target
            return target

        try:
            image = f"dwd-{vuln_type}:vulnerable"
            logger.info(f"Building {image}...")
            subprocess.run(
                ["docker", "build", "-t", image, target_dir],
                capture_output=True, timeout=120, check=True
            )

            self._stop_port(port)

            subprocess.run([
                "docker", "run", "-d",
                "--name", name,
                "-p", f"{port}:{port}",
                "--rm",
                image
            ], capture_output=True, timeout=30, check=True)

            # Wait for startup
            self._wait_ready(url)

            target = Target(vuln_type, port, url, name, running=True, patched=False)
            self._targets[vuln_type] = target
            logger.info(f"Vulnerable target running: {url}")
            return target

        except subprocess.CalledProcessError as e:
            logger.error(f"Docker build/run failed: {e}")
            target = Target(vuln_type, port, url, name, running=False)
            self._targets[vuln_type] = target
            return target

    def deploy_patched(self, vuln_type: str) -> Target:
        port = PORTS[vuln_type]
        name = f"dwd-{vuln_type}-patched"
        url = f"http://localhost:{port}"

        if not self.docker_available:
            target = Target(vuln_type, port, url, name, running=False, patched=True)
            self._targets[vuln_type] = target
            return target

        # Stop vulnerable version
        self._stop(f"dwd-{vuln_type}-vulnerable")

        # Write patched app to temp dir
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write(PATCHED_APPS[vuln_type])

            # Copy Dockerfile from original
            src_df = os.path.join(TARGETS_DIR, vuln_type, "Dockerfile")
            shutil.copy(src_df, os.path.join(tmpdir, "Dockerfile"))

            image = f"dwd-{vuln_type}:patched"
            subprocess.run(
                ["docker", "build", "-t", image, tmpdir],
                capture_output=True, timeout=120, check=True
            )

            self._stop_port(port)
            self._stop(name)

            subprocess.run([
                "docker", "run", "-d",
                "--name", name,
                "-p", f"{port}:{port}",
                "--rm",
                image
            ], capture_output=True, timeout=30, check=True)

            self._wait_ready(url)

            target = Target(vuln_type, port, url, name, running=True, patched=True)
            self._targets[vuln_type] = target
            logger.info(f"Patched target running: {url}")
            return target

        except Exception as e:
            logger.error(f"Patched deploy failed: {e}")
            target = Target(vuln_type, port, url, name, running=False, patched=True)
            self._targets[vuln_type] = target
            return target
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _wait_ready(self, url: str, timeout: int = 30):
        start = time.time()
        while time.time() - start < timeout:
            try:
                requests.get(f"{url}/health", timeout=2)
                return True
            except Exception:
                time.sleep(1)
        return False

    def _stop(self, name: str):
        try:
            subprocess.run(["docker", "stop", name],
                         capture_output=True, timeout=15)
            subprocess.run(["docker", "rm", "-f", name],
                         capture_output=True, timeout=10)
        except Exception:
            pass

    def _stop_port(self, port: int):
        try:
            result = subprocess.run(
                ["docker", "ps", "-q", "--filter", f"publish={port}"],
                capture_output=True, text=True, timeout=10
            )
            for cid in result.stdout.strip().split('\n'):
                if cid:
                    subprocess.run(["docker", "stop", cid],
                                 capture_output=True, timeout=15)
        except Exception:
            pass

    def teardown(self, vuln_type: str):
        for suffix in ["vulnerable", "patched"]:
            self._stop(f"dwd-{vuln_type}-{suffix}")
        self._targets.pop(vuln_type, None)

    def teardown_all(self):
        for vt in list(self._targets.keys()):
            self.teardown(vt)