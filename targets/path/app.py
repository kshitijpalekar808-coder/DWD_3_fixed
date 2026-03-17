import os
from flask import Flask, request, jsonify

app = Flask(__name__)
BASE_DIR = "/app/files"

@app.route("/read")
def read():
    filename = request.args.get("file", "")
    # VULNERABLE: no path sanitization
    try:
        full_path = os.path.join(BASE_DIR, filename)
        with open(full_path, "r") as f:
            return jsonify({
                "file": filename,
                "content": f.read(),
                "vulnerable": True
            })
    except Exception as e:
        return jsonify({"error": str(e), "path": filename}), 404

@app.route("/upload", methods=["POST"])
def upload():
    filename = request.form.get("filename", "")
    content = request.form.get("content", "")
    # VULNERABLE: no path sanitization on write
    try:
        full_path = os.path.join(BASE_DIR, filename)
        with open(full_path, "w") as f:
            f.write(content)
        return jsonify({"saved": filename, "vulnerable": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"status": "vulnerable", "type": "path"})

if __name__ == "__main__":
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(f"{BASE_DIR}/secret.txt", "w") as f:
        f.write("SECRET_KEY=prod-secret-abc123\nDB_PASS=supersecret")
    app.run(host="0.0.0.0", port=8085, debug=False)