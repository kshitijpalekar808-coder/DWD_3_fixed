import requests as req
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/fetch", methods=["POST"])
def fetch():
    url = request.form.get("url", "")
    # VULNERABLE: fetches any URL including internal
    try:
        resp = req.get(url, timeout=3)
        return jsonify({
            "url": url,
            "status": resp.status_code,
            "content": resp.text[:500],
            "vulnerable": True
        })
    except Exception as e:
        return jsonify({"error": str(e), "url": url}), 500

@app.route("/pdf", methods=["POST"])
def pdf():
    url = request.form.get("url", "")
    # VULNERABLE: simulates PDF generator fetching URLs
    try:
        resp = req.get(url, timeout=3)
        return jsonify({
            "pdf_generated": True,
            "fetched_url": url,
            "content_preview": resp.text[:200]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"status": "vulnerable", "type": "ssrf"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8084, debug=False)