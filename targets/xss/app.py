from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
comments = []

@app.route("/")
def index():
    name = request.args.get("name", "")
    # VULNERABLE: reflects unsanitized input
    return f"<html><body><h1>Hello {name}</h1></body></html>"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: reflects unsanitized input
    return f"<html><body><p>Results for: {q}</p></body></html>"

@app.route("/comment", methods=["POST"])
def comment():
    body = request.form.get("body", "")
    # VULNERABLE: stores and renders unsanitized
    comments.append(body)
    return jsonify({"status": "ok", "stored": body})

@app.route("/comments")
def get_comments():
    # VULNERABLE: renders stored unsanitized content
    html = "<html><body>"
    for c in comments:
        html += f"<div>{c}</div>"
    html += "</body></html>"
    return html

@app.route("/health")
def health():
    return jsonify({"status": "vulnerable", "type": "xss"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082, debug=False)