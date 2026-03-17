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
        # VULNERABLE: direct string injection
        results = db.execute(f"SELECT * FROM users WHERE username = '{q}'").fetchall()
        return jsonify({"results": [list(r) for r in results]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    try:
        db = get_db()
        # VULNERABLE: direct string injection
        r = db.execute(f"SELECT * FROM users WHERE username='{u}' AND password='{p}'").fetchone()
        if r:
            return jsonify({"status": "ok", "user": r[1], "role": r[3]})
        return jsonify({"status": "fail"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    try:
        db = get_db()
        # VULNERABLE: direct string injection
        r = db.execute(f"SELECT * FROM users WHERE id = {uid}").fetchone()
        return jsonify({"user": list(r) if r else None})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/health")
def health():
    return jsonify({"status": "vulnerable", "type": "sqli"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
