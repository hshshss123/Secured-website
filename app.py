import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
from functools import wraps
from pathlib import Path

from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "lab.db"
TERMINAL_SECRET = os.environ.get("TERMINAL_SECRET", secrets.token_hex(32))
TERMINAL_WS = os.environ.get("TERMINAL_WS", "ws://127.0.0.1:7681")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    WTF_CSRF_TIME_LIMIT=None,
)
csrf = CSRFProtect(app)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error):
    conn = g.pop("db", None)
    if conn:
        conn.close()

def init_db():
    conn = db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    if not conn.execute("SELECT 1 FROM users WHERE username = ?", ("demo",)).fetchone():
        conn.execute(
            "INSERT INTO users(username, password_hash) VALUES (?, ?)",
            ("demo", generate_password_hash("DemoPass!2026")),
        )
    conn.commit()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def terminal_token():
    ts = str(int(time.time() * 1000))
    sig = hmac.new(TERMINAL_SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return ts + "." + sig

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self' ws://127.0.0.1:7681 ws://localhost:7681; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    return response

@app.route("/")
def index():
    return render_template("index.html", user=g_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html", error=None)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 40 or not username.replace("_", "").isalnum():
            return render_template("register.html", error="Use 3–40 letters, numbers, or underscores.")
        if len(password) < 12:
            return render_template("register.html", error="Password must be at least 12 characters.")
        try:
            conn = db()
            conn.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already exists.")
        return redirect(url_for("login"))
    return render_template("register.html", error=None)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    notes = db().execute(
        "SELECT id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("dashboard.html", user=g_user(), notes=notes)

@app.route("/notes", methods=["POST"])
@login_required
def create_note():
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title or not body or len(title) > 120 or len(body) > 5000:
        abort(400)
    db().execute(
        "INSERT INTO notes(user_id, title, body) VALUES (?, ?, ?)",
        (session["user_id"], title, body),
    )
    db().commit()
    return redirect(url_for("dashboard"))

@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    db().execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"]),
    )
    db().commit()
    return redirect(url_for("dashboard"))

@app.route("/search")
@login_required
def search():
    term = request.args.get("q", "").strip()
    rows = db().execute(
        "SELECT id, title, body FROM notes WHERE user_id = ? AND (title LIKE ? OR body LIKE ?)",
        (session["user_id"], f"%{term}%", f"%{term}%"),
    ).fetchall()
    return render_template("search.html", term=term, results=rows, user=g_user())

@app.route("/api/me")
@login_required
def api_me():
    return jsonify({"id": session["user_id"], "username": session["username"]})

@app.route("/api/notes")
@login_required
def api_notes():
    rows = db().execute(
        "SELECT id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return jsonify([dict(row) for row in rows])

@app.route("/labs")
def labs():
    return render_template("labs.html", user=g_user())

@app.route("/terminal")
@login_required
def terminal():
    return render_template(
        "terminal.html",
        user=g_user(),
        terminal_ws=TERMINAL_WS,
        terminal_token=terminal_token(),
    )

@app.route("/github")
def github_search():
    return render_template("github.html", user=g_user())

@app.route("/api/github/repos")
def github_repos():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "Search query is required."}), 400
    if len(query) > 256:
        return jsonify({"error": "Query is too long."}), 400
    try:
        page = max(1, min(int(request.args.get("page", "1")), 10))
    except ValueError:
        page = 1

    params = urllib.parse.urlencode({"q": query, "per_page": 30, "page": page})
    req = urllib.request.Request(
        "https://api.github.com/search/repositories?" + params,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "Secured-Lab/1.0",
        },
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer " + token)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return jsonify({"error": "GitHub API request failed or was rate-limited."}), 502

    items = []
    for x in data.get("items", []):
        items.append({
            "full_name": x.get("full_name"),
            "description": x.get("description"),
            "html_url": x.get("html_url"),
            "language": x.get("language"),
            "stargazers_count": x.get("stargazers_count", 0),
            "updated_at": x.get("updated_at", ""),
        })
    return jsonify({
        "total_count": data.get("total_count", 0),
        "incomplete_results": data.get("incomplete_results", False),
        "page": page,
        "items": items,
    })

def g_user():
    if "user_id" not in session:
        return None
    return {"id": session["user_id"], "username": session["username"]}

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
