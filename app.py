"""UX Bridge admin proxy.

Lets the UX Bridge admin page work with just the admin password, on any
phone, without a GitHub token on the device. This server holds the GitHub
token (in the GITHUB_TOKEN env var) and talks to the GitHub Contents API
on behalf of password-authenticated admin sessions.

Env vars (set in the Render dashboard, never in chat or in this repo):
  GITHUB_TOKEN    - a classic GitHub token with `repo` scope on the site repo
  ADMIN_PASSWORD  - the password for the admin lock screen

Public endpoints: /health, /api/login
Everything else requires the X-Admin-Session header from /api/login.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.request
import urllib.error
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS

OWNER = "engrmahmod"
REPO = "engrmahmod.github.io"
GH_API = "https://api.github.com"
ALLOWED_ORIGIN = "https://engrmahmod.github.io"
SESSION_TTL = 24 * 3600

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# Only these repo files may be read/written through the proxy.
ALLOWED_FILES = ("data/galleries.json", "data/site-config.json")
UPLOAD_RE = re.compile(r"img/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+\.(jpg|jpeg|png|webp)")

app = Flask(__name__)
CORS(app, origins=[ALLOWED_ORIGIN])

_sessions = {}        # session token -> expiry timestamp
_login_attempts = {}  # ip -> [timestamps]


def gh(path, method="GET", payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(GH_API + path, data=body, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Authorization", "Bearer " + GITHUB_TOKEN)
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            detail = ""
        return e.code, {"error": detail}


def require_session(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        tok = request.headers.get("X-Admin-Session", "")
        if not tok or _sessions.get(tok, 0) < time.time():
            return jsonify({"error": "not authorized"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "github_connected": bool(GITHUB_TOKEN),
        "password_set": bool(ADMIN_PASSWORD),
    })


@app.route("/api/login", methods=["POST"])
def login():
    ip = (request.headers.get("X-Forwarded-For", "") or request.remote_addr or "").split(",")[0].strip()
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < 600]
    if len(attempts) >= 15:
        return jsonify({"error": "Too many tries. Wait a bit."}), 429
    attempts.append(now)
    _login_attempts[ip] = attempts

    data = request.get_json(force=True, silent=True) or {}
    pw = data.get("password", "")
    if ADMIN_PASSWORD and hmac.compare_digest(pw, ADMIN_PASSWORD):
        tok = secrets.token_urlsafe(32)
        _sessions[tok] = now + SESSION_TTL
        return jsonify({"ok": True, "session": tok})
    return jsonify({"error": "Wrong password."}), 401


@app.route("/api/file/<path:name>", methods=["GET"])
@require_session
def get_file(name):
    if name not in ALLOWED_FILES:
        return jsonify({"error": "not allowed"}), 403
    status, d = gh(f"/repos/{OWNER}/{REPO}/contents/{name}")
    if status != 200:
        return jsonify({"error": "Could not load file."}), 502
    text = base64.b64decode(d["content"]).decode("utf-8")
    return jsonify({"sha": d["sha"], "data": json.loads(text)})


@app.route("/api/file/<path:name>", methods=["PUT"])
@require_session
def put_file(name):
    if name not in ALLOWED_FILES:
        return jsonify({"error": "not allowed"}), 403
    data = request.get_json(force=True, silent=True) or {}
    if "data" not in data or "sha" not in data:
        return jsonify({"error": "missing data"}), 400
    content = base64.b64encode((json.dumps(data["data"], indent=2) + "\n").encode()).decode()
    status, d = gh(f"/repos/{OWNER}/{REPO}/contents/{name}", "PUT", {
        "message": data.get("message", "Admin update"),
        "content": content,
        "sha": data["sha"],
    })
    if status not in (200, 201):
        return jsonify({"error": "Could not save. Try again."}), 502
    return jsonify({"ok": True, "sha": d["content"]["sha"]})


@app.route("/api/upload", methods=["POST"])
@require_session
def upload():
    data = request.get_json(force=True, silent=True) or {}
    dest = data.get("path", "")
    if not UPLOAD_RE.fullmatch(dest):
        return jsonify({"error": "bad path"}), 403
    if not data.get("content"):
        return jsonify({"error": "missing content"}), 400
    status, d = gh(f"/repos/{OWNER}/{REPO}/contents/{dest}", "PUT", {
        "message": data.get("message", "Admin: add photo"),
        "content": data["content"],
    })
    if status not in (200, 201):
        return jsonify({"error": "Upload failed. Try again."}), 502
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
