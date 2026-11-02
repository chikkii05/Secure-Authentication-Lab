"""Secure Authentication Lab: stdlib-only local auth service (learning project)."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer

DB_PATH = os.environ.get("AUTH_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db"))
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)  # lab only: set a stable secret in deployment
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
WINDOW = 60            # seconds
MAX_ATTEMPTS = 5       # per client+username per window
MAX_CLIENT_ATTEMPTS = 20  # per client per window (stops username rotation)
SESSION_TTL = 900      # 15 minutes
COOKIE_NAME = "auth_session"


def _scrypt(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


class AuthService:
    # Verified against when the username is unknown, so timing doesn't reveal which users exist.
    DUMMY_HASH = None

    def __init__(self, db_path=DB_PATH, secret=SECRET_KEY):
        self.db_path = db_path
        self.secret = secret.encode()
        self.attempts = {}
        if AuthService.DUMMY_HASH is None:
            AuthService.DUMMY_HASH = self.hash_password("dummy-password-for-timing")
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL)")

    def connect(self):
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        return db

    # ---- passwords ----
    @staticmethod
    def valid_username(u):
        return isinstance(u, str) and re.fullmatch(r"[A-Za-z0-9_]{3,32}", u) is not None

    @staticmethod
    def hash_password(password, salt=None):
        salt = salt or secrets.token_bytes(16)
        return salt.hex() + ":" + _scrypt(password, salt).hex()

    @staticmethod
    def verify_password(password, encoded):
        try:
            salt_hex, digest_hex = encoded.split(":")
            actual = _scrypt(password, bytes.fromhex(salt_hex))
            return hmac.compare_digest(actual.hex(), digest_hex)
        except (ValueError, TypeError, AttributeError):
            return False

    # ---- register / login ----
    def register(self, username, password):
        if not self.valid_username(username):
            return 400, {"error": "Invalid username format"}
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            return 400, {"error": "Password must be 12-128 characters"}
        try:
            with self.connect() as db:
                db.execute("INSERT INTO users(username,password_hash) VALUES (?,?)", (username, self.hash_password(password)))
            return 201, {"message": "Account created"}
        except sqlite3.IntegrityError:
            return 409, {"error": "Unable to create account"}

    def _rate_limited(self, keys_limits):
        now = time.time()
        if len(self.attempts) > 10000:  # prune stale keys so memory can't grow forever
            self.attempts = {k: v for k, v in self.attempts.items() if v and now - v[-1] < WINDOW}
        blocked = False
        for key, limit in keys_limits:
            recent = [t for t in self.attempts.get(key, []) if now - t < WINDOW]
            if len(recent) >= limit:
                blocked = True
            else:
                recent.append(now)
            self.attempts[key] = recent
        return blocked

    def login(self, username, password, client="local"):
        uname = str(username).lower()[:64]
        if self._rate_limited([(f"user:{client}:{uname}", MAX_ATTEMPTS), (f"client:{client}", MAX_CLIENT_ATTEMPTS)]):
            return 429, {"error": "Too many attempts. Try again later."}, None
        row = None
        if isinstance(username, str):
            with self.connect() as db:
                row = db.execute("SELECT id,password_hash FROM users WHERE username=?", (username,)).fetchone()
        pw = password if isinstance(password, str) and len(password) <= 128 else ""
        ok = self.verify_password(pw, row["password_hash"] if row else self.DUMMY_HASH)
        if row is None or not ok:
            return 401, {"error": "Invalid username or password"}, None
        return 200, {"message": "Login successful"}, self.make_token(row["id"])

    # ---- sessions (signed token + server-side session record, so logout really revokes) ----
    def make_token(self, user_id):
        sid, expiry = secrets.token_urlsafe(16), int(time.time()) + SESSION_TTL
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
            db.execute("INSERT INTO sessions(sid,user_id,expires_at) VALUES (?,?,?)", (sid, user_id, expiry))
        payload = f"{user_id}:{expiry}:{sid}"
        return payload + "." + hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def read_token(self, token):
        try:
            payload, sig = token.rsplit(".", 1)
            expected = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            uid, expiry, sid = payload.split(":")
            if int(expiry) < int(time.time()):
                return None
            with self.connect() as db:
                row = db.execute("SELECT 1 FROM sessions WHERE sid=? AND user_id=?", (sid, int(uid))).fetchone()
            return int(uid) if row else None
        except (ValueError, TypeError, AttributeError):
            return None

    def logout(self, token):
        try:
            sid = token.rsplit(".", 1)[0].split(":")[2]
        except (IndexError, AttributeError):
            return
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE sid=?", (sid,))

    def username_for(self, token):
        uid = self.read_token(token)
        if uid is None:
            return None
        with self.connect() as db:
            row = db.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        return row["username"] if row else None


def make_handler(service, cookie_secure=COOKIE_SECURE):
    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, data, extra=None):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def body(self):
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n > 4096:
                    return None
                data = json.loads(self.rfile.read(n) or b"{}")
                return data if isinstance(data, dict) else None
            except (ValueError, json.JSONDecodeError):
                return None

        def token(self):
            c = SimpleCookie()
            try:
                c.load(self.headers.get("Cookie", ""))
            except Exception:
                return None
            return c[COOKIE_NAME].value if COOKIE_NAME in c else None

        def cookie(self, value, max_age):
            return f"{COOKIE_NAME}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}" + ("; Secure" if cookie_secure else "")

        def do_GET(self):
            if self.path == "/health":
                return self.send_json(200, {"status": "ok"})
            if self.path == "/me":
                username = service.username_for(self.token() or "")
                return self.send_json(200, {"username": username}) if username else self.send_json(401, {"error": "Authentication required"})
            self.send_json(404, {"error": "Not found"})

        def do_POST(self):
            data = self.body()
            if data is None:
                return self.send_json(400, {"error": "Invalid request"})
            if self.path == "/register":
                status, result = service.register(data.get("username"), data.get("password"))
                return self.send_json(status, result)
            if self.path == "/login":
                status, result, token = service.login(data.get("username"), data.get("password"), self.client_address[0])
                return self.send_json(status, result, {"Set-Cookie": self.cookie(token, SESSION_TTL)} if token else None)
            if self.path == "/logout":
                service.logout(self.token() or "")
                return self.send_json(200, {"message": "Logged out"}, {"Set-Cookie": self.cookie("", 0)})
            self.send_json(404, {"error": "Not found"})

        def log_message(self, *args):
            pass

    return Handler


def run():
    service = AuthService()
    print("Local lab listening at http://127.0.0.1:5000")
    HTTPServer(("127.0.0.1", 5000), make_handler(service)).serve_forever()


if __name__ == "__main__":
    run()
