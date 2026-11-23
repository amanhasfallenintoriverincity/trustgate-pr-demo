"""Intentional SQLi/path-traversal lab. Synthetic data; TrustGate worker ONLY."""
import json
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import parse_qs, urlsplit

# Public DEMO constants, NOT real credentials or secrets. No .env access.
DEMO_ALICE_PASSWORD = "DEMO-ALICE-PASSWORD-NOT-A-SECRET"
DEMO_ADMIN_PASSWORD = "DEMO-ADMIN-PASSWORD-NOT-A-SECRET"
DEMO_GUIDE = "DEMO PUBLIC GUIDE: all accounts and files are synthetic.\n"
DEMO_CANARY = "DEMO CANARY: SYNTHETIC-ONLY-NOT-A-SECRET\n"
DEMO_ADMIN_DATA = {"record": "DEMO-ADMIN-RECORD", "content": "Synthetic protected training data only."}
MAX_BODY = 4096
PUBLIC_FILES = {"guide.txt": "guide.txt"}


class LabServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, port, temp_parent):
        self.temp = tempfile.TemporaryDirectory(prefix="trustgate-security-lab-", dir=temp_parent)
        self.state_root = Path(self.temp.name).resolve()
        self.lock = threading.Lock()
        self.sessions = {}
        self._closed = False
        self.db = None
        try:
            (self.state_root / "docs").mkdir()
            (self.state_root / "private").mkdir()
            (self.state_root / "docs" / "guide.txt").write_text(DEMO_GUIDE, encoding="utf-8")
            (self.state_root / "private" / "canary.txt").write_text(DEMO_CANARY, encoding="utf-8")
            self.db = sqlite3.connect(":memory:", check_same_thread=False)
            self.db.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, role TEXT)")
            self.db.executemany("INSERT INTO users VALUES (?, ?, ?)", [
                ("alice", DEMO_ALICE_PASSWORD, "user"), ("admin", DEMO_ADMIN_PASSWORD, "admin")])
            self.db.commit()
            super().__init__(("127.0.0.1", port), LabHandler)
        except Exception:
            if self.db is not None:
                self.db.close()
            self.temp.cleanup()
            raise

    def server_close(self):
        if self._closed:
            return
        self._closed = True
        try:
            super().server_close()
        finally:
            if self.db is not None:
                self.db.close()
            self.sessions.clear()
            self.temp.cleanup()

    def handle_error(self, request, client_address):
        # No request bodies, paths, exception details or local paths in logs.
        pass


class LabHandler(BaseHTTPRequestHandler):
    @property
    def lab(self) -> LabServer:
        return cast(LabServer, self.server)

    protocol_version = "HTTP/1.1"
    server_version = "SyntheticTrainingLab"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(4)

    def log_message(self, format, *args):
        pass

    def _send(self, status, body):
        data = json.dumps(body, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(data)

    def _error(self, status, message):
        self._send(status, {"error": message})

    def _login(self):
        if self.headers.get("Transfer-Encoding"):
            return self._error(400, "invalid request")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            return self._error(400, "invalid request")
        size = int(lengths[0])
        if size > MAX_BODY:
            return self._error(413, "request too large")
        if size < 1:
            return self._error(400, "invalid request")
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            return self._error(415, "JSON required")
        raw = self.rfile.read(size)
        if len(raw) != size:
            return self._error(400, "invalid request")
        body = json.loads(raw.decode("utf-8"))
        if not isinstance(body, dict):
            return self._error(400, "invalid request")
        username, password = body.get("username"), body.get("password")
        if not all(isinstance(value, str) and 0 < len(value) <= 512 for value in (username, password)):
            return self._error(400, "invalid request")
        with self.lab.lock:
            try:
                db = self.lab.db
                assert db is not None
                # Intentional flaw: untrusted text is executed as SQLite syntax.
                row = db.execute(
                    f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
                ).fetchone()
            except sqlite3.Error:
                row = None
            if row is None:
                return self._error(401, "invalid credentials")
            if len(self.lab.sessions) >= 256:
                return self._error(503, "demo session limit")
            user = {"username": row[0], "role": row[1]}
            session = secrets.token_hex(24)
            self.lab.sessions[session] = user
        self._send(200, {"session": session, "user": user})

    def _admin(self):
        auth = self.headers.get_all("Authorization", [])
        token = auth[0][7:] if len(auth) == 1 and auth[0].startswith("Bearer ") else ""
        with self.lab.lock:
            user = self.lab.sessions.get(token)
        if user is None:
            return self._error(401, "authentication required")
        if user["role"] != "admin":
            return self._error(403, "forbidden")
        self._send(200, {"data": DEMO_ADMIN_DATA})

    def _download(self, query):
        values = parse_qs(query, keep_blank_values=True, max_num_fields=8)
        files = values.get("file", [])
        if set(values) != {"file"} or len(files) != 1:
            return self._error(403, "forbidden")
        name = files[0]  # parse_qs decodes percent escapes exactly once.
        if not name or "\x00" in name or "\\" in name:
            return self._error(403, "forbidden")
        # Intentional flaw: resolve relative to docs, not an explicit document ID.
        target = (self.lab.state_root / "docs" / name).resolve()
        # Demo safety boundary: NEVER read outside this generated synthetic root.
        try:
            target.relative_to(self.lab.state_root)
        except ValueError:
            return self._error(403, "forbidden")
        try:
            content = target.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return self._error(403, "forbidden")
        self._send(200, {"file": name, "content": content})

    def _dispatch(self, method):
        try:
            url = urlsplit(self.path)
            if method == "POST" and url.path == "/api/login":
                return self._login()
            if method == "GET" and url.path == "/api/admin/data":
                return self._admin()
            if method == "GET" and url.path == "/api/download":
                return self._download(url.query)
            if method == "GET" and url.path == "/healthz":
                return self._send(200, {"status": "ok"})
            self._error(404, "not found")
        except (ValueError, UnicodeError, OSError, sqlite3.Error, RecursionError):
            self._error(400, "invalid request")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def create_server(port=18081, *, temp_parent=None):
    """Bind ONLY loopback; caller owns serve_forever/shutdown/server_close."""
    return LabServer(port, temp_parent if temp_parent is not None else os.environ.get("TMPDIR"))


def main():
    server = create_server()

    def stop(signum, frame):
        # shutdown must run off the serve_forever thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, stop)
    try:
        print("Synthetic training lab: worker loopback 127.0.0.1:18081", flush=True)
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
