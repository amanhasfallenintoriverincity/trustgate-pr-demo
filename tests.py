"""Identical controls for both snapshots; run ONLY inside a TrustGate worker."""
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import quote

from server import create_server

# Public synthetic fixtures, never production credentials or personal data.
ALICE_PASSWORD = "DEMO-ALICE-PASSWORD-NOT-A-SECRET"
ADMIN_PASSWORD = "DEMO-ADMIN-PASSWORD-NOT-A-SECRET"
GUIDE = "DEMO PUBLIC GUIDE: all accounts and files are synthetic.\n"
CANARY = "DEMO CANARY: SYNTHETIC-ONLY-NOT-A-SECRET\n"
ADMIN_DATA = {"record": "DEMO-ADMIN-RECORD", "content": "Synthetic protected training data only."}


class SecurityLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trustgate-lab-test-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.server = create_server(port=0, temp_parent=self.temp.name)
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self):
        self.server.shutdown()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive(), "demo server must shut down")

    def _request(self, path, method="GET", payload=None, raw=None, token=None, headers=None):
        request_headers = {}
        if payload is not None:
            raw = json.dumps(payload).encode("utf-8")
        if raw is not None:
            request_headers["Content-Type"] = "application/json"
        if token is not None:
            request_headers["Authorization"] = "Bearer " + token
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=4)
        try:
            connection.request(method, path, body=raw, headers=request_headers)
            response = connection.getresponse()
            self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
            return response.status, json.loads(response.read().decode("utf-8"))
        finally:
            connection.close()

    def _login(self, username, password):
        return self._request("/api/login", method="POST", payload={"username": username, "password": password})

    def _assert_injection_denied(self, username, password):
        status, login = self._login(username, password)
        # Follow any issued session to the real resource BEFORE asserting denial.
        resource_status, resource = self._request("/api/admin/data", token=login.get("session"))
        observed = {"login_status": status, "admin_status": resource_status,
                    "protected_data_leaked": resource.get("data") == ADMIN_DATA}
        self.assertEqual(observed, {"login_status": 401, "admin_status": 401, "protected_data_leaked": False},
                         "actual login/resource responses: " + json.dumps({"login": login, "resource": resource}))
        self.assertNotIn("session", login)
        self.assertNotIn("data", resource)

    def _assert_file_denied(self, raw_query_value):
        status, body = self._request("/api/download?file=" + raw_query_value)
        self.assertEqual({"status": status, "canary_leaked": CANARY in body.get("content", "")},
                         {"status": 403, "canary_leaked": False}, "actual file response: " + json.dumps(body))
        self.assertNotIn("content", body)

    def test_normal_loopback_and_real_synthetic_files(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.server.state_root.relative_to(Path(self.temp.name).resolve())
        self.assertEqual((self.server.state_root / "docs" / "guide.txt").read_text(encoding="utf-8"), GUIDE)
        self.assertEqual((self.server.state_root / "private" / "canary.txt").read_text(encoding="utf-8"), CANARY)

    def test_normal_alice_login(self):
        status, body = self._login("alice", ALICE_PASSWORD)
        self.assertEqual(status, 200)
        self.assertEqual(body["user"], {"username": "alice", "role": "user"})
        self.assertIsInstance(body["session"], str)
        self.assertGreaterEqual(len(body["session"]), 24)

    def test_normal_admin_login_and_protected_data(self):
        status, body = self._login("admin", ADMIN_PASSWORD)
        self.assertEqual(status, 200)
        self.assertEqual(body["user"], {"username": "admin", "role": "admin"})
        self.assertEqual(self._request("/api/admin/data", token=body["session"]), (200, {"data": ADMIN_DATA}))

    def test_normal_invalid_password(self):
        for username in ("alice", "admin", "missing-demo-user"):
            with self.subTest(username=username):
                self.assertEqual(self._login(username, "DEMO-WRONG-PASSWORD"), (401, {"error": "invalid credentials"}))

    def test_normal_admin_without_session_is_denied(self):
        self.assertEqual(self._request("/api/admin/data"), (401, {"error": "authentication required"}))

    def test_normal_alice_cannot_read_admin_data(self):
        status, body = self._login("alice", ALICE_PASSWORD)
        self.assertEqual(status, 200)
        self.assertEqual(self._request("/api/admin/data", token=body["session"]), (403, {"error": "forbidden"}))

    def test_normal_guessed_sessions_are_denied(self):
        for token in ("admin", "alice", ADMIN_PASSWORD, "DEMO-UNKNOWN-SESSION"):
            with self.subTest(token=token):
                self.assertEqual(self._request("/api/admin/data", token=token), (401, {"error": "authentication required"}))

    def test_normal_public_guide(self):
        self.assertEqual(self._request("/api/download?file=guide.txt"), (200, {"file": "guide.txt", "content": GUIDE}))

    def test_normal_role_header_does_not_authenticate(self):
        self.assertEqual(self._request("/api/admin/data", headers={"X-Role": "admin", "X-User": "admin"}),
                         (401, {"error": "authentication required"}))

    def test_normal_file_reads_cannot_leave_synthetic_root(self):
        outside = Path(self.temp.name) / "outside-demo.txt"
        outside.write_text("DEMO OUTSIDE STATE ROOT", encoding="utf-8")
        self._assert_file_denied(quote(str(outside), safe=""))

    def test_normal_server_close_removes_synthetic_files(self):
        extra = create_server(port=0, temp_parent=self.temp.name)
        root = extra.state_root
        try:
            self.assertTrue((root / "private" / "canary.txt").is_file())
        finally:
            extra.server_close()
        self.assertFalse(root.exists())

    def test_normal_public_guide_encoded_id(self):
        self.assertEqual(self._request("/api/download?file=guide%2Etxt"), (200, {"file": "guide.txt", "content": GUIDE}))

    def test_normal_request_body_limit(self):
        body = json.dumps({"username": "alice", "password": ALICE_PASSWORD}).encode("utf-8")
        status, _ = self._request("/api/login", method="POST", raw=body + b" " * (4096 - len(body)))
        self.assertEqual(status, 200)
        self.assertEqual(self._request("/api/login", method="POST", raw=b" " * 4097),
                         (413, {"error": "request too large"}))

    def test_normal_invalid_json_and_fields(self):
        for body in (b"{", b"[]", b"null", b"{}", b"\xff", b"[" * 1100 + b"0" + b"]" * 1100,
                     b'{"username":1,"password":"demo"}',
                     b'{"username":"alice","password":false}', b'{"username":"alice","password":""}'):
            with self.subTest(body=body):
                self.assertEqual(self._request("/api/login", method="POST", raw=body),
                                 (400, {"error": "invalid request"}))
        self.assertEqual(self._request("/api/login", method="POST", raw=b"{}", headers={"Content-Type": "text/plain"}),
                         (415, {"error": "JSON required"}))

    def test_security_username_sql_injection_cannot_reach_admin(self):
        for username in ("admin' -- ", "missing' OR username='admin' -- "):
            with self.subTest(username=username):
                self._assert_injection_denied(username, "DEMO-WRONG-PASSWORD")

    def test_security_password_sql_injection_cannot_reach_admin(self):
        self._assert_injection_denied("admin", "' OR username='admin' -- ")

    def test_security_literal_quote_username_is_data(self):
        self.assertEqual(self._login("alice'", ALICE_PASSWORD), (401, {"error": "invalid credentials"}))
        self.assertEqual(self._login("alice", ALICE_PASSWORD)[0], 200)

    def test_security_traversal_cannot_read_real_canary(self):
        self._assert_file_denied("../private/canary.txt")

    def test_security_encoded_traversal_cannot_read_real_canary(self):
        for value in ("%2e%2e%2fprivate%2fcanary.txt", "..%2fprivate%2fcanary.txt", "%2E%2E/private/canary.txt"):
            with self.subTest(file=value):
                self._assert_file_denied(value)

    def test_security_absolute_path_is_not_a_document_id(self):
        self._assert_file_denied(quote(str(self.server.state_root / "private" / "canary.txt"), safe=""))

    def test_security_ambiguous_and_malformed_file_ids_are_denied(self):
        for value in ("guide.txt%00", "..%5cprivate%5ccanary.txt", "", "guide.txt&file=../private/canary.txt"):
            with self.subTest(file=value):
                self._assert_file_denied(value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
