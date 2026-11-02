import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import HTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import AuthService, make_handler  # noqa: E402

PW = "correct-horse-battery-staple"


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = AuthService(os.path.join(self.tmp.name, "test.db"), "test-secret-for-unit-tests")

    def tearDown(self):
        self.tmp.cleanup()

    def test_password_is_hashed_and_login_works(self):
        self.assertEqual(self.s.register("tester_1", PW)[0], 201)
        with self.s.connect() as db:
            stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotIn(PW, stored)
        self.assertTrue(self.s.verify_password(PW, stored))
        status, _, token = self.s.login("tester_1", PW)
        self.assertEqual(status, 200)
        self.assertEqual(self.s.username_for(token), "tester_1")

    def test_same_password_gets_different_hashes(self):
        self.assertNotEqual(self.s.hash_password(PW), self.s.hash_password(PW))

    def test_input_validation(self):
        self.assertEqual(self.s.register("x", "short")[0], 400)
        self.assertEqual(self.s.register("bad name", "long-password-value")[0], 400)
        self.assertEqual(self.s.register("tester_1", "x" * 200)[0], 400)

    def test_generic_login_error(self):
        a = self.s.login("missing", "wrong-password-long")[1]
        self.s.register("tester_1", PW)
        b = self.s.login("tester_1", "wrong-password-long")[1]
        self.assertEqual(a, b)

    def test_rate_limit(self):
        for _ in range(5):
            self.s.login("nobody", "wrong-password", "test-client")
        self.assertEqual(self.s.login("nobody", "wrong-password", "test-client")[0], 429)

    def test_rate_limit_blocks_username_rotation(self):
        codes = [self.s.login(f"user{i}", "wrong-password", "attacker")[0] for i in range(25)]
        self.assertEqual(codes[-1], 429)

    def test_token_tampering(self):
        self.s.register("tester_1", PW)
        _, _, token = self.s.login("tester_1", PW)
        self.assertIsNotNone(self.s.read_token(token))
        self.assertIsNone(self.s.read_token(token + "x"))

    def test_token_expiry(self):
        self.s.register("tester_1", PW)
        _, _, token = self.s.login("tester_1", PW)
        with mock.patch("app.time.time", return_value=time.time() + 1000):
            self.assertIsNone(self.s.read_token(token))

    def test_logout_revokes_token(self):
        self.s.register("tester_1", PW)
        _, _, token = self.s.login("tester_1", PW)
        self.s.logout(token)
        self.assertIsNone(self.s.read_token(token))

    def test_duplicate_registration(self):
        self.assertEqual(self.s.register("tester_1", PW)[0], 201)
        self.assertEqual(self.s.register("tester_1", PW)[0], 409)
        self.assertEqual(self.s.register("TESTER_1", PW)[0], 409)


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        svc = AuthService(os.path.join(self.tmp.name, "http.db"), "test-secret-for-unit-tests")
        self.srv = HTTPServer(("127.0.0.1", 0), make_handler(svc, cookie_secure=True))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def call(self, method, path, body=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port)
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        c.request(method, path, json.dumps(body) if body is not None else None, headers)
        r = c.getresponse()
        data = json.loads(r.read() or b"{}")
        return r.status, data, r

    def test_full_flow_cookie_flags_me_and_logout(self):
        creds = {"username": "demo_user", "password": "a-long-demo-password"}
        self.assertEqual(self.call("POST", "/register", creds)[0], 201)
        status, _, r = self.call("POST", "/login", creds)
        self.assertEqual(status, 200)
        set_cookie = r.getheader("Set-Cookie")
        for flag in ("HttpOnly", "SameSite=Lax", "Secure"):
            self.assertIn(flag, set_cookie)
        cookie = set_cookie.split(";")[0]
        self.assertEqual(self.call("GET", "/me", cookie=cookie)[1]["username"], "demo_user")
        self.assertEqual(self.call("GET", "/me")[0], 401)
        self.assertEqual(self.call("POST", "/logout", {}, cookie=cookie)[0], 200)
        self.assertEqual(self.call("GET", "/me", cookie=cookie)[0], 401)  # old cookie now useless

    def test_security_headers_and_bad_body(self):
        _, _, r = self.call("GET", "/health")
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port)
        c.request("POST", "/login", "[1,2]", {"Content-Type": "application/json"})
        self.assertEqual(c.getresponse().status, 400)


if __name__ == "__main__":
    unittest.main()
