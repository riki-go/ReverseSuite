"""Local API tests (AC-10): token, Host, Origin, path allowlist, no CORS wildcard."""
import http.client
import json
import unittest
from pathlib import Path

from reversesuite import api

ROOT = Path("fixtures/frozen").resolve()


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.token, cls.thread = api.serve(ROOT)
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, token=None, host=None, origin=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        if origin:
            headers["Origin"] = origin
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", host or "127.0.0.1:%d" % self.port)
        for key, value in headers.items():
            conn.putheader(key, value)
        if data is not None:
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders()
        if data is not None:
            conn.send(data)
        response = conn.getresponse()
        text = response.read().decode("utf-8", errors="replace")
        conn.close()
        return response.status, text, dict(response.getheaders())

    def test_health_without_token(self):
        status, text, _ = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(text), {"ok": True})

    def test_missing_token_is_401(self):
        status, _, _ = self.request("GET", "/rules")
        self.assertEqual(status, 401)

    def test_token_in_query_does_not_authenticate(self):
        status, _, _ = self.request("GET", "/rules?token=" + self.token)
        self.assertEqual(status, 401)

    def test_bad_host_is_403(self):
        status, _, _ = self.request("GET", "/rules", token=self.token, host="evil.example:80")
        self.assertEqual(status, 403)

    def test_bad_origin_is_403(self):
        status, _, _ = self.request("GET", "/rules", token=self.token,
                                    origin="https://evil.example")
        self.assertEqual(status, 403)

    def test_allowed_origin_is_fine(self):
        status, _, _ = self.request("GET", "/rules", token=self.token,
                                    origin="http://localhost:3000")
        self.assertEqual(status, 200)

    def test_no_cors_wildcard_header(self):
        _, _, headers = self.request("GET", "/rules", token=self.token,
                                     origin="http://127.0.0.1:3000")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_analyze_requires_token(self):
        status, _, _ = self.request("POST", "/analyze", body={"path": str(ROOT / "b.exe")})
        self.assertEqual(status, 401)

    def test_analyze_returns_canonical_document(self):
        status, text, _ = self.request("POST", "/analyze", token=self.token,
                                       body={"path": str(ROOT / "b.exe")})
        self.assertEqual(status, 200, text[:200])
        doc = json.loads(text)
        self.assertEqual(doc["status"], "ok")
        self.assertEqual(doc["target"]["size"], 21006)
        self.assertGreaterEqual(len(doc["findings"]), 300)
        self.assertEqual(len(doc["graph"]["edges"]), 129)

    def test_path_outside_root_is_403(self):
        status, _, _ = self.request("POST", "/analyze", token=self.token,
                                    body={"path": "C:/Windows/System32/notepad.exe"})
        self.assertEqual(status, 403)

    def test_ui_shell_is_served_without_token(self):
        status, text, headers = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("ReverseSuite", text)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertNotIn("Access-Control-Allow-Origin", headers)


if __name__ == "__main__":
    unittest.main()