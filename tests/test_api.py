"""Local API tests (AC-10): token, Host, Origin, path allowlist, no CORS wildcard."""
import http.client
import tempfile
import json
import unittest
from pathlib import Path

from reversesuite import api

ROOT = Path("fixtures/frozen").resolve()


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.token, cls.thread = api.serve(ROOT)
        cls.open_server, cls.open_token, cls.open_thread = api.serve(None)
        cls.limited, cls.limited_token, cls.limited_thread = api.serve(None, rate_limit=3)
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.open_server.shutdown()
        cls.open_server.server_close()
        cls.limited.shutdown()
        cls.limited.server_close()

    def open_request(self, method, path, body=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.open_server.server_address[1], timeout=60)
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", "127.0.0.1:%d" % self.open_server.server_address[1])
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

    def raw(self, method, path, payload=b"", token=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.open_server.server_address[1], timeout=120)
        hdrs = dict(headers or {})
        if token:
            hdrs["Authorization"] = "Bearer " + token
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", "127.0.0.1:%d" % self.open_server.server_address[1])
        for key, value in hdrs.items():
            conn.putheader(key, value)
        if payload:
            conn.putheader("Content-Length", str(len(payload)))
        conn.endheaders()
        if payload:
            conn.send(payload)
        response = conn.getresponse()
        text = response.read().decode("utf-8", errors="replace")
        conn.close()
        return response.status, text

    def upload(self, path):
        body = Path(path).read_bytes()
        status, text = self.raw("POST", "/upload", body, self.open_token,
                                {"Content-Type": "application/octet-stream",
                                 "X-Filename": Path(path).name})
        self.assertEqual(status, 200, text[:200])
        return json.loads(text)["id"]

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
        self.assertEqual(len(doc["graph"]["edges"]), 145)

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

    def test_diff_between_two_binaries(self):
        status, text, _ = self.request("POST", "/diff", token=self.token,
                                       body={"left_path": str(ROOT / "b.exe"),
                                             "right_path": str(ROOT / "a.exe")})
        self.assertEqual(status, 200, text[:300])
        doc = json.loads(text)
        self.assertGreater(doc["summary"]["nodes"]["added"], 0)
        self.assertGreater(doc["summary"]["nodes"]["removed"], 0)
        self.assertGreater(doc["summary"]["edges"]["added"], 0)
        self.assertTrue(doc["added_nodes"])
        self.assertTrue(doc["removed_nodes"])

    def test_diff_self_is_empty(self):
        status, text, _ = self.request("POST", "/diff", token=self.token,
                                       body={"left_path": str(ROOT / "b.exe"),
                                             "right_path": str(ROOT / "b.exe")})
        self.assertEqual(status, 200)
        summary = json.loads(text)["summary"]
        self.assertEqual(summary["edges"]["added"], 0)
        self.assertEqual(summary["edges"]["removed"], 0)
        self.assertGreater(summary["edges"]["unchanged"], 0)

    def test_diff_missing_file_is_400(self):
        status, _, _ = self.request("POST", "/diff", token=self.token,
                                    body={"left_path": str(ROOT / "missing.exe"),
                                          "right_path": str(ROOT / "b.exe")})
        self.assertEqual(status, 400)

    def test_diff_outside_root_is_403(self):
        status, _, _ = self.request("POST", "/diff", token=self.token,
                                    body={"left_path": "C:/Windows/System32/notepad.exe",
                                          "right_path": str(ROOT / "b.exe")})
        self.assertEqual(status, 403)

    def test_report_returns_downloadable_html(self):
        status, text, headers = self.request("POST", "/report", token=self.token,
                                             body={"left_path": str(ROOT / "b.exe"),
                                                   "right_path": str(ROOT / "b.exe"),
                                                   "format": "html"})
        self.assertEqual(status, 200, text[:300])
        self.assertIn("attachment;", headers.get("Content-Disposition", ""))
        self.assertIn(".html", headers.get("Content-Disposition", ""))
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn("No changes detected", text)

    def test_report_markdown_format(self):
        status, text, headers = self.request("POST", "/report", token=self.token,
                                             body={"left_path": str(ROOT / "b.exe"),
                                                   "right_path": str(ROOT / "b.exe"),
                                                   "format": "md"})
        self.assertEqual(status, 200)
        self.assertIn("text/markdown", headers.get("Content-Type", ""))
        self.assertIn("# ReverseSuite diff report", text)

    def test_report_bad_format_is_400(self):
        status, _, _ = self.request("POST", "/report", token=self.token,
                                    body={"left_path": str(ROOT / "b.exe"),
                                          "right_path": str(ROOT / "b.exe"),
                                          "format": "pdf"})
        self.assertEqual(status, 400)

    def test_report_outside_root_is_403(self):
        status, _, _ = self.request("POST", "/report", token=self.token,
                                    body={"left_path": str(ROOT / "b.exe"),
                                          "right_path": "C:/Windows/System32/notepad.exe"})
        self.assertEqual(status, 403)

    def test_diff_requires_token(self):
        status, _, _ = self.request("POST", "/diff", body={"left_path": "x", "right_path": "y"})
        self.assertEqual(status, 401)

    def test_unrestricted_server_accepts_absolute_path_outside_root(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            copy_path = str(Path(tmp) / "b.exe")
            Path(copy_path).write_bytes((ROOT / "b.exe").read_bytes())
            status, text, _ = self.open_request("POST", "/analyze", token=self.open_token,
                                                body={"path": copy_path})
            self.assertEqual(status, 200, text[:300])
            self.assertEqual(json.loads(text)["target"]["size"], 21006)

    def test_locked_server_still_rejects_outside_root(self):
        status, _, _ = self.request("POST", "/analyze", token=self.token,
                                    body={"path": "C:/Windows/System32/notepad.exe"})
        self.assertEqual(status, 403)

    def test_analyze_from_url(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        payload = (ROOT / "b.exe").read_bytes()

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = "http://127.0.0.1:%d/b.exe" % srv.server_address[1]
            before = set(Path(tempfile.gettempdir()).glob("reversesuite-dl-*"))
            status, text, _ = self.open_request("POST", "/analyze", token=self.open_token,
                                                body={"path": url})
            after = set(Path(tempfile.gettempdir()).glob("reversesuite-dl-*"))
            self.assertEqual(status, 200, text[:300])
            doc = json.loads(text)
            self.assertEqual(doc["target"]["size"], 21006)
            self.assertEqual(doc["source"], url)
            self.assertEqual(before, after)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_url_404_is_400(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_error(404)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = "http://127.0.0.1:%d/missing.exe" % srv.server_address[1]
            status, text, _ = self.open_request("POST", "/analyze", token=self.open_token,
                                                body={"path": url})
            self.assertEqual(status, 400)
            self.assertIn("http_404", text)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_url_non_pe_is_400(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"not a pe file at all"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = "http://127.0.0.1:%d/text.txt" % srv.server_address[1]
            status, text, _ = self.open_request("POST", "/analyze", token=self.open_token,
                                                body={"path": url})
            self.assertEqual(status, 400)
            self.assertIn("not_a_pe_file", text)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_favicon_is_served_without_token(self):
        status, text, headers = self.request("GET", "/favicon.ico")
        self.assertEqual(status, 204)
        self.assertEqual(text, "")

    def test_rate_limit_returns_429(self):
        port = self.limited.server_address[1]
        codes = []
        for _ in range(5):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            conn.putrequest("GET", "/rules", skip_host=True)
            conn.putheader("Host", "127.0.0.1:%d" % port)
            conn.putheader("Authorization", "Bearer " + self.limited_token)
            conn.endheaders()
            codes.append(conn.getresponse().status)
            conn.close()
        self.assertIn(429, codes, codes)
        self.assertIn(200, codes, codes)

    def test_private_url_target_is_rejected(self):
        status, text, _ = self.open_request("POST", "/analyze", token=self.open_token,
                                             body={"path": "http://10.0.0.1/evil.exe"})
        self.assertEqual(status, 400)
        self.assertIn("url_host_not_allowed", text)

    def test_upload_then_analyze(self):
        upload_id = self.upload(ROOT / "b.exe")
        status, text, _ = self.open_request("POST", "/analyze", token=self.open_token,
                                            body={"upload_id": upload_id})
        self.assertEqual(status, 200, text[:200])
        self.assertEqual(json.loads(text)["target"]["size"], 21006)

    def test_upload_rejects_non_pe(self):
        status, text = self.raw("POST", "/upload", b"hello world", self.open_token,
                                {"Content-Type": "application/octet-stream", "X-Filename": "x.exe"})
        self.assertEqual(status, 400)
        self.assertIn("not_a_pe_file", text)

    def test_unknown_upload_is_400(self):
        status, text, _ = self.open_request("POST", "/analyze", token=self.open_token,
                                            body={"upload_id": "deadbeef"})
        self.assertEqual(status, 400)
        self.assertIn("upload_not_found", text)

    def test_diff_with_uploads(self):
        left = self.upload(ROOT / "b.exe")
        right = self.upload(ROOT / "a.exe")
        status, text, _ = self.open_request("POST", "/diff", token=self.open_token,
                                            body={"left_upload_id": left, "right_upload_id": right})
        self.assertEqual(status, 200, text[:200])
        summary = json.loads(text)["summary"]
        self.assertGreater(summary["nodes"]["added"], 0)
        self.assertGreater(summary["nodes"]["removed"], 0)

    def _serve_binaries(self, mapping):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                payload = mapping.get(self.path)
                if payload is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_diff_accepts_absolute_paths_outside_root(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            left = Path(tmp) / "b.exe"
            right = Path(tmp) / "a.exe"
            left.write_bytes((ROOT / "b.exe").read_bytes())
            right.write_bytes((ROOT / "a.exe").read_bytes())
            status, text, _ = self.open_request("POST", "/diff", token=self.open_token,
                                                body={"left_path": str(left),
                                                      "right_path": str(right)})
        self.assertEqual(status, 200, text[:300])
        self.assertGreater(json.loads(text)["summary"]["nodes"]["added"], 0)

    def test_diff_accepts_urls(self):
        port = self._serve_binaries({"/b.exe": (ROOT / "b.exe").read_bytes(),
                                     "/a.exe": (ROOT / "a.exe").read_bytes()})
        status, text, _ = self.open_request("POST", "/diff", token=self.open_token,
                                            body={"left_path": "http://127.0.0.1:%d/b.exe" % port,
                                                  "right_path": "http://127.0.0.1:%d/a.exe" % port})
        self.assertEqual(status, 200, text[:300])
        summary = json.loads(text)["summary"]
        self.assertGreater(summary["nodes"]["removed"], 0)

    def test_report_accepts_urls(self):
        port = self._serve_binaries({"/b.exe": (ROOT / "b.exe").read_bytes(),
                                     "/a.exe": (ROOT / "a.exe").read_bytes()})
        status, text, headers = self.open_request("POST", "/report", token=self.open_token,
                                                  body={"left_path": "http://127.0.0.1:%d/b.exe" % port,
                                                        "right_path": "http://127.0.0.1:%d/a.exe" % port,
                                                        "format": "html"})
        self.assertEqual(status, 200, text[:300])
        self.assertIn("attachment;", headers.get("Content-Disposition", ""))

    def test_locked_server_rejects_outside_path_for_diff(self):
        status, text, _ = self.request("POST", "/diff", token=self.token,
                                       body={"left_path": "C:/Windows/System32/notepad.exe",
                                             "right_path": str(ROOT / "b.exe")})
        self.assertEqual(status, 403)

    def test_ui_exposes_interactive_graph(self):
        status, text, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn('<svg id="graph"', text)
        self.assertIn("view call graph", text)
        self.assertIn("view diff graph", text)
        self.assertIn("export svg", text)
        self.assertIn("export png", text)
        self.assertIn("XMLSerializer", text)
        self.assertIn('id="browse-analyze"', text)
        self.assertIn("simulateForce", text)
        self.assertIn("dragenter", text)
        self.assertIn("/upload", text)
        self.assertIn("addEventListener(\"wheel\"", text)
        self.assertIn("http://www.w3.org/2000/svg", text)
        self.assertNotIn("d3", text)
        self.assertNotIn("chart.js", text.lower())

    def test_path_fields_are_textareas(self):
        status, text, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn('<textarea id="path"', text)
        self.assertIn('<textarea id="left"', text)

    def test_ui_shell_has_diff_section(self):
        status, text, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("Diff &amp; Report", text)
        self.assertIn("/report", text)
        self.assertIn("createObjectURL", text)
        self.assertNotIn("http://cdn", text)


if __name__ == "__main__":
    unittest.main()