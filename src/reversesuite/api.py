"""Local HTTP API (M3 slice 1) per PLAN 2.1.

Security rules enforced here:
- bind 127.0.0.1 only, port chosen by the OS (0) unless pinned
- per-session bearer token (random, never persisted) required on every data route
- token travels in the Authorization header only, never in the query string
- Host must be localhost/127.0.0.1; foreign Origin is rejected
- no CORS wildcard: Access-Control-Allow-Origin is never emitted
- every analysed path must resolve inside the allowlisted root
"""
from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlsplit

from . import callgraph, functions, loader, rules, schema, strings

MAX_BODY = 64 * 1024


def new_token() -> str:
    return secrets.token_urlsafe(32)


def analyze_bytes(data: bytes, workers: int = 1) -> dict:
    """Run loader + functions + strings + call graph and return a canonical doc."""
    result = loader.parse(data)
    if result.status == "failed":
        return result.canonical()
    text = loader.text_bytes(data)
    found = []
    if functions.skip_reason(len(text)) is None:
        found = functions.discover(text, exports=loader.export_addresses(data),
                                   entry=functions.entry_point(data))
    else:
        result.diagnostics.append(schema.Diagnostic(functions.FUNCTION_SKIP_TEXT_TOO_LARGE,
                                                    "function discovery skipped", "info",
                                                    {"text_bytes": len(text)}))
    items = strings.extract(data)
    reason = strings.xref_skip_reason(len(text))
    if reason is None:
        refs = strings.find_xrefs(text, items, workers=workers)
        items = [strings.ExtractedString(s.address, s.value, s.encoding, s.section,
                                         s.length, refs.get(s.address, ())) for s in items]
    else:
        result.diagnostics.append(schema.Diagnostic(strings.XREF_SKIP_TEXT_TOO_LARGE,
                                                    "xref pass skipped", "info",
                                                    {"text_bytes": len(text)}))
    graph = callgraph.build(data, funcs=found) if found else callgraph.CallGraph()
    result.findings.extend(schema.enforce_rules(
        functions.to_findings(found) + strings.to_findings(items) + callgraph.to_findings(graph)))
    doc = result.canonical()
    doc["graph"] = graph.as_dict()
    return doc


def resolve_in_root(root: Path, raw: str) -> Optional[Path]:
    try:
        candidate = Path(raw).resolve(strict=False)
    except Exception:
        return None
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


UI_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ReverseSuite</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:60rem}
input,button{font:inherit;padding:.3rem .5rem}pre{background:#f4f4f4;padding:1rem;overflow:auto}</style>
</head><body>
<h1>ReverseSuite</h1>
<p>Token stays in memory only (sent as an Authorization header, never in the URL).</p>
<p><input id="token" type="password" placeholder="session token" size="40">
<button id="save">use token</button></p>
<p><input id="path" placeholder="absolute path inside the allowlisted root" size="60">
<button id="run">analyze</button></p>
<pre id="out">ready</pre>
<script>
const tokenInput = document.getElementById("token");
document.getElementById("save").onclick = () => {
  sessionStorage.setItem("rs-token", tokenInput.value.trim());
  document.getElementById("out").textContent = "token saved for this tab";
};
document.getElementById("run").onclick = async () => {
  const token = sessionStorage.getItem("rs-token") || "";
  const path = document.getElementById("path").value;
  const res = await fetch("/analyze", {
    method: "POST",
    headers: {"Content-Type": "application/json", "Authorization": "Bearer " + token},
    body: JSON.stringify({path: path})
  });
  const text = await res.text();
  document.getElementById("out").textContent = res.status + " " + text.slice(0, 4000);
};
</script></body></html>"""

def make_handler(token: str, root: Path, workers: int = 1):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ReverseSuite/0.3"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _send_html(self, status: int, document: str) -> None:
            body = document.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
            return host in ("localhost", "127.0.0.1", "[::1]")

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            if not origin:
                return True
            parts = urlsplit(origin)
            return (parts.scheme in ("http", "https")
                    and (parts.hostname or "").lower() in ("localhost", "127.0.0.1"))

        def _authorised(self) -> bool:
            header = self.headers.get("Authorization") or ""
            if not header.startswith("Bearer "):
                return False
            return secrets.compare_digest(header[7:].strip(), token)

        def _guard(self) -> bool:
            if not self._host_ok():
                self._send(403, {"error": "host_not_allowed"})
                return False
            if not self._origin_ok():
                self._send(403, {"error": "origin_not_allowed"})
                return False
            if self.path.split("?")[0] == "/healthz":
                self._send(200, {"ok": True})
                return False
            if not self._authorised():
                self._send(401, {"error": "unauthorised"})
                return False
            return True

        def do_GET(self) -> None:
            if not self._host_ok():
                self._send(403, {"error": "host_not_allowed"})
                return
            if not self._origin_ok():
                self._send(403, {"error": "origin_not_allowed"})
                return
            route = self.path.split("?")[0]
            if route == "/":
                self._send_html(200, UI_HTML)
                return
            if not self._guard():
                return
            if route == "/rules":
                self._send(200, {"rules": [{"id": r.id, "version": r.version}
                                           for r in rules.all_rules()]})
                return
            self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if not self._guard():
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                self._send(400, {"error": "bad_body"})
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception:
                self._send(400, {"error": "bad_json"})
                return
            if self.path.split("?")[0] != "/analyze":
                self._send(404, {"error": "not_found"})
                return
            target = resolve_in_root(root, str(payload.get("path", "")))
            if target is None or not target.is_file():
                self._send(403, {"error": "path_not_allowed"})
                return
            try:
                doc = analyze_bytes(target.read_bytes(), int(payload.get("workers", workers)))
            except Exception as exc:
                self._send(500, {"error": "analysis_failed", "detail": exc.__class__.__name__})
                return
            self._send(200, doc)

    return Handler


def serve(root: Path, token: Optional[str] = None, port: int = 0,
          workers: int = 1) -> Tuple[ThreadingHTTPServer, str, threading.Thread]:
    token = token or new_token()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(token, root, workers))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, token, thread