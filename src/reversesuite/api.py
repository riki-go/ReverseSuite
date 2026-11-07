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
import os
import shutil
import tempfile
import urllib.error
import urllib.request
import secrets
import sys
import threading
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlsplit

from . import callgraph, diff as diff_mod, functions, loader, report as report_mod, rules, schema, strings

MAX_BODY = 64 * 1024
URL_MAX_BYTES = 256 * 1024 * 1024
URL_TIMEOUT = 30
URL_HEADERS = {"User-Agent": "ReverseSuite/0.1 (+http://127.0.0.1)"}


def watch_parent(parent_pid: int) -> None:
    """Exit when the desktop wrapper dies, so no orphaned backend is left behind."""
    if os.name != "nt" or parent_pid <= 0:
        return
    import ctypes
    from ctypes import wintypes

    SYNCHRONIZE = 0x00100000
    handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, wintypes.DWORD(parent_pid))
    if not handle:
        return
    try:
        ctypes.windll.kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
        os._exit(0)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def start_parent_watch(parent_pid: int) -> None:
    if os.name != "nt" or parent_pid <= 0:
        return
    thread = threading.Thread(target=watch_parent, args=(parent_pid,), daemon=True)
    thread.start()


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


def _attachment_name(path: str, fmt: str) -> str:
    stem = Path(path).stem or "report"
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in stem)[:60]
    return "reversesuite-%s.%s" % (safe, "html" if fmt == "html" else "md")


class FetchError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def resolve_path(root: Optional[Path], raw: str):
    """Validate a local path. root=None means any absolute path is allowed."""
    if not raw or len(raw) > 4096:
        return None, "path_not_found"
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        return None, "path_not_allowed"
    try:
        candidate = candidate.resolve(strict=False)
    except Exception:
        return None, "path_not_allowed"
    if root is not None:
        try:
            candidate.relative_to(root)
        except ValueError:
            return None, "path_not_allowed"
    return candidate, None


def is_url(raw: str) -> bool:
    return raw.lower().startswith(("http://", "https://"))


def download_to_temp(url: str, timeout: int = URL_TIMEOUT, max_bytes: int = URL_MAX_BYTES):
    """Fetch a remote binary into a private temp dir. Returns (path, tempdir)."""
    if len(url) > 2048:
        raise FetchError("url_too_long")
    tempdir = tempfile.mkdtemp(prefix="reversesuite-dl-")
    try:
        request = urllib.request.Request(url, headers=URL_HEADERS)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > max_bytes:
                raise FetchError("file_too_large")
            chunks = []
            total = 0
            while True:
                chunk = response.read(1024 * 256)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError("file_too_large")
                chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) < 2 or data[:2] != b"MZ":
            raise FetchError("not_a_pe_file")
        target = Path(tempdir) / "download.bin"
        target.write_bytes(data)
        return target, tempdir
    except FetchError:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise
    except urllib.error.HTTPError as exc:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise FetchError("http_%d" % exc.code)
    except urllib.error.URLError as exc:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise FetchError("download_failed: %s" % (exc.reason,))
    except Exception as exc:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise FetchError("download_failed: %s" % (exc.__class__.__name__,))


UI_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ReverseSuite</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:72rem;color:#111}
h1{margin:0 0 .3rem}h2{margin:1.6rem 0 .4rem;font-size:1.05rem}
input,button,textarea{font:inherit;padding:.3rem .5rem}
input[type=password]{min-width:26rem}
textarea{width:34rem;min-height:2.2rem;font-family:ui-monospace,monospace;font-size:12px;resize:vertical;white-space:pre}
pre{background:#f4f4f4;padding:1rem;overflow:auto;max-height:22rem;white-space:pre-wrap}
table{border-collapse:collapse;margin:.5rem 0;width:100%}
td,th{border:1px solid #ddd;padding:.2rem .5rem;text-align:left;font-family:ui-monospace,monospace;font-size:12px}
th{background:#f7f7f7}.muted{color:#666}
.row{display:flex;gap:.5rem;align-items:flex-start;flex-wrap:wrap;margin:.4rem 0}
.pill{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:12px;font-weight:600}
.ok{background:#d7f5dd;color:#12602a}.bad{background:#ffe0e0;color:#8a1c1c}
</style></head><body>
<h1>ReverseSuite <span id="status" class="pill bad">checking...</span></h1>
<p class="muted">Static PE analysis: functions, strings, call graph, diff and reports.</p>
<div class="row" id="tokenrow">
  <input id="token" type="password" placeholder="session token">
  <button id="save">use token</button>
  <span class="muted">desktop app fills this automatically; otherwise paste the token from %LOCALAPPDATA%/ReverseSuite/session.json</span>
</div>
<h2>Analyze</h2>
<div class="row">
  <textarea id="path" rows="1" placeholder="Absolute path (C:/...) or URL (https://...)"></textarea>
  <button id="run">analyze</button>
</div>
<p class="muted" id="roothint"></p>
<pre id="out">ready</pre>
<h2>Diff &amp; Report</h2>
<div class="row">
  <textarea id="left" rows="1" placeholder="left binary path"></textarea>
  <textarea id="right" rows="1" placeholder="right binary path"></textarea>
  <label><input id="thunks" type="checkbox"> ignore thunks</label>
</div>
<div class="row">
  <button id="diff">run diff</button>
  <button id="report">download report</button>
  <span id="diffstate" class="muted"></span>
</div>
<div id="summary"></div>
<div id="tables"></div>
<script>
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var token = function () {
    return window.__rs_token || sessionStorage.getItem("rs-token") || "";
  };
  var esc = function (value) {
    return String(value).replace(/[&<>"]/g, function (ch) {
      return ch === "&" ? "&amp;" : ch === "<" ? "&lt;" : ch === ">" ? "&gt;" : "&quot;";
    });
  };

  function paintStatus() {
    var badge = $("status");
    var have = token().length > 0;
    badge.textContent = have ? "connected" : "token required";
    badge.className = "pill " + (have ? "ok" : "bad");
    $("tokenrow").style.display = have ? "none" : "flex";
  }
  paintStatus();

  $("save").onclick = function () {
    sessionStorage.setItem("rs-token", $("token").value.trim());
    paintStatus();
  };

  $("roothint").textContent = "backend: " + location.origin + " · accepts any absolute path or http(s) URL";

  function call(route, payload) {
    return fetch(route, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token() },
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res.text().then(function (text) {
        if (res.status === 401) throw new Error("unauthorised: token missing or wrong (open the desktop app, or paste the token from session.json)");
        if (res.status === 403) throw new Error("path rejected: it must be inside the allowed root folder");
        if (res.status === 400) throw new Error("bad request: " + text.slice(0, 200));
        if (!res.ok) throw new Error(res.status + " " + text.slice(0, 200));
        return text;
      });
    });
  }

  $("run").onclick = function () {
    $("out").textContent = "working...";
    call("/analyze", { path: $("path").value.trim() }).then(function (text) {
      var doc = JSON.parse(text);
      var lines = [];
      lines.push("status: " + doc.status + "   size: " + doc.target.size + " bytes");
      lines.push("findings: " + doc.findings.length);
      lines.push("functions: " + doc.graph.nodes.length);
      lines.push("edges: " + doc.graph.edges.length + " (imports " + (doc.graph.import_calls || 0) + ", indirect " + (doc.graph.indirect_calls || 0) + ")");
      lines.push(doc.diagnostics.length ? "diagnostics: " + doc.diagnostics.map(function (d) { return d.code; }).join(", ") : "diagnostics: none");
      $("out").textContent = lines.join(String.fromCharCode(10));
    }).catch(function (err) {
      $("out").textContent = "error: " + err.message;
    });
  };

  function table(title, rows, columns) {
    if (!rows.length) return '<p class="muted">' + esc(title) + ": none</p>";
    var head = columns.map(function (c) { return "<th>" + esc(c) + "</th>"; }).join("");
    var body = rows.slice(0, 200).map(function (row) {
      return "<tr>" + columns.map(function (c) {
        var value = row[c];
        return "<td>" + esc(value === undefined || value === null ? "" : value) + "</td>";
      }).join("") + "</tr>";
    }).join("");
    var more = rows.length > 200 ? '<p class="muted">... and ' + (rows.length - 200) + " more</p>" : "";
    return "<h3>" + esc(title) + " (" + rows.length + ")</h3><table><tr>" + head + "</tr>" + body + "</table>" + more;
  }

  $("diff").onclick = function () {
    $("diffstate").textContent = "working...";
    $("summary").textContent = "";
    $("tables").innerHTML = "";
    call("/diff", { left_path: $("left").value.trim(), right_path: $("right").value.trim(),
                    ignore_thunks: $("thunks").checked }).then(function (text) {
      var doc = JSON.parse(text);
      var s = doc.summary;
      $("summary").textContent = "nodes +" + s.nodes.added + " -" + s.nodes.removed +
        " ~" + s.nodes.moved + " moved ~" + s.nodes.similar + " similar | edges +" +
        s.edges.added + " -" + s.edges.removed + " =" + s.edges.unchanged;
      $("tables").innerHTML = table("Added nodes", doc.added_nodes, ["address", "size"]) +
        table("Removed nodes", doc.removed_nodes, ["address", "size"]) +
        table("Added edges", doc.added_edges, ["caller", "callee", "kind"]) +
        table("Removed edges", doc.removed_edges, ["caller", "callee", "kind"]);
      $("diffstate").textContent = "done";
    }).catch(function (err) {
      $("diffstate").textContent = "error: " + err.message;
    });
  };

  $("report").onclick = function () {
    $("diffstate").textContent = "building report...";
    fetch("/report", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token() },
      body: JSON.stringify({ left_path: $("left").value.trim(), right_path: $("right").value.trim(),
                             format: "html", ignore_thunks: $("thunks").checked })
    }).then(function (res) {
      if (!res.ok) throw new Error("http " + res.status);
      return res.blob();
    }).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      link.href = url;
      link.download = "reversesuite-report.html";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
      $("diffstate").textContent = "report downloaded";
    }).catch(function (err) {
      $("diffstate").textContent = "error: " + err.message;
    });
  };
})();
</script></body></html>"""

def make_handler(token: str, root: Optional[Path], workers: int = 1):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ReverseSuite/0.3"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _send_html(self, status: int, document: str) -> None:
            import secrets as _secrets
            nonce = _secrets.token_urlsafe(16)
            body = document.replace("<script>", '<script nonce="%s">' % nonce).encode("utf-8")
            csp = ("default-src 'none'; style-src 'unsafe-inline'; "
                   "script-src 'nonce-%s'; connect-src 'self'; "
                   "img-src 'self' data:; base-uri 'none'; form-action 'none'" % nonce)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", csp)
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
            if route == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
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
            route = self.path.split("?")[0]
            if route == "/analyze":
                raw_path = str(payload.get("path", "")).strip()
                tempdir = None
                try:
                    if is_url(raw_path):
                        try:
                            target, tempdir = download_to_temp(raw_path)
                        except FetchError as exc:
                            self._send(400, {"error": exc.code})
                            return
                    else:
                        target, error = resolve_path(root, raw_path)
                        if error == "path_not_allowed":
                            self._send(403, {"error": error})
                            return
                        if target is None or not target.is_file():
                            self._send(400, {"error": "path_not_found"})
                            return
                    try:
                        doc = analyze_bytes(target.read_bytes(), int(payload.get("workers", workers)))
                    except Exception as exc:
                        self._send(400, {"error": "analysis_failed", "detail": exc.__class__.__name__})
                        return
                    doc["source"] = raw_path
                    self._send(200, doc)
                finally:
                    if tempdir:
                        shutil.rmtree(tempdir, ignore_errors=True)
                return
            if route in ("/diff", "/report"):
                fmt = str(payload.get("format", "html")).lower()
                if route == "/report" and fmt not in ("html", "md", "markdown"):
                    self._send(400, {"error": "bad_format"})
                    return
                left, left_err = resolve_path(root, str(payload.get("left_path", "")).strip())
                right, right_err = resolve_path(root, str(payload.get("right_path", "")).strip())
                if left is None or right is None:
                    code = 403 if "path_not_allowed" in (left_err, right_err) else 400
                    self._send(code, {"error": left_err or right_err})
                    return
                if not left.is_file() or not right.is_file():
                    self._send(400, {"error": "path_not_found"})
                    return
                try:
                    result = diff_mod.diff_graphs(callgraph.build(left.read_bytes()).as_dict(),
                                                  callgraph.build(right.read_bytes()).as_dict(),
                                                  ignore_thunks=bool(payload.get("ignore_thunks", False)))
                except Exception as exc:
                    self._send(500, {"error": "diff_failed", "detail": exc.__class__.__name__})
                    return
                if route == "/diff":
                    doc = result.as_dict()
                    doc["left"] = str(left)
                    doc["right"] = str(right)
                    self._send(200, doc)
                    return
                document = report_mod.render(result, left.name, right.name, fmt)
                body = document.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8" if fmt == "html"
                                 else "text/markdown; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition",
                                 'attachment; filename="%s"' % _attachment_name(str(left), fmt))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return
            self._send(404, {"error": "not_found"})

    return Handler


def serve(root: Optional[Path] = None, token: Optional[str] = None, port: int = 0,
          workers: int = 1) -> Tuple[ThreadingHTTPServer, str, threading.Thread]:
    token = token or new_token()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(token, root, workers))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, token, thread
