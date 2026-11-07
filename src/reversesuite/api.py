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
<style>
body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:70rem;color:#111}
h1{margin:0 0 .5rem}h2{margin:1.6rem 0 .4rem;font-size:1.05rem}
input,button,select{font:inherit;padding:.3rem .5rem}
input[type=text],input[type=password]{min-width:22rem}
pre{background:#f4f4f4;padding:1rem;overflow:auto;max-height:22rem}
table{border-collapse:collapse;margin:.5rem 0;width:100%}
td,th{border:1px solid #ddd;padding:.2rem .5rem;text-align:left;font-family:ui-monospace,monospace;font-size:12px}
th{background:#f7f7f7}.muted{color:#666}
.row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin:.4rem 0}
</style></head><body>
<h1>ReverseSuite</h1>
<p class="muted">Token stays in this tab (sessionStorage) and is sent only as an Authorization header.</p>
<div class="row"><input id="token" type="password" placeholder="session token" size="40">
<button id="save">use token</button><span id="tokstate" class="muted"></span></div>

<h2>Analyze</h2>
<div class="row"><input id="path" type="text" placeholder="absolute path inside the allowlisted root">
<button id="run">analyze</button></div>
<pre id="out">ready</pre>

<h2>Diff &amp; Report</h2>
<div class="row"><input id="left" type="text" placeholder="left binary path">
<input id="right" type="text" placeholder="right binary path">
<label><input id="thunks" type="checkbox"> ignore thunks</label></div>
<div class="row"><button id="diff">run diff</button>
<button id="report">download report</button><span id="diffstate" class="muted"></span></div>
<div id="summary"></div>
<div id="tables"></div>

<script>
const $ = (id) => document.getElementById(id);
const token = () => sessionStorage.getItem("rs-token") || "";
const esc = (value) => String(value).replace(/[&<>"\']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));

$("save").onclick = () => {
  sessionStorage.setItem("rs-token", $("token").value.trim());
  $("tokstate").textContent = "token saved for this tab";
};

async function call(route, payload) {
  const res = await fetch(route, {
    method: "POST",
    headers: {"Content-Type": "application/json", "Authorization": "Bearer " + token()},
    body: JSON.stringify(payload)
  });
  const text = await res.text();
  if (!res.ok) throw new Error(res.status + " " + text.slice(0, 300));
  return text;
}

$("run").onclick = async () => {
  $("out").textContent = "working...";
  try {
    const text = await call("/analyze", {path: $("path").value});
    const doc = JSON.parse(text);
    $("out").textContent = [
      "status: " + doc.status,
      "findings: " + doc.findings.length,
      "functions: " + doc.graph.nodes.length,
      "edges: " + doc.graph.edges.length,
      "imports: " + (doc.graph.import_calls || 0),
      "indirect: " + (doc.graph.indirect_calls || 0)
    ].join("\n");
  } catch (err) {
    $("out").textContent = "error: " + err.message;
  }
};

function table(title, rows, columns) {
  if (!rows.length) return "<p class=\"muted\">" + esc(title) + ": none</p>";
  const head = columns.map((c) => "<th>" + esc(c) + "</th>").join("");
  const body = rows.slice(0, 200).map((row) => "<tr>" +
    columns.map((c) => "<td>" + esc(row[c] === undefined || row[c] === null ? "" : row[c]) + "</td>").join("") +
    "</tr>").join("");
  const more = rows.length > 200 ? "<p class=\"muted\">... and " + (rows.length - 200) + " more</p>" : "";
  return "<h3>" + esc(title) + " (" + rows.length + ")</h3><table><tr>" + head + "</tr>" + body + "</table>" + more;
}

$("diff").onclick = async () => {
  $("diffstate").textContent = "working...";
  $("summary").textContent = "";
  $("tables").innerHTML = "";
  try {
    const text = await call("/diff", {left_path: $("left").value, right_path: $("right").value,
                                      ignore_thunks: $("thunks").checked});
    const doc = JSON.parse(text);
    const s = doc.summary;
    $("summary").textContent = "nodes +" + s.nodes.added + " -" + s.nodes.removed +
      " ~" + s.nodes.moved + " (moved) ~" + s.nodes.similar + " (similar) | edges +" +
      s.edges.added + " -" + s.edges.removed + " =" + s.edges.unchanged;
    $("tables").innerHTML = [
      table("Added nodes", doc.added_nodes, ["address", "size"]),
      table("Removed nodes", doc.removed_nodes, ["address", "size"]),
      table("Added edges", doc.added_edges, ["caller", "callee", "kind"]),
      table("Removed edges", doc.removed_edges, ["caller", "callee", "kind"])
    ].join("");
    $("diffstate").textContent = "done";
  } catch (err) {
    $("diffstate").textContent = "error: " + err.message;
  }
};

$("report").onclick = async () => {
  $("diffstate").textContent = "building report...";
  try {
    const res = await fetch("/report", {
      method: "POST",
      headers: {"Content-Type": "application/json", "Authorization": "Bearer " + token()},
      body: JSON.stringify({left_path: $("left").value, right_path: $("right").value, format: "html",
                            ignore_thunks: $("thunks").checked})
    });
    if (!res.ok) throw new Error(res.status + " " + (await res.text()).slice(0, 200));
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "reversesuite-report.html";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    $("diffstate").textContent = "report downloaded";
  } catch (err) {
    $("diffstate").textContent = "error: " + err.message;
  }
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
            if self.path.split("?")[0] == "/diff":
                left = resolve_in_root(root, str(payload.get("left_path", "")))
                right = resolve_in_root(root, str(payload.get("right_path", "")))
                if left is None or right is None:
                    self._send(403, {"error": "path_not_allowed"})
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
                doc = result.as_dict()
                doc["left"] = str(left)
                doc["right"] = str(right)
                self._send(200, doc)
                return
            if self.path.split("?")[0] == "/report":
                fmt = str(payload.get("format", "html")).lower()
                if fmt not in ("html", "md", "markdown"):
                    self._send(400, {"error": "bad_format"})
                    return
                left = resolve_in_root(root, str(payload.get("left_path", "")))
                right = resolve_in_root(root, str(payload.get("right_path", "")))
                if left is None or right is None:
                    self._send(403, {"error": "path_not_allowed"})
                    return
                if not left.is_file() or not right.is_file():
                    self._send(400, {"error": "path_not_found"})
                    return
                try:
                    result = diff_mod.diff_graphs(callgraph.build(left.read_bytes()).as_dict(),
                                                  callgraph.build(right.read_bytes()).as_dict(),
                                                  ignore_thunks=bool(payload.get("ignore_thunks", False)))
                    document = report_mod.render(result, left.name, right.name, fmt)
                except Exception as exc:
                    self._send(500, {"error": "report_failed", "detail": exc.__class__.__name__})
                    return
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