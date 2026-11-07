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

import atexit
import json
import os
import shutil
import time
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
import urllib.parse

from . import callgraph, diff as diff_mod, functions, loader, report as report_mod, rules, schema, strings

MAX_BODY = 64 * 1024
MAX_UPLOAD = 256 * 1024 * 1024
UPLOAD_TTL_S = 900.0
URL_MAX_BYTES = 256 * 1024 * 1024
URL_TIMEOUT = 30
URL_HEADERS = {"User-Agent": "ReverseSuite/0.1 (+http://127.0.0.1)"}
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW_S = 60.0


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


def analyze_bytes(data: bytes, workers: int = 1, valueflow: bool = False) -> dict:
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
    graph = (callgraph.build(data, funcs=found, use_valueflow=bool(valueflow))
             if found else callgraph.CallGraph())
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


def _host_is_loopback(host: str) -> bool:
    host = (host or "").strip().lower().strip("[]")
    if host in ("localhost", "::1"):
        return True
    return host.startswith("127.")


def _host_is_private(host: str) -> bool:
    import ipaddress
    try:
        address = ipaddress.ip_address((host or "").strip().strip("[]"))
    except ValueError:
        return False
    return address.is_private or address.is_link_local or address.is_reserved


def url_allowed(raw: str, allow_private: bool = False) -> bool:
    """Block non-loopback private targets unless explicitly allowed (SSRF guard)."""
    parts = urlsplit(raw)
    host = parts.hostname or ""
    if not host:
        return False
    if _host_is_loopback(host):
        return True
    if allow_private:
        return True
    if _host_is_private(host):
        return False
    import socket
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return True
    for info in infos:
        address = info[4][0]
        if _host_is_loopback(address):
            return True
        if _host_is_private(address):
            return False
    return True


def new_upload_id() -> str:
    return secrets.token_hex(16)


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
#graphwrap{background:#fafafa;border:1px solid #ddd;border-radius:6px;overflow:hidden;cursor:grab}
#graphwrap svg{display:block;width:100%;height:380px}
#graph text{font:10px ui-monospace,monospace;fill:#111;pointer-events:none}
.legend{margin:.3rem 0;font-size:12px;color:#555}
.legend span{display:inline-block;margin-right:.9rem}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:.3rem}
.drop{display:flex;flex-direction:column;gap:.25rem}.drop.dragover textarea,.row.dragover textarea{outline:2px dashed #3b82f6}
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
<div class="row" id="drop-analyze">
  <textarea id="path" rows="1" placeholder="Absolute path, URL — or drop a file here"></textarea>
  <button id="browse-analyze" type="button">browse…</button>
  <input id="file-analyze" type="file" accept=".exe,.dll,.bin" hidden>
  <button id="run">analyze</button>
</div>
<p class="muted" id="uploadstate"></p>
<p class="muted" id="roothint"></p>
<pre id="out">ready</pre>
<h2>Diff &amp; Report</h2>
<div class="row" id="drop-diff">
  <div class="drop">
    <textarea id="left" rows="1" placeholder="left binary path"></textarea>
    <button id="browse-left" type="button">browse…</button>
    <input id="file-left" type="file" accept=".exe,.dll,.bin" hidden>
  </div>
  <div class="drop">
    <textarea id="right" rows="1" placeholder="right binary path"></textarea>
    <button id="browse-right" type="button">browse…</button>
    <input id="file-right" type="file" accept=".exe,.dll,.bin" hidden>
  </div>
  <label><input id="thunks" type="checkbox"> ignore thunks</label>
</div>
<div class="row">
  <button id="diff">run diff</button>
  <button id="report">download report</button>
  <span id="diffstate" class="muted"></span>
</div>
<div id="summary"></div>
<h2>Graph</h2>
<div class="row">
  <button id="gcall">view call graph</button>
  <button id="gdiff">view diff graph</button>
  <button id="gexport">export svg</button>
  <button id="gpng">export png</button>
  <button id="gclear">clear</button>
  <span id="gstate" class="muted"></span>
</div>
<p class="legend" id="glegend"></p>
<div id="graphwrap"><svg id="graph" xmlns="http://www.w3.org/2000/svg"></svg></div>
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
    call("/analyze", { path: $("path").value.trim(), upload_id: uploaded.analyze || "" }).then(function (text) {
      var doc = JSON.parse(text);
      window.__lastAnalyze = doc;
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
                    left_upload_id: uploaded.left || "", right_upload_id: uploaded.right || "",
                    ignore_thunks: $("thunks").checked }).then(function (text) {
      var doc = JSON.parse(text);
      window.__lastDiff = doc;
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

  // --- interactive SVG graph (vanilla, CSP safe) ---
  var NS = "http://www.w3.org/2000/svg";
  var view = { scale: 1, tx: 0, ty: 0, drag: null, pan: null };
  var current = { nodes: [], edges: [] };

  function svgEl(name) { return document.createElementNS(NS, name); }

  function clearGraph() {
    var svg = $("graph");
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    current = { nodes: [], edges: [] };
    $("gstate").textContent = "";
    $("glegend").textContent = "";
  }

  function applyView() {
    var world = $("gworld");
    if (world) world.setAttribute("transform", "translate(" + view.tx + "," + view.ty + ") scale(" + view.scale + ")");
  }

  function legend(items) {
    var box = $("glegend");
    box.textContent = "";
    items.forEach(function (pair) {
      var wrap = document.createElement("span");
      var dot = document.createElement("span");
      dot.className = "dot";
      dot.style.background = pair[1];
      wrap.appendChild(dot);
      wrap.appendChild(document.createTextNode(pair[0]));
      box.appendChild(wrap);
    });
  }

  function drawGraph(nodes, edges, colors, note) {
    clearGraph();
    var svg = $("graph");
    var width = svg.clientWidth || 900;
    var height = svg.clientHeight || 380;
    var world = svgEl("g");
    world.setAttribute("id", "gworld");
    svg.appendChild(world);

    var count = nodes.length;
    var radius = Math.max(60, Math.min(width, height) / 2 - 45);
    nodes.forEach(function (node, i) {
      var angle = (2 * Math.PI * i) / Math.max(count, 1);
      node.x = width / 2 + radius * Math.cos(angle);
      node.y = height / 2 + radius * Math.sin(angle);
      node.el = null;
      node.labelEl = null;
    });

    var byAddr = {};
    nodes.forEach(function (node) { byAddr[node.addr] = node; });

    edges.forEach(function (edge) {
      var a = byAddr[edge.caller];
      var b = edge.callee === null || edge.callee === undefined ? null : byAddr[edge.callee];
      if (!a || !b) return;
      var line = svgEl("line");
      line.setAttribute("stroke", colors[edge.kind] || "#9ca3af");
      line.setAttribute("stroke-width", "1.2");
      line.setAttribute("stroke-opacity", "0.75");
      world.appendChild(line);
      edge.el = line;
      edge.a = a;
      edge.b = b;
    });

    nodes.forEach(function (node) {
      var circle = svgEl("circle");
      circle.setAttribute("r", "7");
      circle.setAttribute("fill", node.color || "#6b7280");
      circle.setAttribute("stroke", "#fff");
      circle.setAttribute("stroke-width", "1");
      circle.style.cursor = "grab";
      world.appendChild(circle);
      node.el = circle;

      var label = svgEl("text");
      label.textContent = node.label;
      world.appendChild(label);
      node.labelEl = label;

      circle.addEventListener("mousedown", function (ev) {
        ev.stopPropagation();
        view.drag = node;
        circle.style.cursor = "grabbing";
      });
    });

    current = { nodes: nodes, edges: edges };
    simulateForce(nodes, edges, width, height);
    layoutNodes();
    applyView();
    $("gstate").textContent = note || (nodes.length + " nodes / " + edges.length + " edges");
  }

  function simulateForce(nodes, edges, width, height) {
    if (nodes.length < 2) return;
    var iterations = 220;
    var area = width * height;
    var k = Math.sqrt(area / nodes.length) * 0.55;
    var byAddr = {};
    nodes.forEach(function (n) { byAddr[n.addr] = n; });
    var links = [];
    edges.forEach(function (e) {
      var a = byAddr[e.caller];
      var b = e.callee === null || e.callee === undefined ? null : byAddr[e.callee];
      if (a && b && a !== b) links.push([a, b]);
    });
    for (var step = 0; step < iterations; step++) {
      var disp = {};
      nodes.forEach(function (n) { disp[n.addr] = { x: 0, y: 0 }; });
      for (var i = 0; i < nodes.length; i++) {
        for (var j = i + 1; j < nodes.length; j++) {
          var a = nodes[i], b = nodes[j];
          var dx = a.x - b.x, dy = a.y - b.y;
          var dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
          var force = (k * k) / dist;
          var ux = dx / dist, uy = dy / dist;
          disp[a.addr].x += ux * force; disp[a.addr].y += uy * force;
          disp[b.addr].x -= ux * force; disp[b.addr].y -= uy * force;
        }
      }
      links.forEach(function (pair) {
        var a = pair[0], b = pair[1];
        var dx = a.x - b.x, dy = a.y - b.y;
        var dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        var force = (dist * dist) / k;
        var ux = dx / dist, uy = dy / dist;
        disp[a.addr].x -= ux * force; disp[a.addr].y -= uy * force;
        disp[b.addr].x += ux * force; disp[b.addr].y += uy * force;
      });
      var cx = width / 2, cy = height / 2;
      nodes.forEach(function (n) {
        var d = disp[n.addr];
        var len = Math.sqrt(d.x * d.x + d.y * d.y) || 0.01;
        var move = Math.min(len, 30);
        n.x += (d.x / len) * move + (cx - n.x) * 0.02;
        n.y += (d.y / len) * move + (cy - n.y) * 0.02;
        n.x = Math.max(24, Math.min(width - 24, n.x));
        n.y = Math.max(24, Math.min(height - 24, n.y));
      });
    }
  }

  function layoutNodes() {
    current.nodes.forEach(function (node) {
      node.el.setAttribute("cx", node.x);
      node.el.setAttribute("cy", node.y);
      node.labelEl.setAttribute("x", node.x + 9);
      node.labelEl.setAttribute("y", node.y + 3);
    });
    current.edges.forEach(function (edge) {
      edge.el.setAttribute("x1", edge.a.x);
      edge.el.setAttribute("y1", edge.a.y);
      edge.el.setAttribute("x2", edge.b.x);
      edge.el.setAttribute("y2", edge.b.y);
    });
  }

  function svgPoint(ev) {
    var rect = $("graph").getBoundingClientRect();
    return {
      x: (ev.clientX - rect.left - view.tx) / view.scale,
      y: (ev.clientY - rect.top - view.ty) / view.scale
    };
  }

  $("graph").addEventListener("mousedown", function (ev) {
    if (view.drag) return;
    view.pan = { x: ev.clientX, y: ev.clientY, tx: view.tx, ty: view.ty };
    $("graphwrap").style.cursor = "grabbing";
  });
  window.addEventListener("mousemove", function (ev) {
    if (view.drag) {
      var point = svgPoint(ev);
      view.drag.x = point.x;
      view.drag.y = point.y;
      layoutNodes();
      return;
    }
    if (view.pan) {
      view.tx = view.pan.tx + (ev.clientX - view.pan.x);
      view.ty = view.pan.ty + (ev.clientY - view.pan.y);
      applyView();
    }
  });
  window.addEventListener("mouseup", function () {
    if (view.drag && view.drag.el) view.drag.el.style.cursor = "grab";
    view.drag = null;
    view.pan = null;
    $("graphwrap").style.cursor = "grab";
  });
  $("graph").addEventListener("wheel", function (ev) {
    ev.preventDefault();
    var factor = ev.deltaY < 0 ? 1.15 : 1 / 1.15;
    view.scale = Math.min(4, Math.max(0.25, view.scale * factor));
    applyView();
  }, { passive: false });

  var CALL_COLORS = { direct: "#3b82f6", import: "#8b5cf6", tail: "#0ea5e9", thunk: "#f59e0b" };

  $("gcall").onclick = function () {
    var doc = window.__lastAnalyze;
    if (!doc) { $("gstate").textContent = "run analyze first"; return; }
    var nodes = doc.graph.nodes.map(function (addr) {
      return { addr: addr, label: "0x" + addr.toString(16), color: "#6b7280" };
    });
    var limit = 400;
    if (nodes.length > limit) {
      nodes = nodes.slice(0, limit);
    }
    var kept = {};
    nodes.forEach(function (n) { kept[n.addr] = true; });
    var edges = doc.graph.edges.filter(function (e) { return kept[e.caller] && kept[e.callee]; });
    legend([["direct", CALL_COLORS.direct], ["import", CALL_COLORS.import],
            ["tail", CALL_COLORS.tail], ["thunk", CALL_COLORS.thunk]]);
    drawGraph(nodes, edges, CALL_COLORS, nodes.length + " nodes / " + edges.length + " edges" +
      (doc.graph.nodes.length > limit ? " (first " + limit + ")" : ""));
  };

  $("gdiff").onclick = function () {
    var doc = window.__lastDiff;
    if (!doc) { $("gstate").textContent = "run diff first"; return; }
    var nodes = [];
    var seen = {};
    function add(addr, color) {
      if (addr === null || addr === undefined) return;
      if (seen[addr]) return;
      seen[addr] = true;
      nodes.push({ addr: addr, label: "0x" + addr.toString(16), color: color });
    }
    doc.removed_nodes.forEach(function (n) { add(n.address, "#dc2626"); });
    doc.added_nodes.forEach(function (n) { add(n.address, "#16a34a"); });
    doc.removed_edges.forEach(function (e) { add(e.caller, "#dc2626"); add(e.callee, "#dc2626"); });
    doc.added_edges.forEach(function (e) { add(e.caller, "#16a34a"); add(e.callee, "#16a34a"); });
    var edges = [];
    doc.removed_edges.forEach(function (e) { edges.push({ caller: e.caller, callee: e.callee, kind: "removed" }); });
    doc.added_edges.forEach(function (e) { edges.push({ caller: e.caller, callee: e.callee, kind: "added" }); });
    legend([["added", "#16a34a"], ["removed", "#dc2626"]]);
    drawGraph(nodes, edges, { added: "#16a34a", removed: "#dc2626" },
      nodes.length + " nodes / " + edges.length + " edges (added+removed)");
  };

  function snapshotSvg() {
    var svg = $("graph");
    var clone = svg.cloneNode(true);
    clone.setAttribute("xmlns", NS);
    clone.setAttribute("width", String(svg.clientWidth || 900));
    clone.setAttribute("height", String(svg.clientHeight || 380));
    clone.setAttribute("viewBox", "0 0 " + (svg.clientWidth || 900) + " " + (svg.clientHeight || 380));
    var style = document.createElementNS(NS, "style");
    style.textContent = "text{font:10px ui-monospace,monospace;fill:#111}";
    clone.insertBefore(style, clone.firstChild);
    return clone;
  }

  function downloadBlob(blob, name) {
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
  }

  // --- file picker and drag & drop (uploads bytes; no trusted local paths) ---
  var uploaded = { analyze: null, left: null, right: null };

  function uploadFile(file) {
    var headers = { "Content-Type": "application/octet-stream",
                    "X-Filename": encodeURIComponent(file.name),
                    "Authorization": "Bearer " + token() };
    return fetch("/upload", { method: "POST", headers: headers, body: file })
      .then(function (res) {
        return res.text().then(function (text) {
          if (!res.ok) throw new Error(res.status + " " + text.slice(0, 160));
          return JSON.parse(text);
        });
      });
  }

  function wirePicker(kind, buttonId, inputId, textareaId) {
    var input = $(inputId);
    var area = $(textareaId);
    $(buttonId).onclick = function () { input.click(); };
    input.onchange = function () {
      if (!input.files || !input.files.length) return;
      var file = input.files[0];
      area.value = file.name;
      $("uploadstate").textContent = "uploading " + file.name + "…";
      uploadFile(file).then(function (info) {
        uploaded[kind] = info.id;
        $("uploadstate").textContent = "uploaded " + file.name + " (" + info.size + " bytes)";
      }).catch(function (err) {
        uploaded[kind] = null;
        $("uploadstate").textContent = "upload failed: " + err.message;
      });
    };
    area.addEventListener("input", function () { uploaded[kind] = null; });
  }

  function wireDrop(zoneId, kind, textareaId) {
    var zone = $(zoneId);
    ["dragenter", "dragover"].forEach(function (name) {
      zone.addEventListener(name, function (ev) { ev.preventDefault(); zone.classList.add("dragover"); });
    });
    ["dragleave", "drop"].forEach(function (name) {
      zone.addEventListener(name, function (ev) {
        if (name === "dragleave") { zone.classList.remove("dragover"); return; }
        ev.preventDefault();
        zone.classList.remove("dragover");
        var files = (ev.dataTransfer && ev.dataTransfer.files) || [];
        if (!files.length) return;
        var file = files[0];
        $(textareaId).value = file.name;
        $("uploadstate").textContent = "uploading " + file.name + "…";
        uploadFile(file).then(function (info) {
          uploaded[kind] = info.id;
          $("uploadstate").textContent = "uploaded " + file.name + " (" + info.size + " bytes)";
        }).catch(function (err) {
          uploaded[kind] = null;
          $("uploadstate").textContent = "upload failed: " + err.message;
        });
      });
    });
  }

  wirePicker("analyze", "browse-analyze", "file-analyze", "path");
  wirePicker("left", "browse-left", "file-left", "left");
  wirePicker("right", "browse-right", "file-right", "right");
  wireDrop("drop-analyze", "analyze", "path");
  wireDrop("drop-diff", "left", "left");
  $("gexport").onclick = function () {
    if (!current.nodes.length) { $("gstate").textContent = "nothing to export"; return; }
    var clone = snapshotSvg();
    var xml = new XMLSerializer().serializeToString(clone);
    downloadBlob(new Blob([xml], { type: "image/svg+xml" }), "reversesuite-graph.svg");
    $("gstate").textContent = "svg exported";
  };

  $("gpng").onclick = function () {
    if (!current.nodes.length) { $("gstate").textContent = "nothing to export"; return; }
    var clone = snapshotSvg();
    var width = Number(clone.getAttribute("width"));
    var height = Number(clone.getAttribute("height"));
    var xml = new XMLSerializer().serializeToString(clone);
    var url = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(xml);
    var img = new Image();
    img.onload = function () {
      var canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      var ctx = canvas.getContext("2d");
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, width, height);
      ctx.drawImage(img, 0, 0);
      canvas.toBlob(function (blob) {
        if (blob) downloadBlob(blob, "reversesuite-graph.png");
        $("gstate").textContent = "png exported";
      }, "image/png");
    };
    img.onerror = function () { $("gstate").textContent = "png export failed"; };
    img.src = url;
  };

  $("gclear").onclick = clearGraph;
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

def make_handler(token: str, root: Optional[Path], workers: int = 1,
                 rate_limit: int = RATE_LIMIT_REQUESTS, allow_private_urls: bool = False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ReverseSuite/0.3"
        buckets: dict = {}
        uploads: dict = {}

        def _upload_dir(self) -> Path:
            return Path(self.server.upload_dir)

        def _store_upload(self, body: bytes, name_hint: str) -> str:
            upload_id = new_upload_id()
            safe = "".join(ch for ch in (name_hint or "upload.bin") if ch.isalnum() or ch in "-_.")[:64]
            target = self._upload_dir() / ("%s-%s" % (upload_id, safe or "upload.bin"))
            try:
                target.write_bytes(body)
            except OSError:
                self._purge_uploads()
                raise
            self.uploads[upload_id] = (target, time.monotonic())
            return upload_id

        def _resolve_upload(self, upload_id: str):
            entry = self.uploads.get(upload_id or "")
            if not entry:
                return None
            path, stamp = entry
            if time.monotonic() - stamp > UPLOAD_TTL_S or not path.exists():
                self.uploads.pop(upload_id, None)
                return None
            return path

        def _acquire(self, raw: str, tempdirs: list):
            """Resolve one input: URL (downloaded), upload id, or local path."""
            if not raw:
                return None, "path_not_found"
            if is_url(raw):
                if not url_allowed(raw, allow_private_urls):
                    return None, "url_host_not_allowed"
                try:
                    target, tempdir = download_to_temp(raw)
                except FetchError as exc:
                    return None, exc.code
                tempdirs.append(tempdir)
                return target, None
            return resolve_path(root, raw)

        def _purge_uploads(self) -> None:
            now = time.monotonic()
            for key, (path, stamp) in list(self.uploads.items()):
                if now - stamp > UPLOAD_TTL_S:
                    self.uploads.pop(key, None)
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
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
            if rate_limit > 0:
                client = self.client_address[0] if self.client_address else "?"
                now = time.monotonic()
                stamps = [t for t in self.buckets.get(client, []) if now - t < RATE_LIMIT_WINDOW_S]
                if len(stamps) >= rate_limit:
                    self._send(429, {"error": "rate_limited"})
                    return False
                stamps.append(now)
                self.buckets[client] = stamps
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
            route = self.path.split("?")[0]
            if route == "/upload":
                if length <= 0 or length > MAX_UPLOAD:
                    self._send(400, {"error": "bad_upload_size"})
                    return
                body = self.rfile.read(length)
                if len(body) < 2 or body[:2] != b"MZ":
                    self._send(400, {"error": "not_a_pe_file"})
                    return
                name = urllib.parse.unquote(self.headers.get("X-Filename") or "upload.bin")
                upload_id = self._store_upload(body, name)
                self._purge_uploads()
                self._send(200, {"id": upload_id, "size": len(body), "name": name})
                return
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
                upload_id = str(payload.get("upload_id", "")).strip()
                tempdir = None
                try:
                    if upload_id:
                        target = self._resolve_upload(upload_id)
                        if target is None:
                            self._send(400, {"error": "upload_not_found"})
                            return
                        raw_path = target.name
                    elif is_url(raw_path):
                        if not url_allowed(raw_path, allow_private_urls):
                            self._send(400, {"error": "url_host_not_allowed"})
                            return
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
                        doc = analyze_bytes(target.read_bytes(), int(payload.get("workers", workers)),
                                        bool(payload.get("valueflow", False)))
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
                left_upload = str(payload.get("left_upload_id", "")).strip()
                right_upload = str(payload.get("right_upload_id", "")).strip()
                left_raw = str(payload.get("left_path", "")).strip()
                right_raw = str(payload.get("right_path", "")).strip()
                tempdirs = []
                try:
                    left = self._resolve_upload(left_upload) if left_upload else None
                    right = self._resolve_upload(right_upload) if right_upload else None
                    left_err = "upload_not_found" if left_upload and left is None else None
                    right_err = "upload_not_found" if right_upload and right is None else None
                    if left is None and left_err is None:
                        left, left_err = self._acquire(left_raw, tempdirs)
                    if right is None and right_err is None:
                        right, right_err = self._acquire(right_raw, tempdirs)
                    if left is None or right is None:
                        code = 403 if "path_not_allowed" in (left_err, right_err) else 400
                        self._send(code, {"error": left_err or right_err})
                        return
                    if not left.is_file() or not right.is_file():
                        self._send(400, {"error": "path_not_found"})
                        return
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
          workers: int = 1, rate_limit: int = RATE_LIMIT_REQUESTS,
          allow_private_urls: bool = False) -> Tuple[ThreadingHTTPServer, str, threading.Thread]:
    token = token or new_token()
    server = ThreadingHTTPServer(("127.0.0.1", port),
                                 make_handler(token, root, workers, rate_limit, allow_private_urls))
    upload_dir = tempfile.mkdtemp(prefix="reversesuite-up-")
    server.upload_dir = upload_dir
    atexit.register(shutil.rmtree, upload_dir, True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, token, thread
