"""Report rendering (M2 slice 4): diff results as Markdown or standalone HTML.

All values that originate from the analysed binary are escaped before they reach
the document (PLAN T7). Output is deterministic: same diff -> same bytes.
"""
from __future__ import annotations

import html
from typing import Dict, List, Optional

from . import diff as diff_mod

MAX_ROWS = 50


def _rows(items: List, fmt, empty: str) -> List[str]:
    if not items:
        return [fmt(empty)] if fmt else [empty]
    return [fmt(item) for item in items]


def _truncated(total: int) -> Optional[str]:
    if total > MAX_ROWS:
        return "... and %d more" % (total - MAX_ROWS)
    return None


def _edge_label(edge: diff_mod.EdgeChange) -> str:
    target = ("0x%x" % edge.callee) if edge.callee is not None else "<external>"
    return "0x%x -> %s (%s)" % (edge.caller, target, edge.kind)


def _node_label(node: diff_mod.NodeChange) -> str:
    return "0x%x (size %d)" % (node.address, node.size)


def render_markdown(result: diff_mod.DiffResult, left: str = "left", right: str = "right") -> str:
    s = result.summary()
    lines: List[str] = []
    lines.append("# ReverseSuite diff report")
    lines.append("")
    lines.append("| field | value |")
    lines.append("| --- | --- |")
    lines.append("| left | `%s` |" % left.replace("|", "\\|"))
    lines.append("| right | `%s` |" % right.replace("|", "\\|"))
    lines.append("| nodes added | %d |" % s["nodes"]["added"])
    lines.append("| nodes removed | %d |" % s["nodes"]["removed"])
    lines.append("| nodes moved | %d |" % s["nodes"]["moved"])
    lines.append("| nodes similar | %d |" % s["nodes"]["similar"])
    lines.append("| edges added | %d |" % s["edges"]["added"])
    lines.append("| edges removed | %d |" % s["edges"]["removed"])
    lines.append("| edges unchanged | %d |" % s["edges"]["unchanged"])
    lines.append("")
    if not any(s["nodes"].values()) and not s["edges"]["added"] and not s["edges"]["removed"]:
        lines.append("**No changes detected.**")
        lines.append("")
    def section(title: str, items: List, label) -> None:
        lines.append("## %s (%d)" % (title, len(items)))
        lines.append("")
        if not items:
            lines.append("_none_")
            lines.append("")
            return
        for item in items[:MAX_ROWS]:
            lines.append("- `%s`" % label(item))
        more = _truncated(len(items))
        if more:
            lines.append("- %s" % more)
        lines.append("")
    section("Added functions", result.added_nodes, _node_label)
    section("Removed functions", result.removed_nodes, _node_label)
    moved_map = {node.address: to for node, to in result.moved_nodes}
    section("Moved functions", [node for node, _ in result.moved_nodes],
            lambda n: "%s -> 0x%x" % (_node_label(n), moved_map[n.address]))
    section("Added edges", result.added_edges, _edge_label)
    section("Removed edges", result.removed_edges, _edge_label)
    return "\n".join(lines).rstrip() + "\n"


def render_html(result: diff_mod.DiffResult, left: str = "left", right: str = "right") -> str:
    s = result.summary()
    esc = html.escape
    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang=\"en\"><head><meta charset=\"utf-8\">")
    parts.append("<title>ReverseSuite diff report</title>")
    parts.append("<style>body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111}"
                 "table{border-collapse:collapse;margin:1rem 0}"
                 "td,th{border:1px solid #ccc;padding:.25rem .6rem;text-align:left}"
                 "code{background:#f3f3f3;padding:.1rem .3rem}</style></head><body>")
    parts.append("<h1>ReverseSuite diff report</h1>")
    parts.append("<table><tr><th>field</th><th>value</th></tr>")
    for key, value in (("left", left), ("right", right)):
        parts.append("<tr><td>%s</td><td><code>%s</code></td></tr>" % (key, esc(value)))
    for key in ("added", "removed", "moved", "similar"):
        parts.append("<tr><td>nodes %s</td><td>%d</td></tr>" % (key, s["nodes"][key]))
    for key in ("added", "removed", "unchanged"):
        parts.append("<tr><td>edges %s</td><td>%d</td></tr>" % (key, s["edges"][key]))
    parts.append("</table>")
    if not any(s["nodes"].values()) and not s["edges"]["added"] and not s["edges"]["removed"]:
        parts.append("<p><strong>No changes detected.</strong></p>")
    def section(title: str, items: List, label) -> None:
        parts.append("<h2>%s (%d)</h2>" % (esc(title), len(items)))
        if not items:
            parts.append("<p><em>none</em></p>")
            return
        parts.append("<ul>")
        for item in items[:MAX_ROWS]:
            parts.append("<li><code>%s</code></li>" % esc(label(item)))
        if len(items) > MAX_ROWS:
            parts.append("<li>... and %d more</li>" % (len(items) - MAX_ROWS))
        parts.append("</ul>")
    section("Added functions", result.added_nodes, _node_label)
    section("Removed functions", result.removed_nodes, _node_label)
    section("Moved functions", [n for n, _ in result.moved_nodes], _node_label)
    section("Added edges", result.added_edges, _edge_label)
    section("Removed edges", result.removed_edges, _edge_label)
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def render(result: diff_mod.DiffResult, left: str = "left", right: str = "right",
           fmt: str = "md") -> str:
    if fmt in ("md", "markdown"):
        return render_markdown(result, left, right)
    if fmt == "html":
        return render_html(result, left, right)
    raise ValueError("unknown format: %s" % fmt)