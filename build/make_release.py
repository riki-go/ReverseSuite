"""Build the distributable folder + zip for a release.

Layout produced under dist/release/ReverseSuite-<version>/:
  ReverseSuite_<version>_x64_en-US.msi
  manual/USER_MANUAL_TH.md + .html, USER_MANUAL_EN.md + .html
  README.md, LICENSE, RELEASE_NOTES.md, SHA256SUMS.txt
  portable/reversesuite-desktop.exe + reversesuite-backend.exe (optional)
"""
import hashlib
import html
import pathlib
import re
import shutil
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = "0.2.1"
MSI_SRC = ROOT / "src-tauri/target/release/bundle/msi" / ("ReverseSuite_%s_x64_en-US.msi" % VERSION)
RELEASE_SRC = ROOT / "src-tauri/target/release"


def md_to_html(text: str, title: str) -> str:
    out = []
    in_code = False
    in_table = False
    in_list = False

    def inline(value: str) -> str:
        value = html.escape(value)
        value = re.sub(r"`([^`]+)`", r"<code>\1</code>", value)
        value = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", value)
        return value

    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(line))
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            if not in_table:
                out.append("<table>")
                in_table = True
            tag = "th" if not any("<tr>" in l for l in out[-3:]) and out[-1] == "<table>" else "td"
            out.append("<tr>" + "".join("<%s>%s</%s>" % (tag, inline(c), tag) for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            out.append("<h%d>%s</h%d>" % (level, inline(line[level:].strip()), level))
            continue
        if line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append("<li>%s</li>" % inline(line[2:]))
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if line.strip() in ("---", "***"):
            out.append("<hr>")
        elif line.startswith("> "):
            out.append("<blockquote>%s</blockquote>" % inline(line[2:]))
        elif not line.strip():
            continue
        else:
            out.append("<p>%s</p>" % inline(line))
    if in_list:
        out.append("</ul>")
    if in_table:
        out.append("</table>")
    body = "\n".join(out)
    return ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>%s</title><style>body{font:15px/1.6 system-ui,sans-serif;max-width:52rem;"
            "margin:2rem auto;padding:0 1rem;color:#111}code{background:#f2f2f2;padding:.1rem .3rem}"
            "pre{background:#f6f6f6;padding:1rem;overflow:auto}table{border-collapse:collapse}"
            "td,th{border:1px solid #ddd;padding:.3rem .6rem}blockquote{border-left:3px solid #ccc;"
            "margin:1rem 0;padding-left:1rem;color:#444}</style></head><body>%s</body></html>") % (
                html.escape(title), body)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    if not MSI_SRC.is_file():
        print("missing installer:", MSI_SRC, file=sys.stderr)
        return 2
    target = ROOT / "dist" / "release" / ("ReverseSuite-%s" % VERSION)
    if target.exists():
        shutil.rmtree(target)
    (target / "manual").mkdir(parents=True)
    shutil.copy2(MSI_SRC, target / MSI_SRC.name)

    for name in ("USER_MANUAL_TH.md", "USER_MANUAL_EN.md"):
        source = ROOT / "docs" / name
        shutil.copy2(source, target / "manual" / name)
        title = "ReverseSuite %s (%s)" % (VERSION, name.replace("USER_MANUAL_", "").replace(".md", ""))
        (target / "manual" / name.replace(".md", ".html")).write_text(
            md_to_html(source.read_text(encoding="utf-8"), title), encoding="utf-8")

    for name in ("README.md", "LICENSE"):
        shutil.copy2(ROOT / name, target / name)

    notes = ROOT / "docs" / ("RELEASE_NOTES_v%s.md" % VERSION)
    if notes.is_file():
        shutil.copy2(notes, target / "RELEASE_NOTES.md")

    portable = target / "portable"
    for name in ("reversesuite-desktop.exe", "reversesuite-backend.exe"):
        source = RELEASE_SRC / name
        if source.is_file():
            portable.mkdir(exist_ok=True)
            shutil.copy2(source, portable / name)

    lines = []
    for path in sorted(p for p in target.rglob("*") if p.is_file()):
        lines.append("%s  %s" % (sha256(path), path.relative_to(target).as_posix()))
    (target / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    archive = ROOT / "dist" / "release" / ("ReverseSuite-%s-win64.zip" % VERSION)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(p for p in target.rglob("*") if p.is_file()):
            bundle.write(path, path.relative_to(target.parent).as_posix())

    files = sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file())
    print("folder:", target)
    print("files:", len(files))
    for name in files:
        print("  ", name)
    print("zip:", archive, archive.stat().st_size, "bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
