# ReverseSuite v0.3.0 - User Manual (English)

ReverseSuite is a universal static binary analyzer. It scans PE, Mach-O (.ipa),
ELF (.so) and Android (.apk/.dex) files for functions, strings, call graphs and
diffs, and never executes the target file.

## Supported formats (0.3.0)

| Family | Extensions | What is analysed |
| --- | --- | --- |
| Windows PE | `.exe` `.dll` `.sys` | sections, imports/exports, strings + xref, functions, call graph, diff, report |
| iOS Mach-O | `.ipa`, Mach-O | IPA unpacking, `__TEXT,__text`, `__cstring`, symbols, ARM64 prologues, `cryptid` |
| Android APK | `.apk` | manifest presence, every `classes*.dex`, every `lib/<abi>/*.so` |
| Dalvik DEX | `.dex` | classes, methods, fields, string table (no bytecode disassembly) |
| ELF | `.so`, Linux | x86 / x86-64 / ARM / AArch64 sections, dynsym, ARM64 functions |

Detection is magic-byte based, so a renamed file is still classified correctly.

---

## 1. Installation

1. **Remove old versions** - Settings > Apps > Installed apps > search `ReverseSuite` > Uninstall
2. **Install** - open `ReverseSuite_0.3.0_x64_en-US.msi` and follow the wizard
3. **Launch** - Start menu > type `ReverseSuite` > Enter

> The MSI is not code-signed. If SmartScreen warns, choose **More info** > **Run anyway**.

---

## 2. Screen overview

- **Status bar** (top left): `connected` (green) means the backend is ready;
  `checking...` or `token required` means the backend is not reachable (see section 7).
- **Analyze** - analyse a single file.
- **Diff & Report** - compare two files and download a report.
- **Graph** - interactive view of the call graph or the diff.

---

## 3. Analyze

Three ways to feed a file:

1. Type an absolute path, e.g. `D:\samples\b.exe`, `D:\samples\app.apk`, `D:\samples\MyApp.ipa`
2. Type a URL starting with `http://` or `https://` (downloaded to a temp folder, removed afterwards)
3. Drag a file from Explorer into the box, or press **browse...**

Reading the output:

- `status` - `ok` on success
- `size` - file size in bytes
- `findings` - total findings
- `functions` - discovered functions
- `edges` - resolved call-graph edges (`imports`, `indirect`)
- `diagnostics` - warnings such as `text_too_large_for_functions` (the `.text` section is
  larger than 32 MB, so function discovery and xref are skipped; string extraction still runs)

---

## 4. Diff & Report

1. **Left binary path** - first version (path, URL or browse)
2. **Right binary path** - second version
3. **ignore thunks** - recommended for MSVC builds: hides linker thunks that add noise
4. Press **run diff**

Output:

- `nodes +X -Y ~Z` - functions added, removed, moved
- `edges +X -Y =Z` - edges added, removed, unchanged

Press **download report** to save an HTML report (Markdown is available through the API).

---

## 5. Graph

- `view call graph` - graph of the last analysed file
- `view diff graph` - diff graph (green = added, red = removed)
- `export svg` / `export png` - download the current graph
- `clear` - clear the canvas

Interaction: drag nodes, pan the background, zoom with the mouse wheel. The layout is
force-directed, and large graphs are capped at the first 400 nodes (the status line says so).

---

## 6. Security limits

- **URL fetching (SSRF guard)** - private, link-local and reserved targets are blocked;
  loopback (`127.0.0.1`) is allowed for local fixtures. `--allow-private-urls` lifts the
  restriction when running the backend from the CLI.
- **Size cap** - URL downloads are limited to 256 MB, 30 s timeout, and must start with `MZ`.
- **Temp cleanup** - downloaded/uploaded files are removed by an `atexit` hook and expire
  after 15 minutes; a force-killed process may leave files in `%TEMP%`.
- **Rate limit** - 60 requests per minute per client (`429 rate_limited`).
- **Token** - sent only in the `Authorization: Bearer ...` header, never in the URL.

---

## 7. Troubleshooting

**The app stays on `checking...`**
- The Python sidecar did not start. Close and reopen the app once.
- If it persists, read `%LOCALAPPDATA%\ReverseSuite\desktop.log`.

**`path rejected: it must be inside the allowed root folder`**
- You are running 0.2.0 or older, or the backend was started with `--root`.
- Update to 0.2.1, which accepts any absolute path and URLs.

**The graph is unreadable**
- Zoom in, or export SVG and inspect it in an image viewer.

**`429 rate_limited`**
- Wait a minute, or raise `--rate-limit` when starting the backend.

---

ReverseSuite v0.3.0 - MIT License.
