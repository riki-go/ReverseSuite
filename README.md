# ReverseSuite

Static PE analysis toolkit: loader, disassembly, function discovery, string
extraction, call graph, graph diff and diff reports — plus a local API/UI and a
desktop wrapper.

## Layout

- `src/reversesuite/` — analysis library and CLI
- `desktop` UI: `dist/index.html` (static shell shipped inside the app)
- `src-tauri/` — Tauri v2 desktop wrapper with the Python sidecar
- `fixtures/frozen/` — frozen test binaries (`a.exe`, `b.exe`, `b_unstripped.exe`, ...)

## CLI

```powershell
& .venv\Scripts\python.exe -m reversesuite.cli analyze fixtures\frozen\b.exe
& .venv\Scripts\python.exe -m reversesuite.cli calls   fixtures\frozen\b.exe --json
& .venv\Scripts\python.exe -m reversesuite.cli diff    fixtures\frozen\b.exe fixtures\frozen\a.exe
& .venv\Scripts\python.exe -m reversesuite.cli report  fixtures\frozen\b.exe fixtures\frozen\a.exe --format html --out out.html
& .venv\Scripts\python.exe -m reversesuite.cli serve   --root fixtures\frozen
```

`serve` prints `PORT=<n> TOKEN=<t>` on stderr and `{"url": ...}` on stdout; the
token is required in the `Authorization` header (never in the URL).

## Features

- PE loader with hard caps, packer hint (UPX), imports/exports/strings
- Function discovery (AC-15: recall 1.000 / precision 0.989 vs COFF truth)
- Strings with xrefs (AC-16), call graph with import resolution (AC-17/19)
- Graph diff with node matching (AC-18) and md/html reports (AC-20)
- Local API + UI (token, Host/Origin guards, rate limit, SSRF guard) and
  interactive SVG call/diff graph with drag, zoom and SVG/PNG export
- Job Object sandbox for helper processes (memory, process-count, wall-clock caps)

## Desktop app (Tauri v2)

Requirements: Python venv with this project installed, Node 18+, Rust stable,
MinGW-w64 (for the AC-2/repro harnesses; `tools/` is intentionally **not tracked in
git** — install it under `tools/mingw64` or point `OBJDUMP`/`GCC` at your own copy),
WebView2 runtime (preinstalled on Windows 11).

```powershell
# one-shot build (sidecar + installer)
.\build.ps1

# development run
npx tauri dev
```

What the wrapper does:

1. generates a random session token,
2. spawns `reversesuite-backend serve --root %USERPROFILE% --port 0 --token <token>`,
3. reads `PORT=` and `TOKEN=` from the sidecar stderr,
4. opens a 1200x800 webview on `http://127.0.0.1:<port>` and injects the token into
   `sessionStorage` through an initialization script (no manual token entry),
5. kills the sidecar when the window closes.

The bundled installer lands in `src-tauri/target/release/bundle/msi/`
(`ReverseSuite_0.2.0_x64_en-US.msi`).

## Known limitations (0.2.0)

- **MSI is not code-signed.** SmartScreen will warn on first install; signing needs a
  real CA certificate, which is not part of this repository.
- **Windowed run is unverified from the build host.** The build environment runs in
  Windows session 0, so WebView2 cannot create a window there (0x80070578).
  Headless checks cover the sidecar handshake, the API and the page DOM; the actual
  window must be verified on a normal desktop. `desktop.log` records what happened.
- **Indirect calls are only partly resolved.** A two-instruction register provenance
  pass resolves `mov reg,[rip+IAT]; call reg` and `lea reg,[rip+fn]; call reg`
  (b.exe: 16 edges). Calls through vtables or longer dataflow (a.exe: 17 remaining)
  need full value-set analysis and are out of scope for 0.2.0.
- **MSVC builds are not reproducible.** AC-4 covers the pinned MinGW recipe only.
- **No multi-user hardening.** The API binds loopback with a session token, but the
  desktop build accepts any absolute local path; on a shared machine run
  `serve --root DIR` instead.
- **URL analysis is static only.** Downloads are size-capped (256 MB), MZ-checked,
  private targets blocked, and temp files removed — but nothing is executed or
  AV-scanned.
## Tests

```powershell
$env:PYTHONPATH = "src"
& .venv\Scripts\python.exe -m unittest discover -s tests
```
