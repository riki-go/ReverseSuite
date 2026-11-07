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

## Desktop app (Tauri v2)

Requirements: Python venv with this project installed, Node 18+, Rust stable,
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

The bundled installer lands in `src-tauri/target/release/bundle/msi/`.

## Tests

```powershell
$env:PYTHONPATH = "src"
& .venv\Scripts\python.exe -m unittest discover -s tests
```
