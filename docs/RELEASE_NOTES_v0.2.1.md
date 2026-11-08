# ReverseSuite v0.2.1 - Release Notes

Released: 2026-11-08

## What is in this package

- `ReverseSuite_0.2.1_x64_en-US.msi` - installer (recommended)
- `portable/` - run without installing: keep both `.exe` files in the same folder
- `manual/USER_MANUAL_TH.md` / `.html` - Thai manual
- `manual/USER_MANUAL_EN.md` / `.html` - English manual
- `README.md` - feature overview and CLI/API reference
- `SHA256SUMS.txt` - checksums for every file in this folder

## Highlights

- Static PE analysis: sections, imports/exports, strings, function discovery, call graph
- Call graph: direct calls, tail calls, MSVC thunks, separated indirect sites
- Diff engine: added/removed/moved functions and edges, with optional thunk filtering
- Report layer: Markdown and HTML reports from the CLI and the API
- Desktop wrapper (Tauri): Analyze, Diff & Report, interactive SVG graph
- URL analysis with SSRF guard, size cap and temp-file cleanup

## Fixed in this version

- Path validation rejected absolute paths outside the allowed root; 0.2.1 accepts any
  absolute path and URLs (the CLI still supports an optional `--root` sandbox).
- Desktop CSP blocked same-origin fetch; the token is now injected through a nonce.
- Token was injected with naive escaping; now serialized with `serde_json::to_string`.
- `GET /favicon.ico` answered 401; now returns 204 without requiring a token.
- Long path fields were single-line inputs; now textareas.
- Browser browse, drag & drop and upload (`upload_id`) work end to end.
- Graph layout switched to a force-directed layout for readability.

## Known limitations

- Unsigned binaries: Windows SmartScreen may warn on first run.
- Files with a `.text` section over 32 MB skip function discovery and xref
  (`text_too_large_for_functions`); strings still work.
- Indirect call targets are reported as separate sites, not resolved functions.
- Value-set analysis (M6.1) is experimental and disabled by default (`--valueflow`).
- Inter-procedural analysis (M6.2) and vtable/RTTI recovery (M6.3) are not implemented.

## Verification

- Unit tests: 155/155 passing
- objdump agreement on `a.exe`: 0.999122 over 249,453 instructions
- Call-site recall 1.0000 (125/125); precision 0.9843 for direct + import edges

## License

MIT. See `LICENSE`.
