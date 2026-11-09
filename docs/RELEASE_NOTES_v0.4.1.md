# ReverseSuite v0.4.1 - Release Notes

Released: 2026-11-09

## Fixes

- **Call graph showed 0 edges on large binaries.** The 400-node cap kept nodes in
  address order, so the edge filter afterwards dropped almost every edge. Nodes are
  now ranked by degree before the cap, so the graph shows its densest subgraph.
- **UI subtitle still said "Static PE analysis"** even though 0.3.0 added Mach-O,
  ELF and Android support. The header now names all supported families.

## Verification

- GUI check on `fixtures\frozen\a.exe`: `analyze` -> findings 7914, functions 1507,
  edges 5451; `view call graph` renders a connected graph instead of 400 isolated nodes
- GUI check on `fixtures\multi\demo.apk`: `analyze` -> status ok, findings 65, diagnostic
  `dex.bytecode.not_analyzed`
- Unit tests: 185/185 passing

## Notes

- No backend behaviour changed for PE analysis; this is a UI/rendering patch.
- Dalvik bytecode is still inventoried only; FairPlay-encrypted iOS binaries are still
  reported as encrypted rather than decrypted.
