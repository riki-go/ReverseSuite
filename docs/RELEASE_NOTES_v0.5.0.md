# ReverseSuite v0.5.0 - Release Notes

Released: 2026-11-10

## Headline: Dalvik method-level call graph

`.dex` and `.apk` analysis now builds a call graph from Dalvik bytecode instead of
only listing methods:

- every `code_item` is decoded and the invoke instructions are collected
  (`invoke-virtual`, `invoke-super`, `invoke-direct`, `invoke-static`,
  `invoke-interface`, the `/range` forms, plus `invoke-polymorphic`/`invoke-custom`)
- each invoke becomes an edge `caller_method -> callee_method` keyed by `method_id`
- payload pseudo-instructions (`packed-switch`, `sparse-switch`, `fill-array-data`)
  are skipped correctly so the instruction walk stays aligned

## Filtering

- framework and library callees (`java.*`, `javax.*`, `android.*`, `androidx.*`,
  `kotlin.*`, `org.json.*`, `libcore.*`, ...) are hidden by default so the graph shows
  only the app's own classes
- `--all-methods` (CLI) or `"dex_all_methods": true` (API) keeps everything
- the number of hidden framework calls is reported in the stats and in the
  `dex_callgraph` finding

## Interfaces

- CLI: `analyze app.apk` prints `dexgraph N nodes / M edges`; `--json` adds a
  `dex_graph` object with `nodes` (id, label, class, framework), `edges`
  (caller, callee, kind) and `stats`
- API: `POST /analyze` returns the same `dex_graph` object
- UI: new **view dex graph** button renders the DEX graph with method labels, and
  edges coloured by invoke kind (the existing node cap now keeps the most connected
  methods first)

## Fixture

`fixtures/gen_multi.py` now writes a real `classes.dex` with `class_data` and bytecode:
`com.demo.App.run()` calls `com.demo.App.helper()` (virtual) and
`java.lang.System.currentTimeMillis()` (static), which the tests assert on.

## Verification

- Unit tests: 192/192 passing (185 from 0.4.2 + 7 DEX call-graph tests)
- CLI on `fixtures/multi/classes.dex`: `dexgraph 2 nodes / 1 edges (methods scanned 2,
  framework hidden 1)`
- CLI on `fixtures/multi/demo.apk`: same graph after unpacking `classes.dex`

## Known limitations

- Only invoke targets are resolved; dynamic dispatch (interfaces, reflection) still
  shows the declared interface method, not the concrete implementation
- Opcodes are not disassembled; the graph is built from the invoke stream only
- Framework filtering is prefix-based and can be tuned with `--all-methods`

## License

Proprietary - all rights reserved. See `LICENSE`.
