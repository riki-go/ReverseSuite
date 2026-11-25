# ReverseSuite v0.6.0 - Release Notes

Released: 2026-11-26

Feature freeze lifted for the call-graph work that was deferred at 0.5.x.

## New

- **Inter-procedural value sets (M6.2).** `callgraph_interproc` models register copies,
  stack spills (`[rbp-x]`) and IAT loads. On `b.exe` the unresolved indirect calls drop
  from 17 to 14; two of them resolve through a spill/IAT chain. The rest take pointers
  returned by other calls, which needs return-value tracking (not in this release).
- **Vtable inventory with RTTI names (M6.3).** Read-only sections are scanned for arrays
  of code pointers; the pointer at `[-1]` is followed to the RTTI typeinfo and its name
  is demangled. Each table becomes a finding (`pe.callgraph.vtable`):
  `Derived:0x1e5e0;slots=4;targets=0x18f70,0x18f60,0x18fb0,0x18f80`.
  Virtual calls that go through an object pointer still need points-to analysis and stay
  unresolved - the limitation is intentional and documented.
- **DEX dispatch resolution.** `--dispatch` (CLI) or `"dex_dispatch": true` (API) adds
  an edge from every `invoke-virtual`/`invoke-interface` to each in-dex implementation
  found by walking the superclass chain. Measured on a real F-Droid build:
  `classes.dex` +1,410 edges, `classes2.dex` +47,560 edges. Off by default.
- New C++ fixture `fixtures/src/vtable_demo.cpp` (built with the pinned MinGW g++).

## Verification

- Unit tests: **205/205 passing** (196 previous + 4 interprocedural + 5 vtable)
- GUI end-to-end (opt-in): `python tests/e2e_ui.py` → 7 checks pass
- Installer built by CI (job `desktop`, artifact `ReverseSuite-msi`) and locally

## Compatibility

- Defaults unchanged: value sets stay opt-in via `--valueflow`, dispatch via `--dispatch`.
- `CallGraph.as_dict()` gains `interproc_resolved` and `vtables`.
