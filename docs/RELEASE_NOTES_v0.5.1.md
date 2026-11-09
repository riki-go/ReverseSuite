# ReverseSuite v0.5.1 - Release Notes

Released: 2026-11-10

## Fixes

- **Temporary folder leak in `/diff` and `/report`.** When either input was an
  `http(s)` URL the server downloaded it into a temp folder and never removed it,
  leaving a copy of the analysed binary on disk after every request. Both routes now
  clean up in a `finally` block.
- **Stable API tests on antivirus-protected machines.** PE copies written to `%TEMP%`
  can be blocked on read (Windows returns `ERROR_VIRUS_INFECTED`, which Python reports
  as `OSError` errno 22). `api.serve()` accepts `upload_parent=` so the temporary
  upload/download folder can live somewhere the AV excludes, and the API tests use it.
- The distributed package now carries the current proprietary `LICENSE` and the
  portfolio `README` (the v0.5.0 package still shipped the old MIT text).

## Compatibility

- API and CLI behaviour unchanged; `upload_parent` is an optional keyword argument.
- No schema or finding changes.

## Verification

- Unit tests: 192/192 passing
- `smoke`: analyze .apk + `.dex` graph + diff from the installed build
- Package re-generated from the same binaries (no code drift)

## Known limitations (unchanged)

- DEX graphs resolve the declared target of each `invoke`; dynamic dispatch is not resolved
- FairPlay-encrypted iOS binaries are reported as encrypted, not decrypted
- Framework filtering is prefix based; use `--all-methods` to keep `java.*`/`android.*`
