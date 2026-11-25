# CI

`.github/workflows/ci.yml` runs two jobs on `windows-latest`:

1. **python** - installs capstone and runs the full unit suite (196 tests, 2 skipped
   where the pinned objdump/gcc are absent).
2. **desktop** - freezes the backend with PyInstaller, runs `build.ps1` and uploads the
   produced MSI as an artifact.

The workflow builds the installer **for real** - no `continue-on-error` - and uploads it
as the `ReverseSuite-msi` artifact (verified: run 318a7ca, 13.5 MB). If it ever has to be
re-applied, `docs/ci-real-build.yml` holds the same content and a token without
`workflow` scope cannot push it, so use the web editor:

1. open <https://github.com/riki-go/ReverseSuite/edit/master/.github/workflows/ci.yml>
2. select everything, paste the contents of `docs/ci-real-build.yml`
3. commit - the next run builds the MSI and stores it under the run's artifacts

Until then the desktop job stays best-effort and the CI result only proves the Python suite.
