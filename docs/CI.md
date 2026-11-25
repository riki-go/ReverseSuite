# CI

`.github/workflows/ci.yml` runs two jobs on `windows-latest`:

1. **python** - installs capstone and runs the full unit suite (196 tests, 2 skipped
   where the pinned objdump/gcc are absent).
2. **desktop** - freezes the backend with PyInstaller, runs `build.ps1` and uploads the
   produced MSI as an artifact.

`docs/ci-real-build.yml` holds the version that builds the installer **for real**
(`continue-on-error` removed, MSI uploaded). It cannot be pushed with a token that has
no `workflow` scope, so it has to be applied through the GitHub web editor once:

1. open <https://github.com/riki-go/ReverseSuite/edit/master/.github/workflows/ci.yml>
2. select everything, paste the contents of `docs/ci-real-build.yml`
3. commit - the next run builds the MSI and stores it under the run's artifacts

Until then the desktop job stays best-effort and the CI result only proves the Python suite.
