# ReverseSuite v0.5.2 - Release Notes

Released: 2026-11-25

## Changes

- **English-only interface.** Every message in the browser UI is now English; the error
  map no longer mixes Thai with English labels.
- **FairPlay reporting (0.5.1 regression fix).** Encrypted Mach-O images now produce an
  `encryption` finding with `cryptid`, offset and size, not just a diagnostic:
  `cryptid=1;offset=0x1000;size=64`.
- `uninstall-clean.ps1` ships in the package (MSI uninstall plus optional removal of
  `%LOCALAPPDATA%` data, `-KeepUserData` keeps the old behaviour).

## Verification

- Unit tests: 196/196 passing
- Real-world APK (F-Droid, 11.9 MB, 2 dex): 48,389 nodes / 86,485 edges in 7.1 s
- UI checked in the installed desktop build

## Compatibility

- API responses and findings unchanged apart from the new `encryption` finding kind.
