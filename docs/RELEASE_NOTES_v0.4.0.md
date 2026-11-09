# ReverseSuite v0.4.0 - Release Notes

Released: 2026-11-09

## Headline: Android manifest decoding

.apk analysis now decodes the binary `AndroidManifest.xml` (AXML) instead of only
noting its presence. For every APK you get:

- package name, `versionName`, `versionCode`
- `minSdkVersion` / `targetSdkVersion`
- every declared permission (`uses-permission`)
- activities, services, receivers, providers with their `exported` state
- application flags: `debuggable`, `allowBackup`, `usesCleartextTraffic`
- the launcher activity (MAIN + LAUNCHER intent filter)

## Findings added

| kind | meaning |
| --- | --- |
| `package_name` | APK package id |
| `package_version` | versionName/versionCode pair |
| `min_sdk` | min and target SDK levels |
| `permission` | one finding per declared permission |
| `component` | `tag:name` for every manifest component |
| `component_flag` | exported/internal state of a component |
| `manifest_flag` | debuggable / allowBackup / cleartext flags |
| `main_activity` | launcher activity resolved from the intent filter |

## Implementation notes

- `reversesuite.formats.axml` is a stdlib AXML reader: resource string pool
  (UTF-8 and UTF-16LE), start/end element chunks, typed attribute values
- malformed manifests degrade gracefully: an `apk.manifest.unparsed` diagnostic
  is emitted and the rest of the APK (dex, native libs) is still analysed
- the manifest parser never executes anything and ignores unknown chunk types

## Compatibility

- No API or schema changes; new findings use newly registered rule ids
- Existing formats behave exactly as in 0.3.0

## Verification

- Unit tests: 185/185 passing (177 from 0.3.0 + 8 new AXML tests)
- `fixtures/gen_multi.py` now writes a real binary manifest into `demo.apk`,
  which the parser decodes to package `com.demo.app`, versionName `1.2.3`,
  versionCode 42, minSdk 21, targetSdk 33, two permissions and two components

## Known limitations

- Dalvik bytecode is still inventoried, not disassembled
- `resources.arsc` is not decoded yet (manifest only)
- iOS binaries with FairPlay enabled are reported as encrypted, not decrypted

## License

Proprietary - all rights reserved. See `LICENSE`.
