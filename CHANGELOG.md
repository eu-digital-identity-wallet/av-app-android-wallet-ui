# Changelog

## 2026.07-1

### Added

- `userAuthenticationRequired` Wallet Core config option that drives app
  authentication before credential presentation, and skips it when the wallet
  enforces biometric authentication on its keys
- Error feedback when biometrics are unavailable or not enrolled during
  mandatory biometric setup (`biometric_setup_required_error`), with da/de/fr/it
  translations
- CI check in `pull_request_pipeline.yaml` forbidding raw exception-message
  interpolation (`${e.message}`) in the passport/issuance paths
  (LOG-PII-PASSPORT-01) to prevent logging MRZ/document-number PII
- Documented the SCRN-CAPTURE-PASSPORT-01 finding (`FLAG_SECURE` missing on the
  passport capture Activities) with the required implementer action in the
  production hardening guide

### Changed

- Updated dependencies: AGP 9.0.1 → 9.2.1, Kotlin 2.3.0 → 2.3.20, Compose BOM
  2026.02.00 → 2026.06.00, Gradle 9.3.1 → 9.6.0, Koin 4.1.1 → 4.2.2, Ktor
  3.4.0 → 3.5.0, Coil 3.3.0 → 3.5.0, and others (navigation, lifecycle, core,
  camera, protobuf, material)
- Removed legacy support and now treat all compilation warnings as errors;
  removed `android.enableR8.fullMode=false`
- Replaced raw exception-message logging with generic messages plus the
  exception type in the passport-scanner NFC/MRZ paths
- Updated the configuration and how-to-build documentation
- Added ProGuard/R8 keep rules for ML Kit Text Recognition, Google Play Services
  SafeParcelable/KeepName, and MRZ parser record classes (reflection-backed), and
  extended the UI logic keeps to `navigation` and `component` packages to resolve
  R8 `MissingClass` problems in release builds
- Replaced SpongyCastle with BouncyCastle as the JCE provider in the
  passport-scanner (JMRTD security provider, MRTD trust store, and keystore utils)
  and removed the unused SpongyCastle provider and trust-store getters

### Removed

- SpongyCastle provider usage in the passport-scanner

### Fixed

- Splash screen footer hiding behind the system navigation bar
- SonarQube severity issues, including disabling cleartext traffic
  (`usesCleartextTraffic="false"`) for older Android versions and clearing the
  biometric error on cancel
- MRZ analyzer crash from invalid crop dimensions caused by the viewfinder
  height calculation producing negative/zero crop bounds; crop coordinates are now
  bounds-checked and coerced before bitmap creation

## 2026.06-3

### Changed

- Bound the database cipher and biometric authentication state to the vault key,
  including updated storage providers and revocation handling while the vault is
  locked.

### Fixed

- Presentation flow when the vault is locked.

## 2026.06-2

### Fixed

- Hardened certificate pinning for the issuer hosts: pin the Let's Encrypt
  intermediate CAs and ISRG root instead of leaf certificates so routine leaf
  renewal (~every 60 days) no longer breaks connectivity; extended the pin-set
  expiration to 2028-08-01.

## 2026.06-1

### Added

- Auth improvements including hardware-backed authentication
- Production hardening guide and Implementer Checklist references
- Face match model download via foreground service

### Changed

- Store authentication metadata with Tink instead of EncryptedSharedPreferences
- Updated EUDI Wallet Core to fix the Digital Credentials API
- Updated the face match library and applied short-term security improvements
  (pixel zeroing)
- Hardened release logging and removed sensitive data from logs
- Updated certificate pins

### Removed

- Basic root-detection logic
- Leftover proximity permissions

### Fixed

- Crash on the Android 10 biometric prompt
- Wrong host for the credential-offer deep link
- `SecurePrefsStore.getString` and decoupled onboarding biometrics from key
  generation / signing

## 2026.04-3-hotfix

### Fixed

- Reverted the face match threshold to 0.5

## 2026.04-3

### Changed

- Updated EUDI Wallet Core to 0.26.1

### Fixed

- Wallet Core crash when DPoP is disabled
- Security fixes from the security audit

## 2026.04-2

### Added

- Passport scanning improvements

### Changed

- Security improvements from the security audit

## 2026.04-1

### Added

- Dynamic age value rendering

### Changed

- Display age claims as boolean values and increased age claim size
- Updated app icon

## 2026.02-2

### Added

- Token/QR enrollment intro screen
- Wallet instance attestation with attestation-based client authentication
- Support for HAIP deep link schemes
- Test tags / resource IDs exposed for UI automation
- Staging certificate and full certificate chain for the JP case

### Changed

- Replaced Retrofit with Ktor for network operations
- Moved attestation logic to `network-logic` and adopted the SDK's
  `WalletAttestationsProvider`
- Upgraded to AGP 9 and updated Gradle, Wallet Core, and other dependencies
- Improved grouping of multi-element document claims
- Configure HTTP client logging based on build type
- Replaced German "Schnell-PIN" wording with "PIN" and fixed the Italian
  "Download" label

### Removed

- Unused dashboard files

### Fixed

- Crash on the `openid-credential-offer://` deep link caused by a Koin scope
- No-internet handling when downloading the face model
- Screen padding mismatch when showing `ContentError`

## 2026.02-1

### Added

- Download the biometric model on the intro screen
- App-wide no-internet connection error handling with retry
- MRZ line reconstruction algorithm to recover passport lines from partial or
  extra detected text
- Automated same-device regression tests

### Fixed

- Digital Credentials API QR codes not being handled

## 2026.01-1

### Added

- Integrated EUDI Wallet Core 23.0-SNAPSHOT with Zero-Knowledge Proof (ZKP)
  configuration

### Changed

- Synced string resources with the CMS
- Maintainability improvements

## 2025.12-1

### Added

- MRZ TD1 (ID card) support with NFC scanning
- Imported translations from the CMS

### Changed

- Updated OpenID4VCI to v1.0
- More informative error when NFC reading fails
- Reduced logging after the penetration test
- Updated ProGuard rules and dev configuration

### Fixed

- Go back on PIN re-enter
- Release exception related to obfuscation of native libraries

## 2025.11-2
- updated EUDI Wallet Core dependency to 0.20.0

## 2025.10-2

### Added

- Credential issuance via passport scanning flow

## 2025.10-1

### Added

- Initial support for Digital Credentials API (DCAPI) for presentation of org-iso-mdoc with protocol W3C 18013-7 Annex C
- Brute force protection for PIN entry
- Prevent insecure PINs (e.g., 1234, 1111)

### Changed

- Updated EUDI Wallet Core dependency to stable 0.19.0

### Removed

- RQES related code / support


## v0.1.0-beta05 - 2025-07-07

### Added

- Settings screen with app version display and option to delete all documents
- Show app version in splash screen
- Added ToS and data privacy sample link opening action

### Changed

- Customizable batch size and credential policy from WalletCoreConfig
- Show all text lines in landing page
- Updated build and release pipelines for demo APK and AAB distribution
- Update version with tag before build
- Bumped EUDI Wallet Core dependency to 0.18.0-SNAPSHOT

### Removed

- All translations (cleanup)
- Transaction Log related code, cleaned up proximity and dashboard feature modules, icons, strings,
  and image resources

### Fixed

- N/A

## v0.1.0-beta04 - 2025-06-26

### Changed

- Fixes same device presentation

### Removed

- Android Studio module templates

## v0.1.0-beta03 - 2025-06-24

### Added

- Added `av://` URI scheme handling to support deep linking

### Changed

- Updated app version name to `0.1.0-beta03`
- Updated Age Verification document identifier to versioned `eu.europa.ec.av.1`
- Updated issuance and presentation flows videos
- Updated EUDI Wallet Core dependency to stable version 0.17.0

## v0.1.0-beta02 - 2025-06-18

### Added

- Added AVSP URI scheme handling to support deep linking
- Added RedirectUri configuration to supported client ID schemes
- Added support for EUDI issuer
- Added automatic cleanup for depleted one-time-use documents
- Added credential count tracking to age verification documents

### Changed

- Updated EUDI Wallet Core dependency to version 0.17.0
- Updated document creation settings to request 30 credentials and use OneTimeUse policy
- Modified document metadata API usage (DocumentMetaData → IssuerMetadata)
- Updated BiometricCrypto implementation

## v0.1.0-beta01 - 2025-04-10

### Added

- Added AV issuer/verifier certificate
- Added AV issuer doc format to offer interactor
- Added IDE file templates for feature modules
- Added new onboarding flow pages:
  - Welcome screen with pager
  - Consent screen
  - PIN setup and confirmation
  - Enrollment options
  - Landing page

### Changed

- Updated app version name to 0.1.0-beta01
- Updated app icons and other UI assets
- Updated QR scan flow configuration to use NO_DOCUMENT for issuance
- Updated issuer URLs and document identifiers for age verification
- Updated CI configuration to use self-hosted GHA runners
- Updated build upload pipeline to use DEMO flavor
- Updated PIN validation flow to redirect to landing page after successful validation
- Updated splash screen design

### Removed

- Removed EUDI wallet certificates
- Removed EUDI certificate resources from configuration
- Removed unrelated sections from README

### Fixed

- Fixed issue allowing typing too many characters in PIN field
