# Hardware-Backed Authentication

## Overview

The application enforces hardware-backed biometric authentication (Class 3 / `BIOMETRIC_STRONG`) for cryptographic key access. Keys are generated with `setUserAuthenticationRequired(true)` and prefer StrongBox-backed storage when available.

## Usability Trade-offs

| Device capability | User experience |
|---|---|
| StrongBox + Class 3 biometrics | Best security. Biometric prompt on every key use. |
| TEE-only + Class 3 biometrics | Same UX, slightly reduced hardware isolation. |
| Class 2 (weak) biometrics only | Biometric enrollment is blocked; user must rely on device credential (PIN/pattern/password). |
| No biometric hardware | Biometric option is unavailable during onboarding; device credential is the sole authentication method. |

Devices with only Class 2 sensors (e.g., some budget devices) cannot satisfy `BIOMETRIC_STRONG`. Users on these devices will not see a fingerprint/face option and must authenticate via PIN/pattern/password instead. This is a deliberate security decision: weak biometrics do not provide sufficient anti-spoofing guarantees.

## Fallback Behavior

### Key storage fallback

1. `setIsStrongBoxBacked(true)` is attempted first.
2. If the device throws `StrongBoxUnavailableException`, the key is regenerated with TEE-backed storage (hardware keystore without dedicated secure element).
3. All keys remain hardware-bound regardless of path; software-only key storage is never used.

### Authentication fallback

1. `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)` is checked at enrollment time.
2. If result is `BIOMETRIC_ERROR_NO_HARDWARE` or `BIOMETRIC_ERROR_UNSUPPORTED` the biometric option is not offered.
3. If result is `BIOMETRIC_ERROR_NONE_ENROLLED` the user is directed to system biometric settings.
4. For credential presentation (`DeviceAuthenticationController`), `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` is used, allowing PIN/pattern/password as fallback on any device.

### API level handling

| API level | Behavior |
|---|---|
| >= 30 (Android 11+) | `setUserAuthenticationParameters(0, AUTH_DEVICE_CREDENTIAL or AUTH_BIOMETRIC_STRONG)` requires fresh authentication per use. |
| 23-29 | `setUserAuthenticationValidityDurationSeconds(-1)` provides equivalent per-use enforcement via the deprecated API. |

## Limitations

- Biometric enrollment changes invalidate existing keys (`setInvalidatedByBiometricEnrollment(true)`). Users must re-enroll in the app after adding/removing biometrics at the system level.
- StrongBox availability varies by OEM; there is no user-visible indicator of which hardware path was selected.
- Device credential strength depends on user choice (a 4-digit PIN is weaker than a complex password) and cannot be enforced by the application.
