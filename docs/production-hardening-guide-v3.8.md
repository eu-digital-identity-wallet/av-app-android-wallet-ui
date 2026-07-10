# Production Hardening — Mobile Security Considerations

Security only

EU Digital Identity Wallet — Age Verification

Android & iOS reference implementations

## Reference repositories

- av-app-android-wallet-ui
- av-app-ios-wallet-ui

## Companion material

- Wallet provider server, issuer, code quality, AV Profile and the rest of the blueprint: https://ageverification.dev
- AV Profile (Annex A): annex-A-av-profile

## Mock infrastructure used by the reference apps

- Issuer (mock): https://issuer.ageverification.dev
- Wallet provider server (mock): https://wallet-provider.ageverification.dev

Both endpoints above are reference / mock implementations. A production deployment replaces them with the implementing party's production issuer and production wallet provider server, and updates the bundled trust anchors, integrity registration, app-link configuration and pinning policy accordingly.

## Document control

| Field | Value |
|---|---|
| Version | 3.8 |
| Date | 30 April 2026 |
| Classification | PUBLIC |
| Audience | The implementing party publishing a production AV wallet on Google Play and the App Store (and, where adopted, EU alternative iOS distribution channels) from the open-source reference repos. |
| Scope | Mobile-side security considerations for taking the open-source reference apps toward production distribution. This document covers security controls that protect the mobile app, the locally stored Proof of Age attestations, the presentation path and the production distribution identity. Each item is something to evaluate and decide, not a universal release blocker. |
| Out of scope | Product UX, code quality, protocol correctness, AV Profile conformance, wallet provider server hardening, issuer setup, GDPR / DPIA, operational governance, release approvals, penetration-test procurement, vulnerability disclosure, incident response and inclusion policy. Those topics are handled by ageverification.dev and the implementing party's production governance. |

# Part 1 — Purpose and security boundary

The open-source AV wallet reference applications provide the core reference flows for issuing, storing and presenting Proof of Age attestations. They are not, by themselves, a complete production posture, but the production posture should also remain proportionate to the AV use case.

The AV app is not a full PID wallet and should not be treated as if it stored a full set of high-assurance identity attributes. The mobile app stores and presents Proof of Age material, in practice an age-over threshold attestation such as `age_over_18` with a true/false value. The security goal is therefore different from a full EUDI Wallet / PID deployment: protect the local AV attestation and its unlinkability properties with a substantial, practical mobile-security posture, while preserving broad device availability.

This document is the practical mobile-security reading for that transition. It deliberately focuses on security only: what the implementing party should evaluate, configure, replace or harden before publishing a production AV wallet derived from the open-source repositories.

**Architecture-spec basis.** The EU Age Verification Blueprint architecture specification (§6.1) assigns the following controls to implementers:

> Architecture spec §6.1: The app configuration and UI SHALL be further protected using code hardening and runtime application self-protection or similar security measures to protect the total application against malicious attacks. The app attestation checks are not included in scope (including anti-root measures, etc.), with implementation responsibility resting with the implementers.

The practical consequence is not that every implementer must choose the strictest possible mobile policy. It is that the implementing party should make an explicit, documented decision about runtime protection, app/device integrity and hardware-backed key storage, proportionate to the AV threat model and the desired device coverage.

## Decision language

This document uses three levels:

- **Baseline consideration** — normally evaluated for any production AV wallet, because it affects distribution identity, security posture or the protection of locally stored attestations.
- **Preferred hardening** — a stronger option to use where available, especially when it improves security without materially reducing device coverage.
- **Policy trade-off** — a control that may be valuable but can reduce availability, create operational risk or weaken open-source auditability. The implementing party decides whether the trade-off is justified.

## Terminology used in this document

Three distinct concepts recur throughout. They are not synonyms.

- **mDoc credential / Proof of Age attestation material** — the ISO/IEC 18013-5 format object issued by the issuer and stored on the device, usually in a batch (architecture spec §3.4.1) because Proof of Age attestations are intended to be single use.
- **Proof of Age presentation** — the presentation derived from locally held Proof of Age material and shown to a relying party at the moment of an age verification check.
- **Wallet-instance attestation** — the binding between this specific install of the app on this specific device and the wallet provider server, issued after an integrity or app-instance evaluation.

## Threat scenarios at a glance

The mobile-specific threats this document addresses are expanded in Part 8.

- **Scenario A — holder bypass.** The dominant AV threat: cloning, instrumentation, biometric reuse by a third party and replay of locally held Proof of Age material.
- **Scenario B — automation and scale abuse.** Emulator farms, scripted devices and modified builds used at volume.
- **Scenario C — network and redirect adversary.** MITM, debug proxying, trust-anchor manipulation and redirect-URI hijack.
- **Scenario D — compromised installed base.** CVE in a released version, compromised build observed in distribution or signing-key compromise.
- **Scenario E — supply-chain compromise.** Third-party SDK compromise, dependency hijack or build-pipeline compromise.

## Technical considerations at a glance

| Topic | Level | Decision / evidence to record | Section |
|---|---|---|---|
| Production app identity | Baseline consideration | Production Android applicationId and iOS bundle id under the implementing organisation's developer accounts. | Part 2 |
| Store-compliant target platform | Baseline consideration | Android targetSdkVersion satisfies current Google Play submission rules; iOS deployment target supports the selected security controls. | Part 2 |
| Production signing | Baseline consideration | Android Play App Signing/upload key and iOS Distribution signing configured through controlled release infrastructure. | Part 2 |
| Build artefacts and SBOM | Baseline consideration | Signed AAB/IPA, dependency lockfiles and optional SBOM tied to a tagged git revision. | Part 2 |
| Runtime protection | Baseline consideration | Commercial RASP or documented open-source detection stack considered for release builds. | Part 3 |
| Screen-capture policy | Baseline consideration | Android FLAG_SECURE and iOS capture detection/masking policy evaluated for screens exposing sensitive AV material. | Part 3 |
| Device/app integrity | Baseline consideration | Play Integrity and App Attest production configuration evaluated, with server-side verification where used. | Part 4 |
| Hardware-backed keys | Baseline consideration | StrongBox preferred when available; Trusted Execution Environment acceptable as the normal broad-coverage Android baseline. | Part 4 |
| User presence binding | Baseline consideration | Biometric/PIN/passcode policy chosen according to desired assurance and device coverage. | Part 4 |
| Production endpoints + trusted list | Baseline consideration | Mock URLs replaced; production issuer/wallet provider endpoints configured; production AV Trusted List source configured. | Part 5 |
| Verified redirect handlers | Baseline consideration | Android App Links and iOS Universal Links evaluated for OID4VCI/OID4VP redirect paths. | Part 5 |
| System browser auth flows | Baseline consideration | Chrome Custom Tabs / ASWebAuthenticationSession preferred over in-app WebView. | Part 5 |
| Force-update and kill-switch | Baseline consideration | Signed configuration and key rotation evaluated; failure posture chosen according to AV risk. | Part 6 |
| Telemetry privacy and unlinkability | Baseline consideration | Integrity/RASP telemetry avoids credential material and avoids stable linkable presentation identifiers. | Part 7 |
| Certificate pinning | Policy trade-off | Explicit decision: pin with backup rotation plan, or do not pin and operate strict TLS plus CT monitoring. | Part 5 |

# Part 2 — Distribution, signing and store security considerations

The open-source build cannot be submitted unchanged as a production store app. The first production security boundary is the distribution identity: the package name, signing material, release artefacts, store account and platform versions that users will trust.

## Baseline considerations

- **Production identifiers.** Use a production Android applicationId in Google Play Console and a production iOS bundle identifier in App Store Connect, both under the implementing organisation's developer account. Sample, demo and development identifiers should not be reused in production.
- **Android target API compliance.** For Google Play submission in 2026, the release should target the current Play-required API level. As of the current Play policy, new apps and updates must target Android 15 (API level 35) or higher. `minSdkVersion` is a separate compatibility and device-coverage decision; it does not satisfy the Play target API requirement.
- **Minimum supported platform policy.** Set `minSdkVersion` and `MinimumOSVersion` so the selected security controls behave predictably on supported devices. This should be a coverage decision, not a reflexive move to exclude older devices. If a control is conditional on hardware or OS support, define the reduced-assurance behavior rather than silently failing.
- **Android signing.** Play App Signing is the usual Google Play pattern. The implementing party controls the upload key; Google Play controls the app-signing key used for distributed APKs. The upload key should be generated and stored in controlled release infrastructure, not committed to source control and not exposed in CI logs.
- **iOS signing.** Use an App Store Distribution certificate and production provisioning profile under the production Apple developer account. TestFlight is the normal pre-store validation track.
- **Build artefacts.** Per release, produce a signed AAB for Google Play and a signed IPA/archive for Apple distribution, tied to a tagged git revision, dependency lockfiles and release configuration. An SBOM (CycloneDX or SPDX) is useful for downstream verification and supply-chain review.
- **No demo service leakage.** Verify on the release artefact that issuer.ageverification.dev, wallet-provider.ageverification.dev and other demo/test endpoints are absent from production configuration.

## Preferred hardening

- **Controlled signing custody.** Store upload keys, iOS signing credentials and release secrets in an HSM-backed or equivalent secret-management environment with auditable access.
- **Reproducibility statement.** If the deployment promises open-source auditability, publish what can be reproduced from source and what cannot. Commercial RASP, store signing and iOS build constraints should be explicitly disclosed.
- **Store-channel policy.** Treat every distribution channel as a separate trust boundary. Google Play and the App Store are the primary channels. EU alternative iOS distribution and Android third-party stores require a separate trust and update decision.

# Part 3 — Runtime application self-protection

Runtime protection raises the cost of tampering, repackaging, instrumentation and abuse on hostile devices. It should be considered as hardening for an AV wallet, not as a guarantee that the client can become fully trusted.

## Baseline considerations

- **RASP or equivalent runtime protection.** Evaluate a release-build protection layer that covers anti-debugging, anti-instrumentation, anti-hooking, anti-tamper, repackaging detection, emulator detection, root/jailbreak detection and code-integrity checks. A commercial product such as DexGuard/iXGuard, Promon SHIELD, AppDome, Build38 or V-Key is the common pattern. If commercial RASP is not adopted, document the open-source composition and the expected bypass risk.
- **Signals as risk inputs.** RASP and environment detections are risk signals, not infallible local truth. For online operations, the app can report them to the wallet provider server, which makes allow, step-up, soft-block or hard-block decisions according to policy.
- **Tamper response policy.** Define what happens on debugger detection, hook detection, repackaging, root/jailbreak signal, emulator signal and app-signature mismatch. For an AV app, the policy can be proportionate: high-confidence tamper may block sensitive operations, while lower-confidence signals may trigger step-up or re-attestation.
- **Screen-capture defence.** Android release builds should use `FLAG_SECURE` on screens that expose credential material, QR/session secrets or sensitive confirmations. iOS has no equivalent prevention API; use capture detection (`UIScreen.isCaptured` and capture-change notification) and mask or abort flows where exposing AV material would be inappropriate.

### Known finding in this reference implementation — SCRN-CAPTURE-PASSPORT-01 (Medium)

The passport-scanner Activities render live MRZ data (full name, date of birth, document number, nationality) and capture the user's face image for liveness, but do **not** set `FLAG_SECURE`. The affected screens are:

- `passport-scanner/src/main/java/kl/open/fmandroid/CameraActivity.kt` — front-camera face capture (liveness/embedding).
- `passport-scanner/src/main/java/eu/europa/ec/passportscanner/SmartScannerActivity.kt` — MRZ camera preview.
- `passport-scanner/src/main/java/eu/europa/ec/passportscanner/nfc/NFCActivity.kt` — NFC readout (document data + face image bytes).

On a hostile device (in scope per the threat model in Part 8), a screen-recording app (`MediaProjection`), a malicious accessibility service, or an over-the-shoulder screenshot can capture full document PII and the user's biometric face image during scanning — a far larger disclosure than the boolean `age_over_NN` attestation the app is designed to protect. The misleading `MainActivity` comment at `assembly-logic/src/main/java/eu/europa/ec/assemblylogic/ui/MainActivity.kt` justifies the global omission with "This wallet displays only age-over-X boolean attestations — no passport images, document numbers, or sensitive PII appear on screen", which is not true of the passport-scanning sub-flow.

**Implementer action required before production distribution:** set `window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)` in `onCreate` (before `super.onCreate`) on each of the three capture Activities above, or apply it app-wide via the base Activity. Correct the `MainActivity` comment so it no longer implies no sensitive imagery is ever shown; state that `FLAG_SECURE` is not set on `MainActivity` (age-over-X booleans only) but is set on the sensitive capture screens individually. Reference: `SECURITY_AUDIT_2026-07-07.md`; OWASP MASVS-PLATFORM-3.

## Policy trade-offs

- **Open-source auditability.** Opaque commercial RASP creates an auditable contradiction for an open-source wallet: the public source no longer fully explains the distributed binary. Where this matters, publish a signed statement identifying the vendor, integration scope and classes of protection applied.
- **False positives and inclusion.** Aggressive blocking on root, jailbreak, emulator or device-integrity signals can exclude legitimate users and reduce the value of a broad AV deployment. Decide which signals block, which signals step up and which signals are telemetry-only.

# Part 4 — Device integrity and wallet-instance attestation

Device and app integrity checks are high-value controls, but the policy should be proportionate to the AV app's role. The app protects Proof of Age material such as an `age_over_18` assertion, not a full PID data set. The aim is to make cloning, replay and large-scale automation harder while preserving broad access on ordinary Android and iOS devices.

## Baseline considerations

- **Play Integrity production setup.** Register the production Android applicationId and link the production Play Console app to the implementing party's Google Cloud project. Where Play Integrity is used, verdict verification should happen server-side.
- **Use the right Play Integrity request mode.** Standard requests are suitable for frequent server calls and can bind the protected action using `requestHash`. Classic requests are less frequent and more appropriate for operations where a fresh challenge is useful, such as issuance or wallet-instance attestation refresh; they should use a server-generated nonce or equivalent replay protection.
- **App Attest production setup.** Enable App Attest for the production iOS bundle identifier where supported, and verify App Attest attestation/assertion objects server-side. Development and production App Attest environments are not interchangeable.
- **Server-issued challenges.** Integrity and attestation flows should use server-issued random challenges. Client time should not be the root of a security decision.
- **Android hardware-backed key storage.** Generate wallet-instance keys in Android Keystore and prefer hardware-backed storage. If StrongBox is available and compatible with the selected algorithm and performance requirements, prefer StrongBox. Otherwise, a Trusted Execution Environment-backed key is the normal broad-device-coverage baseline for AV. The policy should avoid requiring StrongBox-only operation unless the implementing party explicitly accepts the loss of many Android devices.
- **Android key attestation.** Where server-side key attestation is used, verify the attestation certificate chain on the server. Check chain signatures, Google attestation roots, revocation status, attestation challenge, app/package identity, verified boot/device state and whether the key is backed by `TrustedEnvironment` or `StrongBox` according to the selected policy.
- **Android attestation root rotation.** If Android Key Attestation is used, the server trust store should include both the old and new Android Key Attestation roots and handle Remote Key Provisioning chains. By April 2026, RKP-enabled devices may use the new root exclusively.
- **iOS wallet-instance key binding.** iOS does not provide the same arbitrary Secure Enclave key-attestation chain as Android. Use App Attest to validate the app instance and bind the server-registered wallet instance to a Secure Enclave-backed key generated by the app where applicable. Treat this as an asymmetric trust model, not as identical Android-style key attestation.
- **User presence policy.** Android `BIOMETRIC_STRONG` is preferred for cryptographic operations where available and compatible with the target population. A PIN/passcode fallback may be acceptable for AV if the implementing party documents the reduced assurance. iOS biometry can be used for sensitive operations; passcode fallback should be a conscious policy decision rather than an accidental default.
- **Biometric enrolment change invalidation.** Android wallet-instance keys can use `setInvalidatedByBiometricEnrollment(true)` where appropriate. iOS keys can use `kSecAccessControlBiometryCurrentSet` where the app gates key use through Keychain/Secure Enclave access control. Adding or replacing a biometric can then force re-onboarding or re-binding before sensitive operations resume.
- **Wallet-instance lifecycle.** Consider re-attestation on credential issuance, wallet-instance attestation refresh, detected key loss, reinstall indicators, app-signature mismatch, material device-state change and policy-defined time windows. On key loss or failed attestation, suspend or refresh the wallet-instance server grant according to the selected risk policy.

## Preferred hardening

- **StrongBox when available.** StrongBox should be preferred on devices that support it, because it gives stronger isolation. It should not be treated as the default availability baseline for AV, because many otherwise suitable Android devices do not provide StrongBox.
- **TEE as the practical baseline.** Trusted Execution Environment-backed Android Keystore keys are the practical baseline for broad Android support. A production AV wallet can prefer StrongBox without excluding TEE-backed devices.
- **Credential batch protection.** Because Proof of Age attestations are designed for single use and issued in batches, hardening protects the whole local batch and any state that could link presentations. Export of the batch weakens unlinkability for future presentations under those credentials.

# Part 5 — Production endpoints, trust anchors, redirects and pinning

The production build should replace the mock environment and harden the channels that carry issuance, wallet-instance attestation, integrity evaluation and OID4VCI/OID4VP redirects.

## Baseline considerations

- **Replace mock infrastructure.** Production builds should point at the implementing party's production issuer and wallet provider server. Release verification can include string/resource inspection of the release artefact to confirm no mock endpoints remain in production configuration.
- **AV Trusted List as trust anchor source.** Configure the production AV Trusted List as the source of attestation-provider trust. The architecture spec identifies the AV Trusted List as an ETSI TS 119 612 trusted list published through the eIDAS Dashboard. Sample trusted lists are not production trust anchors.
- **Verified app links and Universal Links.** OID4VCI and OID4VP redirect paths should use verified Android App Links (`assetlinks.json` plus `android:autoVerify="true"`) and iOS Universal Links (`apple-app-site-association` plus Associated Domains entitlement). Custom schemes are easier to hijack and should be a deliberate compatibility decision, not the default for sensitive redirect handoff.
- **System-managed browser components.** Authorisation redirects should open in Chrome Custom Tabs on Android and `ASWebAuthenticationSession` on iOS. In-app WebView/WKWebView is weaker for identity-provider or authorisation-session paths because it runs inside the wallet app process.
- **Strict TLS and debug-proxy resistance.** Release builds should use strict TLS validation and should not trust user-installed CAs for production endpoints unless a controlled enterprise deployment explicitly requires it. Debug proxy hooks and test network-security overrides should be absent from release configuration.

## Policy trade-offs

- **Certificate pinning.** Pinning can prevent acceptance of a misissued certificate, but bad rotations can create mass outages. If adopted, pin only endpoints under the implementing party's TLS control (issuer, wallet-instance attestation, integrity evaluator), use SPKI pins, ship at least one backup pin for a key not yet in TLS rotation and document the emergency rotation procedure. If not adopted, operate strict TLS validation with controlled CA scope and Certificate Transparency monitoring.
- **Certificate Transparency monitoring.** CT is a detection control, not a replacement for pinning. It can be the realistic fallback when pinning risk is judged too high.

# Part 6 — Force-update and kill-switch

The mobile binary can include emergency controls for compromised versions, vulnerable builds, key compromise and backend policy changes. The server-side counterpart belongs to the wallet provider server material; this section covers only the mobile release considerations.

## Baseline considerations

- **Bundled verification keys.** Public keys that verify signed minimum-version configuration and signed kill-switch messages should be bundled in the release binary rather than fetched as trust roots at runtime.
- **Verification-key rotation.** Shipping current and next verification keys allows server-side signing key rotation without an emergency app release.
- **Signed configuration.** Minimum-version and kill-switch messages should include a server-issued timestamp, counter or equivalent freshness value to prevent replay of stale allow decisions.
- **Failure posture.** On configuration fetch failure, the app may allow a grace period for availability. The implementing party should decide whether sensitive operations fail closed after that window or continue under reduced assurance. For AV, this is a policy decision balancing safety, abuse prevention and access.
- **Mid-protocol behavior.** If a kill-switch fires during an active presentation, the app may allow that protocol instance to complete if aborting creates worse privacy or consistency risk. New sensitive operations can then follow the updated policy.

# Part 7 — Security telemetry and privacy boundary

Telemetry is useful only if it does not weaken the privacy model. Integrity signals should not become a tracking system that defeats unlinkability.

## Baseline considerations

- **Telemetry contract.** Integrity verdicts, RASP detections, pinning failures, install-source results and kill-switch state should be reflected in the privacy notice, iOS Privacy manifest and Android Data Safety form where emitted.
- **No credential material in telemetry.** PII, biometric data, document images, credential material, cryptographic keys, QR payloads, authorisation codes and raw Proof of Age presentations should not be emitted.
- **Unlinkability preservation.** Telemetry identifiers should be scoped and rotated so they do not let the wallet provider, relying parties or analytics systems correlate a user's presentations across relying parties. Where correlation is needed for abuse prevention, it should be documented as a server-side risk decision outside this mobile-only guide.
- **Server-side policy audit.** Allow, step-up, soft-block and hard-block decisions can be auditable on the wallet provider side without embedding a stable user-tracking identifier in the mobile telemetry stream.

## Application logging policy

Sensitive data must never appear in any log output in any build type.

- **Never log** PINs, passcodes, transaction codes, or any credential material.
- **Never log** document personal data: date of birth, computed age, raw MRZ strings, document numbers, or expiry dates.
- **Redact before logging.** Exception messages from third-party libraries (jMRTD, EUDI SDK) may contain personal data. Log a generic message rather than the raw exception.
- **Data classes holding sensitive fields** must override `toString()` to mask those fields, so that accidental string interpolation or debugger inspection does not leak them.
- **Release builds** persist only WARN and ERROR to disk; Timber d/i/v call sites are stripped by R8 (`-assumenosideeffects`). Do not lower the log level threshold.
- **Crash reporting** integrations must be reviewed for the same constraints before enabling.

# Part 8 — Threat model (mobile, focused)

This threat model covers only mobile-app security controls added or verified during production hardening. Protocol correctness, issuer assurance, verifier-side abuse, backend hardening and organisational operations are out of scope for this document.

- **Scenario A — holder bypass (dominant AV threat).** A user in possession of the device wants to enable an unauthorised party, typically an underage person, to present a Proof of Age attestation derived from the holder's local Proof of Age material. Tactics include lending the device unlocked, cloning the wallet to a second device, running a modified build, instrumenting with Frida/Xposed, tampering with system time, extracting local keys from a rooted device, enrolling the third party's biometric on the holder's device or sharing a Proof of Age presentation. Mitigations: Part 4 wallet-instance attestation, hardware-backed keys and user-presence binding are primary; Part 3 RASP raises bypass cost.
- **Scenario B — automation and scale abuse.** Operators run emulator farms, scripted devices or repackaged apps to perform AV checks at volume. Mitigations on the device: Part 3 RASP and Part 4 platform integrity. Bulk response remains primarily server-side and belongs to the wallet provider server guide.
- **Scenario C — network and redirect adversary.** An attacker performs MITM, debug-proxies release builds, manipulates trust anchors, injects user CAs or hijacks OID4VCI/OID4VP redirect URIs. Mitigations: Part 5 production endpoints, verified links, system browser components, strict TLS and optional pinning.
- **Scenario D — compromised installed base.** A released version has a critical vulnerability, a compromised build is observed in distribution or signing material is compromised. Mitigations: Part 6 force-update, kill-switch and signed configuration.
- **Scenario E — supply-chain compromise.** A third-party SDK, dependency, build plugin or CI path is compromised. Mitigations in this mobile-only document: Part 2 signed artefacts, lockfiles and SBOM; deeper build-pipeline governance is out of scope.

Out of scope here: verifier-side abuse and consent UX, issuer assurance, AV Profile conformance, server-side rate limiting, proximity/BLE/NFC presentation, backend incident response, legal compliance and state-level adversaries.

# Part 9 — Production security review checklist

Before store submission, the implementing party records the decision made for each baseline consideration:

- Production Android applicationId and iOS bundle id are configured under production developer accounts.
- Android targetSdkVersion satisfies the current Google Play requirement; minSdkVersion policy is documented as a device-coverage decision.
- Android Play App Signing/upload key and iOS Distribution signing are configured through controlled release infrastructure.
- Signed AAB and IPA/archive are tied to a tagged git revision, dependency lockfiles and, where used, SBOM.
- Release artefact inspection confirms no mock endpoints, debug network overrides or test trust anchors remain in production configuration.
- RASP or equivalent runtime protection has been evaluated, with the chosen posture documented.
- Android screen protection and iOS capture masking/abort policy have been evaluated for sensitive AV screens.
- Play Integrity and App Attest have been evaluated for production identifiers and server-side verification.
- Android Key Attestation policy documents StrongBox preference, TEE acceptance and unsupported-device behavior.
- iOS App Attest plus Secure Enclave key-binding policy is documented where used.
- Biometric, PIN and passcode policy is documented according to the desired AV assurance level and device coverage.
- Production issuer, wallet provider server and AV Trusted List sources are configured.
- Android App Links and iOS Universal Links are evaluated for redirect paths.
- Auth flows use Chrome Custom Tabs / ASWebAuthenticationSession where practical.
- Force-update and kill-switch policy is documented, including key rotation and failure behavior.
- Telemetry is privacy-notice-aligned and does not emit credential material or stable linkable presentation identifiers.
- Certificate pinning decision is recorded, including backup pins and rotation plan if pinning is adopted.
