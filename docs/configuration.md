# How to configure the application

## Table of contents

* [General configuration](#general-configuration)
* [DeepLink Schemas configuration](#deeplink-schemas-configuration)
* [Scoped Issuance Document Configuration](#scoped-issuance-document-configuration)
    * [Passport Scanning Issuer Configuration](#passport-scanning-issuer-configuration)
    * [Face Match Configuration](#face-match-configuration)
* [Batch Document Issuance Configuration](#batch-document-issuance-configuration)
* [Theme configuration](#theme-configuration)
* [Pin Storage configuration](#pin-storage-configuration)
* [Analytics configuration](#analytics-configuration)

## General configuration

All core network and trust settings are centralized in the `WalletCoreConfig` interface inside the
**core-logic** module:

```kotlin
interface WalletCoreConfig {
    // 1. Issuing API
    val vciConfig: List<OpenId4VciManager.Config>

    // 2. Wallet Provider Host
    val walletProviderHost: String

    // 3. Trusted certificates
    val config: EudiWalletConfig
}
```

You configure these properties **per flavor** by providing a `WalletCoreConfigImpl` for each build
variant:

* `core-logic/src/demo/config/WalletCoreConfigImpl.kt`
* `core-logic/src/dev/config/WalletCoreConfigImpl.kt`

Each flavor can use different issuer URLs, wallet provider hosts, and trust stores.

1. Issuing API

   The Issuing API is configured via the `vciConfig` property:

    ```kotlin
    override val vciConfig: List<OpenId4VciManager.Config>
        get() = listOf(
           OpenId4VciManager.Config.Builder()
          .withIssuerUrl(issuerUrl = "https://issuer.eudiw.dev")
          .withClientAuthenticationType(OpenId4VciManager.ClientAuthenticationType.AttestationBased)
          .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
          .withParUsage(OpenId4VciManager.Config.ParUsage.IF_SUPPORTED)
          .withDPoPUsage(OpenId4VciManager.Config.DPoPUsage.IfSupported())
          .build()
    )
    ```

   Adjust the configuration per flavor in the corresponding `WalletCoreConfigImpl`.

2. Wallet Provider Host

   The Wallet Provider Host is configured via the `walletProviderHost` property:

    ```kotlin
    override val walletProviderHost: String
        get() = "https://wallet-provider.eudiw.dev"
    ```

   Again, set a different value per flavor in the corresponding `WalletCoreConfigImpl`.

3. Trusted certificates

   Trusted certificates are configured via the `config` property:

    ```kotlin
    _config = EudiWalletConfig {
       configureReaderTrustStore(context, R.raw.eudi_pid_issuer_ut)
    }
    ```

The application's IACA certificates are located [here](https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui/tree/main/resources-logic/src/main/res/raw)

   Configure `EudiWalletConfig` per flavor inside the appropriate `WalletCoreConfigImpl`.

4. Preregistered Client Scheme

   If you plan to use the *ClientIdScheme.Preregistered* for OpenId4VP configuration, please add the
   following to the configuration files.

    ```kotlin
    const val OPENID4VP_VERIFIER_API_URI = "your_verifier_url"
    const val OPENID4VP_VERIFIER_LEGAL_NAME = "your_verifier_legal_name"
    const val OPENID4VP_VERIFIER_CLIENT_ID = "your_verifier_client_id"
    
    configureOpenId4Vp {
        withClientIdSchemes(
            listOf(
                ClientIdScheme.Preregistered(
                    listOf(
                        PreregisteredVerifier(
                            clientId = OPENID4VP_VERIFIER_CLIENT_ID,
                            verifierApi = OPENID4VP_VERIFIER_API_URI,
                            legalName = OPENID4VP_VERIFIER_LEGAL_NAME
                        )
                    )
                )
            )
        )
    }
    ```

## DeepLink Schemas configuration

According to the specifications, issuance, presentation require deep-linking for the same device
flows.

If you want to adjust any schema, you can alter the *AndroidLibraryConventionPlugin* inside the build-logic module.

```kotlin
val eudiOpenId4VpScheme = "eudi-openid4vp"
val eudiOpenid4VpHost = "*"

val mdocOpenId4VpScheme = "mdoc-openid4vp"
val mdocOpenid4VpHost = "*"

val openId4VpScheme = "openid4vp"
val openid4VpHost = "*"

val avspScheme = "avsp"
val avspHost = "*"

val credentialOfferScheme = "openid-credential-offer"
val credentialOfferHost = "*"
```

Let's assume you want to change the credential offer schema to custom-my-offer:// the *AndroidLibraryConventionPlugin* should look like this:

```kotlin
val eudiOpenId4VpScheme = "eudi-openid4vp"
val eudiOpenid4VpHost = "*"

val mdocOpenId4VpScheme = "mdoc-openid4vp"
val mdocOpenid4VpHost = "*"

val openId4VpScheme = "openid4vp"
val openid4VpHost = "*"

val avspScheme = "avsp"
val avspHost = "*"

val credentialOfferScheme = "custom-my-offer"
val credentialOfferHost = "*"

val credentialOfferHaipScheme = "haip-vci"
val credentialOfferHaipHost = "*"
```

In case of an additive change, e.g., adding an extra credential offer schema, you must adjust the following.

AndroidLibraryConventionPlugin:

```kotlin
val credentialOfferScheme = "openid-credential-offer"
val credentialOfferHost = "*"

val credentialOfferHaipScheme = "haip-vci"
val credentialOfferHaipHost = "*"

val myOwnCredentialOfferScheme = "custom-my-offer"
val myOwnCredentialOfferHost = "*"
```

```kotlin
// Manifest placeholders used for OpenId4VCI
manifestPlaceholders["credentialOfferHost"] = credentialOfferHost
manifestPlaceholders["credentialOfferScheme"] = credentialOfferScheme
manifestPlaceholders["credentialOfferHaipHost"] = credentialOfferHaipHost
manifestPlaceholders["credentialOfferHaipScheme"] = credentialOfferHaipScheme
manifestPlaceholders["myOwnCredentialOfferHost"] = myOwnCredentialOfferHost
manifestPlaceholders["myOwnCredentialOfferScheme"] = myOwnCredentialOfferScheme
```

```kotlin
addConfigField("CREDENTIAL_OFFER_SCHEME", credentialOfferScheme)
addConfigField("CREDENTIAL_OFFER_HAIP_SCHEME", credentialOfferHaipScheme)
addConfigField("MY_OWN_CREDENTIAL_OFFER_SCHEME", myOwnCredentialOfferScheme)
```

Android Manifest (inside assembly-logic module):

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />

    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />

    <data
        android:host="${credentialOfferHost}"
        android:scheme="${credentialOfferScheme}" />

</intent-filter>

<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    
    <data
        android:host="${credentialOfferHaipHost}"
        android:scheme="${credentialOfferHaipScheme}" />

</intent-filter>

<intent-filter>
    <action android:name="android.intent.action.VIEW" />

    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />

    <data
        android:host="${myOwnCredentialOfferHost}"
        android:scheme="${myOwnCredentialOfferScheme}" />

</intent-filter>
```

DeepLinkType (DeepLinkHelper Object inside ui-logic module):

```kotlin
enum class DeepLinkType(val schemas: List<String>, val host: String? = null) {

    OPENID4VP(
        schemas = listOf(
            BuildConfig.OPENID4VP_SCHEME,
            BuildConfig.EUDI_OPENID4VP_SCHEME,
            BuildConfig.MDOC_OPENID4VP_SCHEME, 
            BuildConfig.AVSP_SCHEME,
            BuildConfig.AV_SCHEME,
            BuildConfig.MY_OWN_CREDENTIAL_OFFER_SCHEME
        )
    ),
    CREDENTIAL_OFFER(
        schemas = listOf(
            BuildConfig.CREDENTIAL_OFFER_SCHEME,
            BuildConfig.CREDENTIAL_OFFER_HAIP_SCHEME,
            BuildConfig.MY_OWN_CREDENTIAL_OFFER_SCHEME
        )
    ),
    ISSUANCE(
        schemas = listOf(BuildConfig.ISSUE_AUTHORIZATION_SCHEME),
        host = BuildConfig.ISSUE_AUTHORIZATION_HOST
    ),
    DYNAMIC_PRESENTATION(
        emptyList()
    ),
    EXTERNAL(emptyList())
}
```

In the case of an additive change regarding OpenID4VP, you also need to update the *EudiWalletConfig* for each flavor inside the core-logic module.

```Kotlin
configureOpenId4Vp {
   withSchemes(
      listOf(
         BuildConfig.OPENID4VP_SCHEME,
         BuildConfig.EUDI_OPENID4VP_SCHEME,
         BuildConfig.MDOC_OPENID4VP_SCHEME,
         BuildConfig.AVSP_SCHEME,
         BuildConfig.YOUR_OWN_OPENID4VP_SCHEME
      )
   )
}
```

## Scoped Issuance Document Configuration

The credential configuration is derived directly from the issuer's metadata. The issuer URL is
configured per flavor via the *vciConfig* property inside the core-logic module at
src/demo/config/WalletCoreConfigImpl and src/dev/config/WalletCoreConfigImpl.
If you want to add or adjust the displayed scoped documents, you must modify the issuer's metadata, and the wallet will automatically resolve your changes.

### Passport Scanning Issuer Configuration

The application supports multiple issuers for different credential types. By convention, if the
`vciConfig` list contains multiple issuers, the **second issuer (index 1)** is used for passport
scanning flows. This allows age verification documents to be issued through a dedicated endpoint
after passport scanning.

The configuration is flavor-specific and defined in src/demo/config/WalletCoreConfigImpl and
src/dev/config/WalletCoreConfigImpl.

**Dev Flavor Configuration:**

```Kotlin
override val vciConfig: List<OpenId4VciManager.Config>
    get() = listOf(
        // First issuer - for regular credentials
        OpenId4VciManager.Config.Builder()
            .withIssuerUrl(issuerUrl = "https://dev.issuer.eudiw.dev")
            .withClientId(clientId = "wallet-dev")
            .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
            .withParUsage(OpenId4VciManager.Config.ParUsage.NEVER)
            .withUseDPoPIfSupported(false)
            .build(),
        // Second issuer - for passport scanning credentials
        OpenId4VciManager.Config.Builder()
            .withIssuerUrl(issuerUrl = "https://issuer.dev.ageverification.dev")
            .withClientId(clientId = "wallet-dev")
            .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
            .withParUsage(OpenId4VciManager.Config.ParUsage.NEVER)
            .withUseDPoPIfSupported(false)
            .build()
    )
```

**Demo Flavor Configuration:**

```Kotlin
override val vciConfig: List<OpenId4VciManager.Config>
    get() = listOf(
        // First issuer - for regular credentials
        OpenId4VciManager.Config.Builder()
            .withIssuerUrl(issuerUrl = "https://issuer.ageverification.dev")
            .withClientAuthenticationType(
                OpenId4VciManager.ClientAuthenticationType.None(
                    clientId = "wallet-dev"
                )
            )
            .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
            .withParUsage(OpenId4VciManager.Config.ParUsage.NEVER)
            .withDPoPUsage(OpenId4VciManager.Config.DPoPUsage.Disabled)
            .build(),
        // Second issuer - for passport scanning credentials
        OpenId4VciManager.Config.Builder()
            .withIssuerUrl(issuerUrl = "https://issuer.dev.ageverification.dev")
            .withClientAuthenticationType(
                OpenId4VciManager.ClientAuthenticationType.None(
                    clientId = "wallet-dev"
                )
            )
            .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
            .withParUsage(OpenId4VciManager.Config.ParUsage.NEVER)
            .withDPoPUsage(OpenId4VciManager.Config.DPoPUsage.Disabled)
            .build()
    )
```

The passport scanning issuer configuration is optional. If the `vciConfig` list contains only one
issuer, passport scanning issuance will not be available.

**Important Note:** PAR (Pushed Authorization Request) and DPoP (Demonstration of
Proof-of-Possession)
are not supported in the AV profile. Both features must be disabled by setting:

- `parUsage = OpenId4VciManager.Config.ParUsage.NEVER`
- `useDPoPIfSupported = false`

### Face Match Configuration

The application uses AI models for face liveness detection and face matching during passport
verification flows. These models are configured via the `faceMatchConfig` property in the
*WalletCoreConfig* interface.

The configuration is flavor-specific and defined in src/demo/config/WalletCoreConfigImpl and
src/dev/config/WalletCoreConfigImpl.

**Configuration Structure:**

```Kotlin
data class FaceMatchConfig(
    val faceDetectorModel: String,        // Model for detecting faces in images
    val embeddingExtractorModel: String,  // Model for extracting face embeddings
    val livenessModel0: String,           // First liveness detection model
    val livenessModel1: String,           // Second liveness detection model
    val livenessThreshold: Double,        // Threshold for liveness detection (0.0-1.0)
    val matchingThreshold: Double,        // Threshold for face matching (0.0-1.0)
)
```

**Example Configuration:**

```Kotlin
override val faceMatchConfig: FaceMatchConfig = FaceMatchConfig(
    faceDetectorModel = "https://github.com/your-org/models/releases/download/v1.0/face_detector.tflite",
    embeddingExtractorModel = "https://github.com/your-org/models/releases/download/v1.0/embedding_extractor.tflite",
    livenessModel0 = "https://github.com/your-org/models/releases/download/v1.0/liveness_model_0.tflite",
    livenessModel1 = "https://github.com/your-org/models/releases/download/v1.0/liveness_model_1.tflite",
    livenessThreshold = 0.85,  // 85% confidence for liveness
    matchingThreshold = 0.75,  // 75% confidence for face matching
)
```

**Model Path Options:**

The model paths can be specified as:

- Remote URLs (HTTP/HTTPS) for downloading models at runtime
- Local asset paths (e.g., `file:///android_asset/models/face_detector.tflite`)
- Local file paths on device storage

**Threshold Configuration:**

- `livenessThreshold`: Controls the sensitivity of liveness detection. Higher values (e.g., 0.9) are
  more strict and may reject more legitimate faces, while lower values (e.g., 0.7) are more lenient
  but may accept more spoofing attempts.
- `matchingThreshold`: Controls the sensitivity of face matching between the passport photo and
  selfie. Higher values require a closer match, while lower values are more forgiving of lighting
  and angle differences.

> **⚠️ SECURITY WARNING:**
>
> The models referenced in the default configuration are currently hosted on GitHub Releases for
> development and testing purposes only. **This is NOT recommended for production environments.**

## Batch Document Issuance Configuration

The app is configured to use batch document issuance by default, requesting a batch of credentials
at once and handling them according to a defined policy.

You can configure the following aspects of batch document issuance in DocumentIssuanceRule:

1. number of credentials (formerly batch size) - The number of credentials to be issued for the document at once
2. Credential policy - whether to use each credential once or rotate through them

These settings are configured in your flavor's implementation of `WalletCoreConfigImpl`. For
example, in the demo flavor:

```Kotlin
internal class WalletCoreConfigImpl(
    private val context: Context
) : WalletCoreConfig {
    
    // ...other configuration...

    val documentIssuanceConfig: DocumentIssuanceConfig
        get() = DocumentIssuanceConfig(
            defaultRule = DocumentIssuanceRule(
                policy = CredentialPolicy.OneTimeUse,
                numberOfCredentials = 30
            ),
            documentSpecificRules = mapOf()
        )
}
```

Note that the batch size will be limited by the issuer's metadata configuration, so you may not be
able to request a batch larger than what the issuer allows. To understand the issuer's
configuration, you can check the issuer's metadata endpoint, which is usually available at
`https://<issuer-url>/.well-known/openid-configuration`. Specifically, look for the
`credential_batch_size` field in the metadata response.

Note that the batch size will be limited by the issuer's metadata configuration, so you may not be
able to request a batch larger than what the issuer allows. to understand the issuer's
configuration, you can check the issuer's metadata endpoint, which is usually available at
`https://<issuer-url>/.well-known/openid-configuration`. specifically, look for
the `credential_batch_size` field in the metadata response.

## Theme configuration

The application allows the configuration of:

1. Colors
2. Images
3. Shape
4. Fonts
5. Dimension

Via *ThemeManager.Builder()*.

## Pin Storage configuration

The application allows the configuration of the PIN storage. You can configure the following:

1. Where the pin will be stored
2. From where the pin will be retrieved
3. Pin matching and validity

Via the *StorageConfig* inside the authentication-logic module.

```kotlin
interface StorageConfig {
    val pinStorageProvider: PinStorageProvider
    val biometryStorageProvider: BiometryStorageProvider
}
```

You can provide your storage implementation by implementing the *PinStorageProvider* interface and then setting it as the default to the *StorageConfigImpl* pinStorageProvider variable.
The project utilizes Koin for Dependency Injection (DI), thus requiring adjustment of the *LogicAuthenticationModule* graph to provide the configuration.

The *PinStorageProvider* interface:

```kotlin
interface PinStorageProvider {
    fun hasPin(): Boolean
    fun setPin(pin: String)
    fun isPinValid(pin: String): Boolean

    fun getFailedAttempts(): Int
    fun incrementFailedAttempts(): Int
    fun resetFailedAttempts()

    fun setLockoutForDuration(durationMillis: Long)
    fun getLockoutUntil(): Long
    fun isCurrentlyLockedOut(): Boolean
}
```

Implementation Example:

```kotlin
class PrefsPinStorageProvider(
    private val prefsController: PrefsController,
    private val clock: ElapsedRealtimeClock,
    private val bootIdProvider: BootIdProvider,
) : PinStorageProvider {

    override fun hasPin(): Boolean {
        return prefsController.getString(KEY_PIN_HASH, "").isNotEmpty()
    }

    override fun setPin(pin: String) {
        val salt = generateSalt()
        val hash = hashPin(pin, salt)
        prefsController.setString(KEY_PIN_HASH, hash.toHexString())
        prefsController.setString(KEY_PIN_SALT, salt.toHexString())
        resetFailedAttempts()
    }

    override fun isPinValid(pin: String): Boolean {
        val storedHashHex = prefsController.getString(KEY_PIN_HASH, "")
        val saltHex = prefsController.getString(KEY_PIN_SALT, "")
        if (storedHashHex.isEmpty() || saltHex.isEmpty()) return false

        val salt = saltHex.hexToByteArray()
        val computedHash = hashPin(pin, salt)
        return MessageDigest.isEqual(computedHash, storedHashHex.hexToByteArray())
    }
}
```

The default implementation uses PBKDF2 with HMAC-SHA256 for PIN hashing with a random salt, constant-time comparison to prevent timing attacks, and reboot-aware lockout via `ElapsedRealtimeClock` and `BootIdProvider`.

Config Example:

```kotlin
class StorageConfigImpl(
    private val pinImpl: PinStorageProvider,
    private val biometryImpl: BiometryStorageProvider
) : StorageConfig {
    override val pinStorageProvider: PinStorageProvider
        get() = pinImpl
    override val biometryStorageProvider: BiometryStorageProvider
        get() = biometryImpl
}
```

Config Construction via Koin DI Example:

```kotlin
@Single
fun provideStorageConfig(
    prefsController: PrefsController,
    clock: ElapsedRealtimeClock,
    bootIdProvider: BootIdProvider,
): StorageConfig = StorageConfigImpl(
    pinImpl = PrefsPinStorageProvider(prefsController, clock, bootIdProvider),
    biometryImpl = PrefsBiometryStorageProvider(prefsController)
)
```

## Analytics configuration

The application allows the configuration of multiple analytics providers. You can configure the following:

1. Initializing the provider (e.g., Firebase, Appcenter, etc)
2. Screen logging
3. Event logging

Via the *AnalyticsConfig* inside the analytics-logic module.

```kotlin
interface AnalyticsConfig {
    val analyticsProviders: Map<String, AnalyticsProvider>
        get() = emptyMap()
}
```

You can provide your implementation by implementing the *AnalyticsProvider* interface and then adding it to your *AnalyticsConfigImpl* analyticsProviders variable.
You will also need the provider's token/key, thus requiring a Map<String, AnalyticsProvider> configuration.
The project utilizes Koin for Dependency Injection (DI), thus requiring adjustment of the *LogicAnalyticsModule* graph to provide the configuration.

Implementation Example:

```kotlin
object AppCenterAnalyticsProvider : AnalyticsProvider {
    override fun initialize(context: Application, key: String) {
        AppCenter.start(
            context,
            key,
            Analytics::class.java
        )
    }

    override fun logScreen(name: String, arguments: Map<String, String>) {
        logEvent(name, arguments)
    }

    override fun logEvent(event: String, arguments: Map<String, String>) {
        if (Analytics.isEnabled().get()) {
            Analytics.trackEvent(event, arguments)
        }
    }
}
```

Config Example:

```kotlin
class AnalyticsConfigImpl : AnalyticsConfig {
    override val analyticsProviders: Map<String, AnalyticsProvider>
        get() = mapOf("YOUR_OWN_KEY" to AppCenterAnalyticsProvider)
}
```

Config Construction via Koin DI Example:

```kotlin
@Single
fun provideAnalyticsConfig(): AnalyticsConfig = AnalyticsConfigImpl()
```
