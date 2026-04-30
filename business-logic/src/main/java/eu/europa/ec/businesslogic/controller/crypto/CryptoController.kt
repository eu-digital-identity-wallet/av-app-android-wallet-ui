/*
 * Copyright (c) 2025 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.businesslogic.controller.crypto

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

typealias GUID = String

interface CryptoController {

    /**
     * Generates a code verifier for Proof Key for Code Exchange (PKCE).
     *
     * This function generates a cryptographically random string that is used as the code
     * verifier in the PKCE flow. The code verifier is a high-entropy string that is
     * difficult to guess. It is used to protect against authorization code interception attacks.
     *
     * The generated code verifier is a Base64 URL-safe encoded string without padding or wrapping.
     *
     * @return A [String] representing the generated code verifier.
     */
    fun generateCodeVerifier(): String


    /**
     * Retrieves a [Cipher] instance configured for either encryption or decryption.
     *
     * This function initializes a [Cipher] object using the AES/GCM/NoPadding transformation.
     * The behavior of the cipher (encryption or decryption) is determined by the [encrypt] parameter.
     *
     * - If [encrypt] is `true`, the cipher is initialized in `Cipher.ENCRYPT_MODE`.
     * - If [encrypt] is `false`, the cipher is initialized in `Cipher.DECRYPT_MODE`, and the
     *   [ivBytes] parameter is required to provide the Initialization Vector (IV) for the
     *   GCMParameterSpec.
     *
     * The secret key used for cipher initialization is retrieved or generated via the
     * `keystoreController`.
     *
     * @param encrypt A [Boolean] indicating whether the cipher should be initialized for
     * encryption (`true`) or decryption (`false`). Defaults to `false`.
     * @param ivBytes An optional [ByteArray] containing the Initialization Vector. This is
     * required only when `encrypt` is `false` (i.e., for decryption).
     * @param userAuthenticationRequired A [Boolean] indicating if user authentication is
     * required for the cryptographic operation. Defaults to `true`.
     * @return A configured [Cipher] instance if initialization is successful, or `null` if an
     * exception occurs during initialization.
     */
    fun getCipher(
        encrypt: Boolean = false,
        ivBytes: ByteArray? = null,
        userAuthenticationRequired: Boolean = true
    ): Cipher?


    /**
     * Returns the [ByteArray] after the encryption/decryption from the given [Cipher].
     * [cipher] the cipher needed. This can be null but then an empty [ByteArray] is
     * returned.
     * [byteArray] that needed to be encrypted or decrypted (Depending always on [Cipher] provided.
     */
    fun encryptDecrypt(cipher: Cipher?, byteArray: ByteArray): ByteArray

    fun rotateKey(
        reEncryptData: (decryptCipher: (ByteArray) -> Cipher?, encryptCipher: () -> Cipher?) -> Boolean
    ): RotationResult

    fun getKeyVersion(): Int
}

class CryptoControllerImpl(
    private val keystoreController: KeystoreController
) : CryptoController {

    companion object {
        private const val AES_EXTERNAL_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_SIZE = 128
        const val MAX_GUID_LENGTH = 64
    }

    override fun generateCodeVerifier(): String {
        val code = ByteArray(32)
        SecureRandom().apply {
            nextBytes(code)
        }
        return Base64.encodeToString(code, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    override fun getCipher(
        encrypt: Boolean,
        ivBytes: ByteArray?,
        userAuthenticationRequired: Boolean
    ): Cipher? =
        try {
            Cipher.getInstance(AES_EXTERNAL_TRANSFORMATION).apply {
                if (encrypt) {
                    init(
                        Cipher.ENCRYPT_MODE,
                        keystoreController.retrieveOrGenerateSecretKey(userAuthenticationRequired)
                    )
                } else {
                    init(
                        Cipher.DECRYPT_MODE,
                        keystoreController.retrieveOrGenerateSecretKey(userAuthenticationRequired),
                        GCMParameterSpec(IV_SIZE, ivBytes)
                    )
                }
            }
        } catch (_: Exception) {
            null
        }


    override fun encryptDecrypt(cipher: Cipher?, byteArray: ByteArray): ByteArray {
        return cipher?.doFinal(byteArray) ?: ByteArray(0)
    }

    override fun rotateKey(
        reEncryptData: (decryptCipher: (ByteArray) -> Cipher?, encryptCipher: () -> Cipher?) -> Boolean
    ): RotationResult {
        val result = keystoreController.rotateKey(userAuthenticationRequired = true)
        if (result is RotationResult.Failure) return result

        val success = result as RotationResult.Success

        val decryptWithOld: (ByteArray) -> Cipher? = decryptWithOld@{ iv ->
            try {
                val oldKey = keystoreController.getSecretKeyByAlias(success.oldAlias)
                    ?: return@decryptWithOld null
                Cipher.getInstance(AES_EXTERNAL_TRANSFORMATION).apply {
                    init(Cipher.DECRYPT_MODE, oldKey, GCMParameterSpec(IV_SIZE, iv))
                }
            } catch (_: Exception) {
                null
            }
        }

        val encryptWithNew: () -> Cipher? = encryptWithNew@{
            try {
                val newKey = keystoreController.getSecretKeyByAlias(success.newAlias)
                    ?: return@encryptWithNew null
                Cipher.getInstance(AES_EXTERNAL_TRANSFORMATION).apply {
                    init(Cipher.ENCRYPT_MODE, newKey)
                }
            } catch (_: Exception) {
                null
            }
        }

        val reEncrypted = reEncryptData(decryptWithOld, encryptWithNew)
        if (reEncrypted) {
            keystoreController.cleanupOldKey()
        }

        return result
    }

    override fun getKeyVersion(): Int = keystoreController.getKeyVersion()
}
