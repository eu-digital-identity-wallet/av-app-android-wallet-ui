/*
 * Copyright (c) 2026 European Commission
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

package eu.europa.ec.authenticationlogic.storage

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplate
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.AesGcmParameters
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import eu.europa.ec.businesslogic.controller.log.LogController
import java.io.File
import java.nio.ByteBuffer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

class AuthMetadataStore(
    context: Context,
    private val logController: LogController,
) {
    private val context: Context = context.applicationContext

    companion object {
        private const val TAG = "AuthMetadataStore"
        const val META_KEY_ALIAS = "av_tink_master_v1"
    }

    private class InitializedState(
        val aead: Aead,
        val blobStore: DataStore<ByteArray>,
        val mirrorStore: DataStore<ByteArray>,
    )

    private val mutex = Mutex()

    @Volatile
    private var initializedState: InitializedState? = null

    private var cache: AuthMetadata? = null

    private suspend fun ensureInitialized(): InitializedState {
        initializedState?.let { return it }
        mutex.withLock {
            initializedState?.let { return it }
            val state = withContext(Dispatchers.IO) {
                AeadConfig.register()
                val parameters = AesGcmParameters.builder()
                    .setKeySizeBytes(32)
                    .setIvSizeBytes(12)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build()
                val keyTemplate = KeyTemplate.createFrom(parameters)
                val aead = AndroidKeysetManager.Builder()
                    .withSharedPref(context, "tink_auth_keyset", "tink_auth_keyset_prefs")
                    .withKeyTemplate(keyTemplate)
                    .withMasterKeyUri("android-keystore://${META_KEY_ALIAS}")
                    .build()
                    .keysetHandle
                    .getPrimitive(RegistryConfiguration.get(), Aead::class.java)
                val blobStore = DataStoreFactory.create(
                    corruptionHandler = ReplaceFileCorruptionHandler { ByteArray(0) },
                    serializer = TinkAeadSerializer(aead),
                    produceFile = { File(context.filesDir, "datastore/auth_metadata_blob.pb") }
                )
                val mirrorStore = DataStoreFactory.create(
                    corruptionHandler = ReplaceFileCorruptionHandler { ByteArray(0) },
                    serializer = TinkAeadSerializer(aead),
                    produceFile = { File(context.filesDir, "datastore/auth_write_counter.pb") }
                )
                InitializedState(aead, blobStore, mirrorStore)
            }
            initializedState = state
            return state
        }
    }

    suspend fun read(): AuthMetadata? {
        val state = ensureInitialized()
        return mutex.withLock {
            cache?.let { return@withLock it }

            val rawBlob = state.blobStore.data.first()
            if (rawBlob.isEmpty()) return@withLock null
            val meta = try {
                AuthMetadataCodec.decode(rawBlob)
            } catch (_: AuthMetadataCorruptException) {
                return@withLock null
            }
            val mirrorCounter = readMirrorCounter(state)
            if (meta.writeCounter != mirrorCounter) {
                logController.d(TAG) { "Rollback detected — wiping auth metadata" }
                wipeInternal(state)
                return@withLock null
            }
            cache = meta
            meta
        }
    }

    suspend fun write(meta: AuthMetadata) {
        val state = ensureInitialized()
        mutex.withLock {
            val next = meta.copy(writeCounter = meta.writeCounter + 1)
            val plaintext = AuthMetadataCodec.encode(next)
            state.blobStore.updateData { plaintext }
            writeMirrorCounter(state, next.writeCounter)
            cache = next
        }
    }

    suspend fun wipe() {
        val state = ensureInitialized()
        mutex.withLock {
            wipeInternal(state)
        }
    }

    private suspend fun wipeInternal(state: InitializedState) {
        state.blobStore.updateData { ByteArray(0) }
        state.mirrorStore.updateData { ByteArray(0) }
        cache = null
    }

    private suspend fun readMirrorCounter(state: InitializedState): Long {
        val raw = state.mirrorStore.data.first()
        if (raw.size < 8) return 0L
        return ByteBuffer.wrap(raw).long
    }

    private suspend fun writeMirrorCounter(state: InitializedState, counter: Long) {
        state.mirrorStore.updateData { ByteBuffer.allocate(8).putLong(counter).array() }
    }
}
