package io.ironmesh.android.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class DeviceIdentityCiphertext(
    val iv: ByteArray,
    val ciphertext: ByteArray,
)

interface DeviceIdentityCrypto {
    fun encrypt(plaintext: ByteArray): DeviceIdentityCiphertext

    fun decrypt(payload: DeviceIdentityCiphertext): ByteArray
}

class AndroidKeyStoreDeviceIdentityCrypto(
    private val keyAlias: String = DEFAULT_KEY_ALIAS,
) : DeviceIdentityCrypto {
    private val lock = Any()

    override fun encrypt(plaintext: ByteArray): DeviceIdentityCiphertext = synchronized(lock) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        DeviceIdentityCiphertext(
            iv = cipher.iv,
            ciphertext = cipher.doFinal(plaintext),
        )
    }

    override fun decrypt(payload: DeviceIdentityCiphertext): ByteArray = synchronized(lock) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            getOrCreateKey(),
            GCMParameterSpec(GCM_TAG_LENGTH_BITS, payload.iv),
        )
        cipher.doFinal(payload.ciphertext)
    }

    fun deleteKey() = synchronized(lock) {
        keyStore().deleteEntry(keyAlias)
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = keyStore()
        (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        return generateKey(KEY_SIZE_BITS)
    }

    private fun generateKey(keySize: Int): SecretKey {
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEY_STORE,
        )
        val parameters = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(keySize)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .build()
        generator.init(parameters)
        return generator.generateKey()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply {
        load(null)
    }

    companion object {
        const val DEFAULT_KEY_ALIAS = "ironmesh.device-identity.aes-gcm.v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_SIZE_BITS = 256
        private const val GCM_TAG_LENGTH_BITS = 128
    }
}

class AtomicFileDeviceIdentitySecretStore(
    baseFile: File,
    private val crypto: DeviceIdentityCrypto = AndroidKeyStoreDeviceIdentityCrypto(),
) : DeviceIdentitySecretStore {
    private val atomicFile = AtomicFile(baseFile)
    private val secretAdapter = moshi.adapter(DeviceIdentitySecret::class.java)
    private val envelopeAdapter = moshi.adapter(DeviceIdentityEnvelope::class.java)

    override fun load(): DeviceIdentitySecret? {
        if (!atomicFile.baseFile.exists()) {
            return null
        }

        return try {
            val envelopeJson = atomicFile.readFully().toString(Charsets.UTF_8)
            val envelope = envelopeAdapter.fromJson(envelopeJson)
                ?: throw IllegalStateException("encrypted identity envelope is empty")
            check(envelope.version == ENVELOPE_VERSION) {
                "unsupported encrypted identity envelope version ${envelope.version}"
            }
            val plaintext = crypto.decrypt(
                DeviceIdentityCiphertext(
                    iv = Base64.getDecoder().decode(envelope.iv),
                    ciphertext = Base64.getDecoder().decode(envelope.ciphertext),
                ),
            )
            try {
                secretAdapter.fromJson(plaintext.toString(Charsets.UTF_8))
                    ?: throw IllegalStateException("decrypted device identity is empty")
            } finally {
                plaintext.fill(0)
            }
        } catch (error: Exception) {
            throw DeviceIdentityRecoveryRequiredException(error)
        }
    }

    override fun save(secret: DeviceIdentitySecret) {
        val parent = atomicFile.baseFile.parentFile
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw DeviceIdentityStorageException(
                "Could not create protected device identity storage. Enrollment was not changed.",
            )
        }

        val plaintext = secretAdapter.toJson(secret).toByteArray(Charsets.UTF_8)
        var output: FileOutputStream? = null
        try {
            val encrypted = crypto.encrypt(plaintext)
            val envelope = DeviceIdentityEnvelope(
                version = ENVELOPE_VERSION,
                iv = Base64.getEncoder().encodeToString(encrypted.iv),
                ciphertext = Base64.getEncoder().encodeToString(encrypted.ciphertext),
            )
            output = atomicFile.startWrite()
            output.write(envelopeAdapter.toJson(envelope).toByteArray(Charsets.UTF_8))
            atomicFile.finishWrite(output)
        } catch (error: Exception) {
            output?.let(atomicFile::failWrite)
            throw DeviceIdentityStorageException(
                "Could not protect the device identity. Enrollment was not changed.",
                error,
            )
        } finally {
            plaintext.fill(0)
        }
    }

    override fun clear() {
        try {
            atomicFile.delete()
            val baseFile = atomicFile.baseFile
            check(
                !baseFile.exists() &&
                    !File(baseFile.path + ".bak").exists() &&
                    !File(baseFile.path + ".new").exists(),
            ) {
                "encrypted identity file still exists"
            }
        } catch (error: Exception) {
            throw DeviceIdentityStorageException(
                "Could not clear the protected device identity. Enrollment was not changed.",
                error,
            )
        }
    }

    private data class DeviceIdentityEnvelope(
        val version: Int,
        val iv: String,
        val ciphertext: String,
    )

    companion object {
        const val DEFAULT_FILE_NAME = "device_identity_v1.enc"
        private const val ENVELOPE_VERSION = 1

        private val moshi: Moshi = Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()
    }
}
