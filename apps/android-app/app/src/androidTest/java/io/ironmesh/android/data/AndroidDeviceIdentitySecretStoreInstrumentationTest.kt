package io.ironmesh.android.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AndroidDeviceIdentitySecretStoreInstrumentationTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val keyAlias = "ironmesh.test.${UUID.randomUUID()}"
    private val crypto = AndroidKeyStoreDeviceIdentityCrypto(keyAlias)
    private val encryptedFile = File(context.noBackupFilesDir, "$keyAlias.enc")
    private val store = AtomicFileDeviceIdentitySecretStore(encryptedFile, crypto)

    @After
    fun cleanUp() {
        runCatching { store.clear() }
        runCatching { crypto.deleteKey() }
    }

    @Test
    fun androidKeyStoreAesGcmRoundTripDoesNotWritePlaintext() {
        val secret = testSecret()

        store.save(secret)

        assertEquals(secret, store.load())
        val envelope = encryptedFile.readText()
        assertTrue(envelope.contains("\"version\":1"))
        assertFalse(envelope.contains(secret.privateKeyPem))
        assertFalse(envelope.contains(secret.credentialPem.orEmpty()))
        assertFalse(envelope.contains(secret.rendezvousClientIdentityPem.orEmpty()))
    }

    @Test
    fun deletedKeystoreKeyMakesEncryptedIdentityRecoverableByReEnrollment() {
        store.save(testSecret())
        crypto.deleteKey()

        val error = assertThrows(DeviceIdentityRecoveryRequiredException::class.java) {
            store.load()
        }

        assertFalse(error.message.isNullOrBlank())
    }

    private fun testSecret(): DeviceIdentitySecret =
        DeviceIdentitySecret(
            clusterId = "cluster-1",
            deviceId = "device-1",
            label = "Phone",
            publicKeyPem = "public-key",
            privateKeyPem = "private-key-secret",
            credentialPem = "credential-secret",
            rendezvousClientIdentityPem = "rendezvous-secret",
        )
}
