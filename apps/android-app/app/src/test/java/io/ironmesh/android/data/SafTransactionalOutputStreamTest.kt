package io.ironmesh.android.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream

class SafTransactionalOutputStreamTest {
    @Test
    fun destinationRemainsUnchangedUntilSuccessfulClose() {
        val store = FakeTransactionStore("old".toByteArray())
        val stream = transactionStream(store)

        stream.write("new".toByteArray())

        assertArrayEquals("old".toByteArray(), store.target)
        assertTrue(store.hasStaging)

        stream.close()

        assertArrayEquals("new".toByteArray(), store.target)
        assertFalse(store.hasStaging)
        assertFalse(store.hasBackup)
    }

    @Test
    fun writeFailurePreservesDestinationAndCleansStaging() {
        val store = FakeTransactionStore("old".toByteArray())
        val stream = transactionStream(store, failWrite = true)

        assertThrows(IOException::class.java) {
            stream.write("new".toByteArray())
        }
        assertThrows(IOException::class.java) {
            stream.close()
        }

        assertArrayEquals("old".toByteArray(), store.target)
        assertFalse(store.hasStaging)
        assertFalse(store.hasBackup)
    }

    @Test
    fun commitFailureRollsBackDestinationAndCleansTemporaryDocuments() {
        val store = FakeTransactionStore("old".toByteArray(), failPromotion = true)
        val stream = transactionStream(store)
        stream.write("new".toByteArray())

        assertThrows(IOException::class.java) {
            stream.close()
        }

        assertArrayEquals("old".toByteArray(), store.target)
        assertFalse(store.hasStaging)
        assertFalse(store.hasBackup)
    }

    @Test
    fun stagingCloseFailurePreservesDestinationAndCleansStaging() {
        val store = FakeTransactionStore("old".toByteArray())
        val stream = transactionStream(store, failClose = true)
        stream.write("new".toByteArray())

        assertThrows(IOException::class.java) {
            stream.close()
        }

        assertArrayEquals("old".toByteArray(), store.target)
        assertFalse(store.hasStaging)
        assertFalse(store.hasBackup)
    }

    @Test
    fun explicitAbortPreservesDestinationAndCleansStaging() {
        val store = FakeTransactionStore("old".toByteArray())
        val stream = transactionStream(store)
        stream.write("partial".toByteArray())

        stream.abort()

        assertArrayEquals("old".toByteArray(), store.target)
        assertFalse(store.hasStaging)
        assertFalse(store.hasBackup)
    }

    private fun transactionStream(
        store: FakeTransactionStore,
        failWrite: Boolean = false,
        failClose: Boolean = false,
    ): SafTransactionalOutputStream {
        return SafTransactionalOutputStream(
            delegate = FakeStagingOutputStream(store, failWrite, failClose),
            coordinator = SafWriteTransactionCoordinator(store),
        )
    }

    private class FakeTransactionStore(
        initialTarget: ByteArray?,
        private val failPromotion: Boolean = false,
    ) : SafWriteTransactionStore {
        override val targetExists = initialTarget != null
        var target: ByteArray? = initialTarget?.copyOf()
            private set
        var staging: ByteArray? = byteArrayOf()
        var backup: ByteArray? = null

        val hasStaging: Boolean
            get() = staging != null
        val hasBackup: Boolean
            get() = backup != null

        override fun prepareTargetForReplace() {
            backup = checkNotNull(target).copyOf()
        }

        override fun promoteStaging() {
            if (failPromotion) {
                target = "partial".toByteArray()
                throw IOException("injected promotion failure")
            }
            target = checkNotNull(staging).copyOf()
            staging = null
        }

        override fun restoreTarget() {
            target = if (targetExists) checkNotNull(backup).copyOf() else null
        }

        override fun deleteBackup() {
            backup = null
        }

        override fun deleteStaging() {
            staging = null
        }
    }

    private class FakeStagingOutputStream(
        private val store: FakeTransactionStore,
        private val failWrite: Boolean,
        private val failClose: Boolean,
    ) : OutputStream() {
        private val buffer = ByteArrayOutputStream()

        override fun write(value: Int) {
            if (failWrite) {
                throw IOException("injected write failure")
            }
            buffer.write(value)
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (failWrite) {
                throw IOException("injected write failure")
            }
            buffer.write(bytes, offset, length)
        }

        override fun close() {
            if (failClose) {
                throw IOException("injected close failure")
            }
            store.staging = buffer.toByteArray()
        }
    }
}
