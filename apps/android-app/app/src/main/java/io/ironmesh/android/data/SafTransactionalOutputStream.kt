package io.ironmesh.android.data

import java.io.IOException
import java.io.OutputStream

internal interface SafWriteTransactionStore {
    val targetExists: Boolean

    fun prepareTargetForReplace()

    fun promoteStaging()

    fun restoreTarget()

    fun deleteBackup()

    fun deleteStaging()
}

internal class SafWriteTransactionCoordinator(
    private val store: SafWriteTransactionStore,
) {
    private var finalized = false

    @Synchronized
    fun commit() {
        check(!finalized) { "SAF write transaction is already finalized" }
        try {
            if (store.targetExists) {
                store.prepareTargetForReplace()
            }
            store.promoteStaging()
        } catch (commitError: Throwable) {
            rollbackAfterCommitFailure(commitError)
            finalized = true
            throw commitError
        }

        finalized = true
        store.deleteBackup()
    }

    @Synchronized
    fun abort() {
        if (finalized) {
            return
        }
        finalized = true
        store.deleteStaging()
    }

    private fun rollbackAfterCommitFailure(commitError: Throwable) {
        var restored = false
        try {
            store.restoreTarget()
            restored = true
        } catch (rollbackError: Throwable) {
            commitError.addSuppressed(rollbackError)
        }

        if (restored) {
            try {
                store.deleteBackup()
            } catch (cleanupError: Throwable) {
                commitError.addSuppressed(cleanupError)
            }
        }

        try {
            store.deleteStaging()
        } catch (cleanupError: Throwable) {
            commitError.addSuppressed(cleanupError)
        }
    }
}

/**
 * Buffers a SAF write in a sibling document and only asks the transaction store to replace the
 * destination after the underlying stream has closed successfully.
 *
 * [abort] is public and has a stable JVM name because the Rust/JNI writer calls it when a download
 * fails before completion. A regular [close] means commit.
 */
class SafTransactionalOutputStream internal constructor(
    private val delegate: OutputStream,
    private val coordinator: SafWriteTransactionCoordinator,
    private val onFinalized: () -> Unit = {},
) : OutputStream() {
    private var failedWrite: Throwable? = null
    private var finalized = false

    override fun write(value: Int) {
        recordWriteFailure {
            delegate.write(value)
        }
    }

    override fun write(buffer: ByteArray) {
        recordWriteFailure {
            delegate.write(buffer)
        }
    }

    override fun write(buffer: ByteArray, offset: Int, length: Int) {
        recordWriteFailure {
            delegate.write(buffer, offset, length)
        }
    }

    override fun flush() {
        recordWriteFailure {
            delegate.flush()
        }
    }

    @Synchronized
    override fun close() {
        if (finalized) {
            return
        }
        finalized = true

        val writeError = failedWrite
        val closeError = closeDelegate()
        if (writeError != null || closeError != null) {
            val primaryError = writeError ?: closeError!!
            if (writeError != null && closeError != null && closeError !== writeError) {
                primaryError.addSuppressed(closeError)
            }
            abortTransaction(primaryError)
            onFinalizedSafely(primaryError)
            throw primaryError.asIOException("Failed to finish SAF staging write")
        }

        try {
            coordinator.commit()
        } catch (commitError: Throwable) {
            onFinalizedSafely(commitError)
            throw commitError.asIOException("Failed to commit SAF staging write")
        }
        onFinalized()
    }

    /** Discards the staged document without replacing the destination. */
    @Synchronized
    fun abort() {
        if (finalized) {
            return
        }
        finalized = true

        val closeError = closeDelegate()
        val primaryError = closeError
        if (primaryError == null) {
            try {
                coordinator.abort()
                onFinalized()
                return
            } catch (abortError: Throwable) {
                onFinalizedSafely(abortError)
                throw abortError.asIOException("Failed to abort SAF staging write")
            }
        }

        abortTransaction(primaryError)
        onFinalizedSafely(primaryError)
        throw primaryError.asIOException("Failed to close aborted SAF staging write")
    }

    private inline fun recordWriteFailure(block: () -> Unit) {
        check(!finalized) { "SAF output stream is already finalized" }
        try {
            block()
        } catch (error: Throwable) {
            if (failedWrite == null) {
                failedWrite = error
            }
            throw error
        }
    }

    private fun closeDelegate(): Throwable? {
        return try {
            delegate.close()
            null
        } catch (error: Throwable) {
            error
        }
    }

    private fun abortTransaction(primaryError: Throwable) {
        try {
            coordinator.abort()
        } catch (abortError: Throwable) {
            primaryError.addSuppressed(abortError)
        }
    }

    private fun onFinalizedSafely(primaryError: Throwable) {
        try {
            onFinalized()
        } catch (callbackError: Throwable) {
            primaryError.addSuppressed(callbackError)
        }
    }
}

private fun Throwable.asIOException(message: String): IOException {
    return if (this is IOException) {
        this
    } else {
        IOException(message, this)
    }
}
