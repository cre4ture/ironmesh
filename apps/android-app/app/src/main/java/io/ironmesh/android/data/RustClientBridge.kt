package io.ironmesh.android.data

import java.io.InputStream
import java.io.OutputStream

object RustClientBridge {
    init {
        System.loadLibrary("android_app")
    }

    @JvmStatic
    external fun enrollWithBootstrap(
        bootstrapJson: String,
        deviceId: String?,
        label: String?,
    ): String

    @JvmStatic
    external fun putObject(
        connectionInput: String,
        key: String,
        payload: ByteArray,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ): Int

    @JvmStatic
    external fun getObject(
        connectionInput: String,
        key: String,
        snapshot: String?,
        version: String?,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ): ByteArray

    @JvmStatic
    external fun storeIndex(
        connectionInput: String,
        prefix: String?,
        depth: Int,
        snapshot: String?,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ): String

    @JvmStatic
    external fun streamPutObject(
        connectionInput: String,
        key: String,
        input: InputStream,
        sizeBytes: Long,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ): Int

    @JvmStatic
    external fun deleteObject(
        connectionInput: String,
        key: String,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ): Int

    @JvmStatic
    external fun streamObjectTo(
        connectionInput: String,
        key: String,
        output: OutputStream,
        snapshot: String?,
        version: String?,
        serverCaPem: String?,
        clientIdentityJson: String?,
    )

    @JvmStatic
    external fun streamRelativeUrlTo(
        connectionInput: String,
        relativeUrl: String,
        output: OutputStream,
        serverCaPem: String?,
        clientIdentityJson: String?,
    )

    @JvmStatic
    external fun startWebUi(
        connectionInput: String,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ): String

    @JvmStatic
    external fun runFolderSyncOnce(
        connectionInput: String,
        localFolder: String,
        localFolderTreeUri: String?,
        prefix: String?,
        depth: Int,
        serverCaPem: String?,
        clientIdentityJson: String?,
    )

    @JvmStatic
    external fun startContinuousFolderSync(
        profileId: String,
        label: String,
        connectionInput: String,
        localFolder: String,
        localFolderTreeUri: String?,
        prefix: String?,
        depth: Int,
        serverCaPem: String?,
        clientIdentityJson: String?,
    )

    @JvmStatic
    external fun stopContinuousFolderSync(profileId: String)

    @JvmStatic
    external fun stopAllContinuousFolderSync()

    @JvmStatic
    external fun getContinuousFolderSyncStatus(): String

    @JvmStatic
    external fun getFolderSyncModificationHistory(
        connectionInput: String,
        localFolder: String,
        localFolderTreeUri: String?,
        prefix: String?,
        limit: Int,
        beforeId: Long,
        operation: String?,
    ): String

    @JvmStatic
    external fun hasContinuousFolderSyncActive(): Boolean
}
