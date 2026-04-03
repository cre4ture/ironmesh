package io.ironmesh.android.saf

import io.ironmesh.android.api.StoreIndexEntry
import io.ironmesh.android.data.IronmeshRepository
import java.io.FileNotFoundException
import java.io.OutputStream

internal interface IronmeshThumbnailStreamDataSource {
    suspend fun streamRelativeUrlTo(
        connectionInput: String,
        relativeUrl: String,
        output: OutputStream,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    )
}

internal class IronmeshRepositoryThumbnailDataSource(
    private val repository: IronmeshRepository,
) : IronmeshThumbnailStreamDataSource {
    override suspend fun streamRelativeUrlTo(
        connectionInput: String,
        relativeUrl: String,
        output: OutputStream,
        serverCaPem: String?,
        clientIdentityJson: String?,
    ) {
        repository.streamRelativeUrlTo(
            connectionInput,
            relativeUrl,
            output,
            serverCaPem,
            clientIdentityJson,
        )
    }
}

internal class IronmeshThumbnailStreamer(
    private val dataSource: IronmeshThumbnailStreamDataSource,
) {
    suspend fun streamTo(
        connectionInput: String,
        entry: StoreIndexEntry,
        output: OutputStream,
        serverCaPem: String? = null,
        clientIdentityJson: String? = null,
    ) {
        val thumbnailUrl = entry.media?.thumbnail?.url?.trim()?.takeIf { it.isNotEmpty() }
            ?: throw FileNotFoundException("thumbnail not available")
        dataSource.streamRelativeUrlTo(
            connectionInput,
            thumbnailUrl,
            output,
            serverCaPem,
            clientIdentityJson,
        )
    }
}
