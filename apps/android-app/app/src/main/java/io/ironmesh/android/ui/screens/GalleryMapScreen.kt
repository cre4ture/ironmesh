package io.ironmesh.android.ui.screens

import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.ironmesh.android.ui.MainUiState
import io.ironmesh.android.ui.components.IronmeshEmbeddedWebUi

@Composable
fun GalleryMapScreen(
    state: MainUiState,
    onStartGalleryMap: () -> Unit,
) {
    val galleryMapUrl = galleryMapWebUiUrl(state.webUiUrl)

    if (galleryMapUrl != null) {
        IronmeshEmbeddedWebUi(
            url = galleryMapUrl,
            modifier = Modifier.fillMaxSize(),
        )
        return
    }

    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "Gallery Map",
                    style = MaterialTheme.typography.headlineSmall,
                )
                Text(
                    text = if (state.loading) {
                        "Starting the embedded gallery map."
                    } else {
                        "Start the embedded Web UI to open the shared gallery map directly inside the app."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (state.status.isNotBlank()) {
                    Text(
                        text = state.status,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (state.loading) {
                    CircularProgressIndicator()
                } else {
                    Button(onClick = onStartGalleryMap) {
                        Text("Open gallery map")
                    }
                }
            }
        }
    }
}

private fun galleryMapWebUiUrl(baseUrl: String): String? {
    if (baseUrl.isBlank()) {
        return null
    }

    return Uri.parse(baseUrl)
        .buildUpon()
        .appendQueryParameter("embedded", "gallery_map")
        .build()
        .toString()
}
