package io.ironmesh.servernode.android

import android.app.Application
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class MainUiState(
    val status: ServerNodeStatus = ServerNodeStatus(),
    val candidateOrigins: List<String> = emptyList(),
)

class MainViewModel(application: Application) : AndroidViewModel(application) {
    var uiState = mutableStateOf(
        MainUiState(
            candidateOrigins = detectCandidateOrigins(RustServerNodeBridge.DEFAULT_BIND_PORT),
        ),
    )
        private set

    init {
        viewModelScope.launch {
            while (isActive) {
                refresh()
                delay(2_000)
            }
        }
    }

    fun refresh() {
        viewModelScope.launch(Dispatchers.IO) {
            val status = runCatching { RustServerNodeBridge.status() }
                .getOrElse { error ->
                    ServerNodeStatus(
                        state = "error",
                        message = error.message ?: "Failed to load server-node status",
                        lastError = error.message,
                    )
                }
            val origins = detectCandidateOrigins(RustServerNodeBridge.DEFAULT_BIND_PORT)
            withContext(Dispatchers.Main) {
                uiState.value = MainUiState(
                    status = status,
                    candidateOrigins = origins,
                )
            }
        }
    }
}
