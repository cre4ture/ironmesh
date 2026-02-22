package io.ironmesh.android.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.ironmesh.android.data.IronmeshRepository
import kotlinx.coroutines.launch

data class MainUiState(
    val baseUrl: String = "http://10.0.2.2:18080",
    val key: String = "demo-key",
    val payload: String = "hello from android",
    val status: String = "Ready",
    val replicationSummary: String = "",
    val objectBody: String = "",
    val loading: Boolean = false,
)

class MainViewModel(
    private val repository: IronmeshRepository = IronmeshRepository(),
) : ViewModel() {

    var uiState = androidx.compose.runtime.mutableStateOf(MainUiState())
        private set

    fun updateBaseUrl(value: String) {
        uiState.value = uiState.value.copy(baseUrl = value)
    }

    fun updateKey(value: String) {
        uiState.value = uiState.value.copy(key = value)
    }

    fun updatePayload(value: String) {
        uiState.value = uiState.value.copy(payload = value)
    }

    fun checkHealth() {
        execute("Checking health...") {
            val health = repository.health(uiState.value.baseUrl)
            "Health: online=${health.online} node=${health.node_id ?: "n/a"}"
        }
    }

    fun loadReplicationPlan() {
        execute("Loading replication plan...") {
            val plan = repository.replicationPlan(uiState.value.baseUrl)
            val keys = plan.items.take(5).joinToString { it.key }
            val summary = "under=${plan.under_replicated}, over=${plan.over_replicated}, items=${plan.items.size}" +
                if (keys.isNotBlank()) "\nSample: $keys" else ""
            uiState.value = uiState.value.copy(replicationSummary = summary)
            "Plan loaded"
        }
    }

    fun putObject() {
        execute("Uploading object...") {
            val statusCode = repository.putObject(
                uiState.value.baseUrl,
                uiState.value.key,
                uiState.value.payload,
            )
            "PUT ok: HTTP $statusCode"
        }
    }

    fun getObject() {
        execute("Downloading object...") {
            val body = repository.getObject(uiState.value.baseUrl, uiState.value.key)
            uiState.value = uiState.value.copy(objectBody = body)
            "GET ok: ${body.length} bytes"
        }
    }

    private fun execute(loadingMessage: String, action: suspend () -> String) {
        uiState.value = uiState.value.copy(loading = true, status = loadingMessage)
        viewModelScope.launch {
            runCatching { action() }
                .onSuccess { message ->
                    uiState.value = uiState.value.copy(loading = false, status = message)
                }
                .onFailure { error ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        status = "Error: ${error.message}",
                    )
                }
        }
    }
}
