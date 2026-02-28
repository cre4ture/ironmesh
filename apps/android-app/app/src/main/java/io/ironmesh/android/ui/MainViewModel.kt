package io.ironmesh.android.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.ironmesh.android.data.IronmeshPreferences
import io.ironmesh.android.data.IronmeshRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class MainUiState(
    val baseUrl: String = IronmeshPreferences.DEFAULT_BASE_URL,
    val key: String = "demo-key",
    val payload: String = "hello from android",
    val status: String = "Ready",
    val replicationSummary: String = "",
    val objectBody: String = "",
    val loading: Boolean = false,
)

class MainViewModel(
    application: Application,
) : AndroidViewModel(application) {

    private val repository = IronmeshRepository()

    var uiState = androidx.compose.runtime.mutableStateOf(MainUiState())
        private set

    init {
        val persistedBaseUrl = IronmeshPreferences.getBaseUrl(getApplication())
        uiState.value = uiState.value.copy(baseUrl = persistedBaseUrl)
    }

    fun updateBaseUrl(value: String) {
        uiState.value = uiState.value.copy(baseUrl = value)
        IronmeshPreferences.setBaseUrl(getApplication(), value)
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

    fun setStatus(message: String) {
        uiState.value = uiState.value.copy(status = message)
    }

    fun openWebUi(onReady: (String) -> Unit) {
        val baseUrl = uiState.value.baseUrl
        uiState.value = uiState.value.copy(loading = true, status = "Starting embedded Web UI...")
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    repository.startWebUi(baseUrl)
                }
            }
                .onSuccess { url ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        status = "Web UI ready at $url",
                    )
                    onReady(url)
                }
                .onFailure { error ->
                    uiState.value = uiState.value.copy(
                        loading = false,
                        status = "Error: ${error.message}",
                    )
                }
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
