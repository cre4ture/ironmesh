package io.ironmesh.android.data

import android.content.Context
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory

object IronmeshPreferences {
    const val DEFAULT_BASE_URL = "http://10.0.2.2:18080"
    private const val PREFS_NAME = "ironmesh_prefs"
    private const val PREF_BASE_URL = "base_url"
    private const val PREF_SYNC_CONFIGS = "folder_sync_configs"
    private const val PREF_SYNC_RUNTIME_STATES = "folder_sync_runtime_states"

    private val moshi: Moshi by lazy {
        Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()
    }

    private val syncConfigAdapter by lazy {
        val listType = Types.newParameterizedType(List::class.java, FolderSyncConfig::class.java)
        moshi.adapter<List<FolderSyncConfig>>(listType)
    }

    private val syncRuntimeStateAdapter by lazy {
        val valueType = FolderSyncRuntimeState::class.java
        val mapType = Types.newParameterizedType(Map::class.java, String::class.java, valueType)
        moshi.adapter<Map<String, FolderSyncRuntimeState>>(mapType)
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getBaseUrl(context: Context): String {
        return prefs(context).getString(PREF_BASE_URL, DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL
    }

    fun setBaseUrl(context: Context, baseUrl: String) {
        prefs(context).edit().putString(PREF_BASE_URL, baseUrl).apply()
    }

    fun getFolderSyncConfigs(context: Context): List<FolderSyncConfig> {
        val raw = prefs(context).getString(PREF_SYNC_CONFIGS, null) ?: return emptyList()
        return runCatching { syncConfigAdapter.fromJson(raw).orEmpty() }
            .getOrDefault(emptyList())
    }

    fun setFolderSyncConfigs(context: Context, configs: List<FolderSyncConfig>) {
        val payload = syncConfigAdapter.toJson(configs)
        prefs(context).edit().putString(PREF_SYNC_CONFIGS, payload).apply()
    }

    fun getFolderSyncRuntimeState(
        context: Context,
        profileId: String,
    ): FolderSyncRuntimeState {
        val states = getFolderSyncRuntimeStates(context)
        return states[profileId] ?: FolderSyncRuntimeState()
    }

    fun setFolderSyncRuntimeState(
        context: Context,
        profileId: String,
        state: FolderSyncRuntimeState,
    ) {
        val states = getFolderSyncRuntimeStates(context).toMutableMap()
        states[profileId] = state
        setFolderSyncRuntimeStates(context, states)
    }

    fun clearFolderSyncRuntimeState(context: Context, profileId: String) {
        val states = getFolderSyncRuntimeStates(context).toMutableMap()
        states.remove(profileId)
        setFolderSyncRuntimeStates(context, states)
    }

    private fun getFolderSyncRuntimeStates(context: Context): Map<String, FolderSyncRuntimeState> {
        val raw = prefs(context).getString(PREF_SYNC_RUNTIME_STATES, null) ?: return emptyMap()
        return runCatching { syncRuntimeStateAdapter.fromJson(raw).orEmpty() }
            .getOrDefault(emptyMap())
    }

    private fun setFolderSyncRuntimeStates(
        context: Context,
        states: Map<String, FolderSyncRuntimeState>,
    ) {
        val payload = syncRuntimeStateAdapter.toJson(states)
        prefs(context).edit().putString(PREF_SYNC_RUNTIME_STATES, payload).apply()
    }
}
