package io.ironmesh.android.data

import android.content.Context
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import io.ironmesh.android.ui.GalleryViewMode

object IronmeshPreferences {
    private const val PREFS_NAME = "ironmesh_prefs"
    private const val PREF_SYNC_CONFIGS = "folder_sync_configs"
    private const val PREF_DEVICE_AUTH_STATE = "device_auth_state"
    private const val PREF_GALLERY_VIEW_MODE = "gallery_view_mode"

    private val moshi: Moshi by lazy {
        Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()
    }

    private val syncConfigAdapter by lazy {
        val listType = Types.newParameterizedType(List::class.java, FolderSyncConfig::class.java)
        moshi.adapter<List<FolderSyncConfig>>(listType)
    }

    private val deviceAuthStateAdapter by lazy {
        moshi.adapter(DeviceAuthState::class.java)
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getFolderSyncConfigs(context: Context): List<FolderSyncConfig> {
        val raw = prefs(context).getString(PREF_SYNC_CONFIGS, null) ?: return emptyList()
        return runCatching { syncConfigAdapter.fromJson(raw).orEmpty() }
            .getOrDefault(emptyList())
    }

    fun setFolderSyncConfigs(context: Context, configs: List<FolderSyncConfig>) {
        val payload = syncConfigAdapter.toJson(configs)
        prefs(context).edit().putString(PREF_SYNC_CONFIGS, payload).apply()
    }

    fun getDeviceAuthState(context: Context): DeviceAuthState {
        val raw = prefs(context).getString(PREF_DEVICE_AUTH_STATE, null) ?: return DeviceAuthState()
        return runCatching { deviceAuthStateAdapter.fromJson(raw) ?: DeviceAuthState() }
            .getOrDefault(DeviceAuthState())
    }

    fun setDeviceAuthState(context: Context, state: DeviceAuthState) {
        val payload = deviceAuthStateAdapter.toJson(state)
        prefs(context).edit().putString(PREF_DEVICE_AUTH_STATE, payload).apply()
    }

    fun clearDeviceAuthState(context: Context) {
        prefs(context).edit().remove(PREF_DEVICE_AUTH_STATE).apply()
    }

    fun getGalleryViewMode(context: Context): GalleryViewMode {
        val raw = prefs(context).getString(PREF_GALLERY_VIEW_MODE, null)
        return runCatching { raw?.let(GalleryViewMode::valueOf) ?: GalleryViewMode.FLATTENED_ALL_IMAGES }
            .getOrDefault(GalleryViewMode.FLATTENED_ALL_IMAGES)
    }

    fun setGalleryViewMode(context: Context, mode: GalleryViewMode) {
        prefs(context).edit().putString(PREF_GALLERY_VIEW_MODE, mode.name).apply()
    }
}
