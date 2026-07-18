package io.ironmesh.android.data

import android.content.Context
import android.content.SharedPreferences
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import io.ironmesh.android.ui.GalleryViewMode
import io.ironmesh.android.ui.theme.DEFAULT_IRONMESH_ACCENT_COLOR_HEX
import io.ironmesh.android.ui.theme.normalizeIronmeshAccentColorHex

private const val DEVICE_AUTH_STATE_KEY = "device_auth_state"

object IronmeshPreferences {
    private const val DEVICE_AUTH_PREFS_NAME = "ironmesh_prefs"
    private const val APP_PREFS_NAME = "ironmesh_app_prefs"
    private const val PREF_SYNC_CONFIGS = "folder_sync_configs"
    private const val PREF_GALLERY_VIEW_MODE = "gallery_view_mode"
    private const val PREF_APP_CONNECTION_STATUS = "app_connection_status"
    private const val PREF_THEME_ACCENT_COLOR = "theme_accent_color"

    private val moshi: Moshi by lazy {
        Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()
    }

    private val syncConfigAdapter by lazy {
        val listType = Types.newParameterizedType(List::class.java, FolderSyncConfig::class.java)
        moshi.adapter<List<FolderSyncConfig>>(listType)
    }

    private val appConnectionStatusAdapter by lazy {
        moshi.adapter(AppConnectionStatus::class.java)
    }

    @Volatile
    private var deviceAuthPersistence: DeviceAuthStatePersistence? = null

    private fun appPrefs(context: Context) =
        context.getSharedPreferences(APP_PREFS_NAME, Context.MODE_PRIVATE)

    private fun deviceAuthPrefs(context: Context) =
        context.getSharedPreferences(DEVICE_AUTH_PREFS_NAME, Context.MODE_PRIVATE)

    private fun deviceAuthPersistence(context: Context): DeviceAuthStatePersistence {
        deviceAuthPersistence?.let { return it }
        return synchronized(this) {
            deviceAuthPersistence ?: DeviceAuthStatePersistence(
                preferences = SharedPreferencesDeviceAuthStorage(deviceAuthPrefs(context)),
                secretStore = AtomicFileDeviceIdentitySecretStore(
                    context.noBackupFilesDir.resolve(
                        AtomicFileDeviceIdentitySecretStore.DEFAULT_FILE_NAME,
                    ),
                ),
            ).also { deviceAuthPersistence = it }
        }
    }

    private fun readAppPreference(
        context: Context,
        key: String,
    ): String? {
        appPrefs(context).getString(key, null)?.let { return it }
        val legacyPrefs = deviceAuthPrefs(context)
        val legacyValue = legacyPrefs.getString(key, null) ?: return null
        if (appPrefs(context).edit().putString(key, legacyValue).commit()) {
            legacyPrefs.edit().remove(key).apply()
        }
        return legacyValue
    }

    private fun writeAppPreference(
        context: Context,
        key: String,
        value: String?,
    ) {
        val editor = appPrefs(context).edit()
        if (value == null) {
            editor.remove(key)
        } else {
            editor.putString(key, value)
        }
        editor.apply()
        deviceAuthPrefs(context).edit().remove(key).apply()
    }

    fun getFolderSyncConfigs(context: Context): List<FolderSyncConfig> {
        val raw = readAppPreference(context, PREF_SYNC_CONFIGS) ?: return emptyList()
        return runCatching { syncConfigAdapter.fromJson(raw).orEmpty() }
            .getOrDefault(emptyList())
    }

    fun setFolderSyncConfigs(context: Context, configs: List<FolderSyncConfig>) {
        val payload = syncConfigAdapter.toJson(configs)
        writeAppPreference(context, PREF_SYNC_CONFIGS, payload)
    }

    fun getDeviceAuthState(context: Context): DeviceAuthState {
        return deviceAuthPersistence(context.applicationContext).load()
    }

    fun setDeviceAuthState(context: Context, state: DeviceAuthState) {
        deviceAuthPersistence(context.applicationContext).save(state)
    }

    fun clearDeviceAuthState(context: Context) {
        deviceAuthPersistence(context.applicationContext).clear()
    }

    fun getGalleryViewMode(context: Context): GalleryViewMode {
        val raw = readAppPreference(context, PREF_GALLERY_VIEW_MODE)
        return runCatching { raw?.let(GalleryViewMode::valueOf) ?: GalleryViewMode.FLATTENED_ALL_IMAGES }
            .getOrDefault(GalleryViewMode.FLATTENED_ALL_IMAGES)
    }

    fun setGalleryViewMode(context: Context, mode: GalleryViewMode) {
        writeAppPreference(context, PREF_GALLERY_VIEW_MODE, mode.name)
    }

    fun getAppConnectionStatus(context: Context): AppConnectionStatus {
        val raw = readAppPreference(context, PREF_APP_CONNECTION_STATUS)
            ?: return AppConnectionStatus()
        return runCatching {
            appConnectionStatusAdapter.fromJson(raw) ?: AppConnectionStatus()
        }.getOrDefault(AppConnectionStatus())
    }

    fun setAppConnectionStatus(context: Context, status: AppConnectionStatus) {
        val payload = appConnectionStatusAdapter.toJson(status)
        writeAppPreference(context, PREF_APP_CONNECTION_STATUS, payload)
    }

    fun clearAppConnectionStatus(context: Context) {
        writeAppPreference(context, PREF_APP_CONNECTION_STATUS, null)
    }

    fun getThemeAccentColor(context: Context): String {
        val raw = readAppPreference(context, PREF_THEME_ACCENT_COLOR)
        return normalizeIronmeshAccentColorHex(raw) ?: DEFAULT_IRONMESH_ACCENT_COLOR_HEX
    }

    fun setThemeAccentColor(
        context: Context,
        colorHex: String,
    ) {
        val normalized = normalizeIronmeshAccentColorHex(colorHex) ?: DEFAULT_IRONMESH_ACCENT_COLOR_HEX
        writeAppPreference(
            context,
            PREF_THEME_ACCENT_COLOR,
            normalized.takeUnless { it == DEFAULT_IRONMESH_ACCENT_COLOR_HEX },
        )
    }
}

private class SharedPreferencesDeviceAuthStorage(
    private val preferences: SharedPreferences,
) : DeviceAuthPreferencesStorage {
    override fun read(): String? =
        preferences.getString(DEVICE_AUTH_STATE_KEY, null)

    override fun write(value: String) {
        if (!preferences.edit().putString(DEVICE_AUTH_STATE_KEY, value).commit()) {
            throw DeviceIdentityStorageException(
                "Could not save device authentication settings. Enrollment was not changed.",
            )
        }
    }

    override fun clear() {
        if (!preferences.edit().remove(DEVICE_AUTH_STATE_KEY).commit()) {
            throw DeviceIdentityStorageException(
                "Could not clear device authentication settings. Enrollment was not changed.",
            )
        }
    }
}
