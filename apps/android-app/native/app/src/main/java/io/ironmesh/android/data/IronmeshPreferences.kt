package io.ironmesh.android.data

import android.content.Context

object IronmeshPreferences {
    const val DEFAULT_BASE_URL = "http://10.0.2.2:18080"
    private const val PREFS_NAME = "ironmesh_prefs"
    private const val PREF_BASE_URL = "base_url"

    fun getBaseUrl(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(PREF_BASE_URL, DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL
    }

    fun setBaseUrl(context: Context, baseUrl: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(PREF_BASE_URL, baseUrl).apply()
    }
}
