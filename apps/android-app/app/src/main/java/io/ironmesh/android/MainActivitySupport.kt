package io.ironmesh.android

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.provider.DocumentsContract
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import io.ironmesh.android.data.FolderSyncNetworkPolicy

fun launchFolderPicker(
    launcher: ManagedActivityResultLauncher<Intent, ActivityResult>,
    onError: (String) -> Unit,
) {
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
        addFlags(
            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION,
        )
    }

    try {
        launcher.launch(intent)
    } catch (_: ActivityNotFoundException) {
        onError("No compatible folder picker found on this device")
    }
}

fun missingOriginalPhotoAccessPermissions(context: Context): Array<String> {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
        return emptyArray()
    }

    val required = buildList {
        add(Manifest.permission.ACCESS_MEDIA_LOCATION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.READ_MEDIA_IMAGES)
        } else {
            add(Manifest.permission.READ_EXTERNAL_STORAGE)
        }
    }

    return required
        .filter { permission ->
            ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED
        }
        .toTypedArray()
}

fun requestOriginalPhotoAccessIfNeeded(
    context: Context,
    launcher: ManagedActivityResultLauncher<Array<String>, Map<String, Boolean>>,
) {
    val missing = missingOriginalPhotoAccessPermissions(context)
    if (missing.isNotEmpty()) {
        launcher.launch(missing)
    }
}

fun missingWifiNameAccessPermissions(context: Context): Array<String> {
    val required = buildList {
        add(Manifest.permission.ACCESS_FINE_LOCATION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.NEARBY_WIFI_DEVICES)
        }
    }

    return required
        .filter { permission ->
            ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED
        }
        .toTypedArray()
}

fun requestWifiNameAccessIfNeeded(
    context: Context,
    launcher: ManagedActivityResultLauncher<Array<String>, Map<String, Boolean>>,
    policy: FolderSyncNetworkPolicy,
) {
    if (policy.normalized().allowedWifiSsids.isEmpty()) {
        return
    }

    val missing = missingWifiNameAccessPermissions(context)
    if (missing.isNotEmpty()) {
        launcher.launch(missing)
    }
}

fun isDeviceLocationEnabled(context: Context): Boolean {
    val locationManager = context.getSystemService(LocationManager::class.java) ?: return false
    return runCatching {
        locationManager.isLocationEnabled
    }.getOrDefault(false)
}

fun openLocationSettings(context: Context): Boolean {
    val intent = Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    return runCatching {
        context.startActivity(intent)
        true
    }.getOrDefault(false)
}

fun handleFolderPickerResult(
    context: Context,
    result: ActivityResult,
    onResolvedSelection: (String, String) -> Unit,
    onError: (String) -> Unit,
) {
    val treeUri = result.data?.data
    if (treeUri == null) {
        onError("Folder selection was cancelled")
        return
    }

    val grantFlags = result.data?.flags
        ?.and(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        ?: (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
    runCatching {
        context.contentResolver.takePersistableUriPermission(treeUri, grantFlags)
    }

    val resolvedPath = resolveTreeUriToFilesystemPath(treeUri)
    if (resolvedPath != null) {
        onResolvedSelection(resolvedPath, treeUri.toString())
    } else {
        onError(
            "Selected folder could not be mapped to a filesystem path. Please use a folder under shared storage such as DCIM or Documents.",
        )
    }
}

private fun resolveTreeUriToFilesystemPath(treeUri: Uri): String? {
    val documentId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull()
        ?: return null
    if (documentId.startsWith("raw:")) {
        return documentId.removePrefix("raw:")
    }

    val storageRoot = documentId.substringBefore(':', "")
    val relative = documentId.substringAfter(':', "")
        .split('/')
        .filter { it.isNotBlank() }

    val basePath = when {
        storageRoot.equals("primary", ignoreCase = true) -> "/storage/emulated/0"
        storageRoot.equals("home", ignoreCase = true) -> "/storage/emulated/0/Documents"
        storageRoot.length == 9 && storageRoot[4] == '-' -> "/storage/$storageRoot"
        else -> return null
    }

    return if (relative.isEmpty()) {
        basePath
    } else {
        buildString {
            append(basePath.trimEnd('/'))
            relative.forEach { segment ->
                append('/')
                append(segment)
            }
        }
    }
}
