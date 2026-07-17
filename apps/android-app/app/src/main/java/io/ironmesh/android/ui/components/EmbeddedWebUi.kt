package io.ironmesh.android.ui.components

import android.annotation.SuppressLint
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView

@Composable
fun IronmeshEmbeddedWebUi(
    url: String,
    modifier: Modifier = Modifier,
    onCreated: ((WebView) -> Unit)? = null,
) {
    AndroidView(
        modifier = modifier,
        factory = { context ->
            WebView(context).apply {
                configureEmbeddedWebUi(url)
                onCreated?.invoke(this)
            }
        },
        update = { webView ->
            if (webView.url != url) {
                webView.loadUrl(url)
            }
        },
    )
}

@SuppressLint("SetJavaScriptEnabled")
private fun WebView.configureEmbeddedWebUi(url: String) {
    settings.javaScriptEnabled = true
    settings.domStorageEnabled = true
    settings.allowFileAccess = false
    settings.allowContentAccess = false
    settings.mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
    webViewClient = WebViewClient()
    loadUrl(url)
}
