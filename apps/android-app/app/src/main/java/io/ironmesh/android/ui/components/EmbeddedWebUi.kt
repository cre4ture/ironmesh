package io.ironmesh.android.ui.components

import android.annotation.SuppressLint
import android.net.Uri
import android.webkit.CookieManager
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import io.ironmesh.android.data.EmbeddedWebUiSession

private const val EMBEDDED_WEB_UI_SESSION_HEADER = "X-IronMesh-Web-Ui-Session"
private const val EMBEDDED_WEB_UI_SESSION_COOKIE = "ironmesh_web_ui_session"

@Composable
fun IronmeshEmbeddedWebUi(
    session: EmbeddedWebUiSession,
    modifier: Modifier = Modifier,
    onCreated: ((WebView) -> Unit)? = null,
) {
    AndroidView(
        modifier = modifier,
        factory = { context ->
            WebView(context).apply {
                configureEmbeddedWebUi(session)
                onCreated?.invoke(this)
            }
        },
        update = { webView ->
            if (webView.url != session.url) {
                webView.loadEmbeddedWebUi(session)
            }
        },
    )
}

@SuppressLint("SetJavaScriptEnabled")
private fun WebView.configureEmbeddedWebUi(session: EmbeddedWebUiSession) {
    settings.javaScriptEnabled = true
    settings.domStorageEnabled = true
    settings.allowFileAccess = false
    settings.allowContentAccess = false
    settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
    settings.javaScriptCanOpenWindowsAutomatically = false
    settings.setSupportMultipleWindows(false)
    webViewClient = EmbeddedWebUiClient(session.url)
    loadEmbeddedWebUi(session)
}

private fun WebView.loadEmbeddedWebUi(session: EmbeddedWebUiSession) {
    loadUrl(session.url, mapOf(EMBEDDED_WEB_UI_SESSION_HEADER to session.authorization))
}

fun clearEmbeddedWebUiSession(url: String) {
    CookieManager.getInstance().apply {
        setCookie(url, "$EMBEDDED_WEB_UI_SESSION_COOKIE=; Path=/; Max-Age=0")
        flush()
    }
}

private class EmbeddedWebUiClient(
    private val initialUrl: String,
) : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean = !isSameOrigin(url)

    override fun shouldOverrideUrlLoading(
        view: WebView,
        request: android.webkit.WebResourceRequest,
    ): Boolean = !isSameOrigin(request.url.toString())

    private fun isSameOrigin(url: String): Boolean {
        val origin = Uri.parse(initialUrl)
        val candidate = Uri.parse(url)
        return candidate.scheme == origin.scheme &&
            candidate.host == origin.host &&
            candidate.port == origin.port
    }
}
