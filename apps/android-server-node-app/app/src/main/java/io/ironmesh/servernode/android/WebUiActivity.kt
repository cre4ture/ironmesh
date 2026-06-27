package io.ironmesh.servernode.android

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.http.SslError
import android.os.Bundle
import android.webkit.SslErrorHandler
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.addCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView

class WebUiActivity : ComponentActivity() {
    private var hostedWebView: WebView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        onBackPressedDispatcher.addCallback(this) {
            val webView = hostedWebView
            if (webView != null && webView.canGoBack()) {
                webView.goBack()
            } else {
                finish()
            }
        }

        val url = intent.getStringExtra(EXTRA_WEB_UI_URL).orEmpty()
        if (url.isBlank()) {
            finish()
            return
        }

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AndroidView(
                        modifier = Modifier.fillMaxSize(),
                        factory = { context ->
                            WebView(context).apply {
                                configure(url)
                                hostedWebView = this
                            }
                        },
                    )
                }
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun WebView.configure(url: String) {
        val allowedHost = Uri.parse(url).host.orEmpty()

        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        webViewClient = object : WebViewClient() {
            override fun onReceivedSslError(
                view: WebView?,
                handler: SslErrorHandler?,
                error: SslError?,
            ) {
                val requestHost = error?.url?.let(Uri::parse)?.host.orEmpty()
                if (requestHost == allowedHost) {
                    handler?.proceed()
                } else {
                    handler?.cancel()
                }
            }
        }
        loadUrl(url)
    }

    companion object {
        private const val EXTRA_WEB_UI_URL = "io.ironmesh.servernode.android.extra.WEB_UI_URL"

        fun intent(context: Context, webUiUrl: String): Intent =
            Intent(context, WebUiActivity::class.java).putExtra(EXTRA_WEB_UI_URL, webUiUrl)
    }
}
