package io.ironmesh.android

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.webkit.WebView
import androidx.activity.ComponentActivity
import androidx.activity.addCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import io.ironmesh.android.ui.components.IronmeshEmbeddedWebUi

class WebUiActivity : ComponentActivity() {
    private var hostedWebView: WebView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        hideStatusBar()

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
                    IronmeshEmbeddedWebUi(
                        modifier = Modifier.fillMaxSize(),
                        url = url,
                        onCreated = { hostedWebView = it },
                    )
                }
            }
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            hideStatusBar()
        }
    }

    private fun hideStatusBar() {
        WindowInsetsControllerCompat(window, window.decorView).apply {
            systemBarsBehavior =
                WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            hide(WindowInsetsCompat.Type.statusBars())
        }
    }

    companion object {
        private const val EXTRA_WEB_UI_URL = "io.ironmesh.android.extra.WEB_UI_URL"

        fun intent(context: Context, webUiUrl: String): Intent =
            Intent(context, WebUiActivity::class.java).putExtra(EXTRA_WEB_UI_URL, webUiUrl)
    }
}
