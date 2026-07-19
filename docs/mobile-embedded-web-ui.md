# Mobile embedded Web UI security and lifecycle

The Android and iOS clients host the embedded Web UI only on an ephemeral
`127.0.0.1` listener. It is not intended to be opened in a system browser,
custom tab, or Safari view.

Each request to open the UI creates a new, random session authorization that
expires after 15 minutes. The native in-app WebView supplies that value only
as an HTTP header on its initial request. The loopback server exchanges it for
an `HttpOnly`, `SameSite=Strict`, host-only cookie and rejects all requests
without that session. The authorization is never part of a URL, referrer, or
diagnostic message.

The server is alive only while the app is actively presenting its embedded Web
UI. Both platforms invalidate it when the WebView is dismissed, the app moves
to the background, the connection is cleared, or identity/connection material
is replaced. Opening the UI again starts a new listener and authorization;
cookies or headers from a previous session cannot be reused.

Android uses an app-owned `WebView`, and iOS uses a `WKWebView` with a
non-persistent data store. Both restrict navigation to the active loopback
origin so authorization material cannot be carried into external browsing
state.
