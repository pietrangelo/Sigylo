//! The webview shows the bundled app and nothing else. Tauri serves it at
//! `tauri://localhost` (macOS, Linux, iOS) or `http://tauri.localhost`
//! (Windows, Android; `https` only with `useHttpsScheme`, which the app leaves
//! off): only this platform's origin is the app. Besides it, the webview may
//! only follow a `blob:` the page itself made, which it saves as a download:
//! that is how an opened file is saved. Any other navigation, and any other
//! download, is refused.

use url::{Host, Url};

/// Whether the webview may follow a navigation to `url`.
pub fn allows(url: &Url) -> bool {
    is_app_url(url) || is_app_download(url)
}

/// The scheme and host Tauri serves the bundle at on this platform.
#[cfg(any(windows, target_os = "android"))]
const APP_ORIGIN: (&str, &str) = ("http", "tauri.localhost");
#[cfg(not(any(windows, target_os = "android")))]
const APP_ORIGIN: (&str, &str) = ("tauri", "localhost");

pub fn is_app_url(url: &Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return false;
    }
    let (scheme, host) = APP_ORIGIN;
    url.scheme() == scheme && url.host() == Some(Host::Domain(host))
}

/// Whether the webview may save a download: only a `blob:` the page itself
/// made, as `saveFile` does for an opened file. `saveFile` always marks it
/// `application/octet-stream` with a `download` name, so the webview writes
/// it to the downloads folder and never shows it.
pub fn is_app_download(url: &Url) -> bool {
    url.scheme() == "blob" && Url::parse(url.path()).is_ok_and(|origin| is_app_url(&origin))
}
