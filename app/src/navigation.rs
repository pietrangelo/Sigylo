//! The webview shows the bundled app and nothing else. Tauri serves it at
//! `tauri://localhost` (macOS, Linux, iOS) or `http(s)://tauri.localhost`
//! (Windows, Android). Besides it, the webview may only follow a `blob:` the
//! page itself made, which it saves as a download: that is how an opened file
//! is saved. Any other navigation, and any other download, is refused.

use url::{Host, Url};

/// Whether the webview may follow a navigation to `url`.
pub fn allows(url: &Url) -> bool {
    is_app_url(url) || is_app_download(url)
}

pub fn is_app_url(url: &Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return false;
    }
    let host = |name: &str| url.host() == Some(Host::Domain(name));
    match url.scheme() {
        "tauri" => host("localhost"),
        "http" | "https" => host("tauri.localhost"),
        _ => false,
    }
}

/// Whether the webview may save a download: only a `blob:` the page itself
/// made, as `saveFile` does for an opened file. `saveFile` always marks it
/// `application/octet-stream` with a `download` name, so the webview writes
/// it to the downloads folder and never shows it.
pub fn is_app_download(url: &Url) -> bool {
    url.scheme() == "blob" && Url::parse(url.path()).is_ok_and(|origin| is_app_url(&origin))
}
