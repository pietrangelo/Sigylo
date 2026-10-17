//! The webview shows the bundled app and nothing else. Tauri serves it at
//! `tauri://localhost` (macOS, Linux, iOS) or `http(s)://tauri.localhost`
//! (Windows, Android); any other navigation is refused.

use url::{Host, Url};

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
