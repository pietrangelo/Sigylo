//! What the page may reach: where the webview may navigate, which pages the
//! shell opens in the system browser, and the security configuration.

use sigylo_app::{
    legal,
    navigation::{allows, is_app_download},
};
use url::Url;

fn json(path: &str) -> serde_json::Value {
    let dir = env!("CARGO_MANIFEST_DIR");
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{path}")).unwrap()).unwrap()
}

fn allowed(url: &str) -> bool {
    allows(&Url::parse(url).unwrap())
}

/// Where Tauri serves the bundle on this platform, and the origins it uses on
/// the others (or with `useHttpsScheme`, which the app leaves off).
#[cfg(any(windows, target_os = "android"))]
const APP: &str = "http://tauri.localhost";
#[cfg(any(windows, target_os = "android"))]
const OTHER_PLATFORMS: [&str; 2] = ["tauri://localhost", "https://tauri.localhost"];
#[cfg(not(any(windows, target_os = "android")))]
const APP: &str = "tauri://localhost";
#[cfg(not(any(windows, target_os = "android")))]
const OTHER_PLATFORMS: [&str; 2] = ["http://tauri.localhost", "https://tauri.localhost"];

#[test]
fn the_webview_stays_on_the_bundled_app() {
    assert!(allowed(&format!("{APP}/")));
    assert!(allowed(&format!("{APP}/#/s/a/b")));
    assert!(allowed(&format!("{APP}/index.html")));
}

fn saved(url: &str) -> bool {
    is_app_download(&Url::parse(url).unwrap())
}

#[test]
fn files_the_page_saves_go_to_the_downloads() {
    let blob = format!("blob:{APP}/0b6e8f4a-6a43-4c55-9a8e-2f1d3c9e5b10");
    assert!(saved(&blob));
    // Saving follows the blob, so the navigation policy lets exactly these through.
    assert!(allowed(&blob));
}

#[test]
fn legal_pages_open_on_the_public_site() {
    assert_eq!(legal::page_url("terms"), Some("https://sigylo.net/#/terms"));
    assert_eq!(legal::page_url("privacy"), Some("https://sigylo.net/#/privacy"));
}

#[test]
fn the_page_carries_the_same_policy_as_the_bundled_html() {
    let conf = json("tauri.conf.json");
    let csp = conf["app"]["security"]["csp"].as_str().unwrap();
    let html = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../web/index.html")).unwrap();
    let meta = html.split("Content-Security-Policy\" content=\"").nth(1).unwrap().split('"').next().unwrap();
    assert_eq!(csp, meta.replace("connect-src 'self';", "connect-src 'self' ipc: http://ipc.localhost;"));
}

mod adversary {
    use super::*;

    #[test]
    fn navigation_anywhere_else_is_refused() {
        for url in [
            "https://sigylo.net/",
            "https://evil.example/",
            "http://localhost/",
            "tauri://evil.example/",
            "tauri://localhost.evil.example/",
            "http://tauri.localhost.evil.example/",
            "http://evil.example/?tauri.localhost",
            "http://user@tauri.localhost/",
            "http://tauri.localhost:8080/",
            "tauri://localhost:1/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "blob:https://evil.example/x",
            "ipc://localhost/relay",
        ] {
            assert!(!allowed(url), "{url}");
        }
    }

    /// Another platform's origin is not the bundle here: on Linux nothing
    /// serves `http://tauri.localhost`, so a page there is not the app's.
    #[test]
    fn another_platform_s_origin_is_refused() {
        for origin in OTHER_PLATFORMS {
            assert!(!allowed(&format!("{origin}/")), "{origin}");
            assert!(!allowed(&format!("{origin}/index.html")), "{origin}");
            assert!(!saved(&format!("blob:{origin}/0b6e8f4a-6a43-4c55-9a8e-2f1d3c9e5b10")), "{origin}");
        }
    }

    #[test]
    fn the_app_origin_with_a_port_or_a_user_is_refused() {
        let (scheme, host) = APP.split_once("://").unwrap();
        for url in [
            format!("{APP}:1/"),
            format!("{APP}:80/"),
            format!("{scheme}://user@{host}/"),
            format!("{scheme}://user:pass@{host}/"),
            format!("blob:{APP}:1/0b6e8f4a"),
            format!("blob:{scheme}://user@{host}/0b6e8f4a"),
        ] {
            assert!(!allowed(&url), "{url}");
            assert!(!saved(&url), "{url}");
        }
    }

    #[test]
    fn only_the_page_s_own_blobs_are_saved() {
        for url in [
            "https://evil.example/payload.exe",
            "tauri://localhost/index.html",
            "blob:https://evil.example/0b6e8f4a",
            "blob:tauri://localhost.evil.example/0b6e8f4a",
            "blob:null/0b6e8f4a",
            "data:application/octet-stream,AAAA",
            "file:///etc/passwd",
        ] {
            assert!(!saved(url), "{url}");
        }
    }

    #[test]
    fn the_shell_opens_no_other_page() {
        for page in ["", "Terms", "terms ", "https://evil.example", "../terms", "privacy/"] {
            assert_eq!(legal::page_url(page), None, "{page:?}");
        }
    }

    #[test]
    fn the_policy_allows_no_inline_code_and_no_network() {
        let csp = json("tauri.conf.json")["app"]["security"]["csp"].as_str().unwrap().to_string();
        let directives: Vec<Vec<&str>> = csp.split(';').map(|d| d.split_whitespace().collect()).collect();
        assert_eq!(directives[0], ["default-src", "'none'"]);
        for directive in &directives {
            let (name, sources) = directive.split_first().unwrap();
            let expected: &[&str] = match *name {
                "connect-src" => &["'self'", "ipc:", "http://ipc.localhost"],
                "script-src" => &["'self'", "'wasm-unsafe-eval'"],
                "default-src" | "base-uri" | "form-action" => &["'none'"],
                _ => &["'self'"],
            };
            assert_eq!(sources, expected, "{name}");
        }
    }

    #[test]
    fn the_page_gets_no_tauri_api_beyond_its_two_commands() {
        let conf = json("tauri.conf.json");
        assert_eq!(conf["app"]["withGlobalTauri"], false);
        assert_eq!(conf["app"]["security"]["capabilities"], serde_json::json!(["main"]));
        assert_eq!(conf["app"]["security"]["freezePrototype"], true);
        assert!(conf["app"]["security"].get("dangerousDisableAssetCspModification").is_none());
        assert!(conf["app"]["security"].get("assetProtocol").is_none());
        let capability = json("capabilities/main.json");
        assert_eq!(capability["windows"], serde_json::json!(["main"]));
        assert_eq!(capability["permissions"], serde_json::json!(["allow-relay", "allow-open-legal"]));
        assert!(capability.get("remote").is_none(), "no remote origin may call the shell");
    }

    #[test]
    fn the_code_ships_with_the_app_and_never_updates_itself_from_a_server() {
        let conf = json("tauri.conf.json");
        assert_eq!(conf["build"]["frontendDist"], "../web/dist-app");
        assert!(conf["build"].get("devUrl").is_none());
        assert!(conf.get("plugins").is_none_or(|p| p.get("updater").is_none()));
        assert!(conf["bundle"].get("createUpdaterArtifacts").is_none());
    }
}
