//! What the page may reach: where the webview may navigate, which pages the
//! shell opens in the system browser, and the security configuration.

use sigylo_app::{legal, navigation::is_app_url};
use url::Url;

fn json(path: &str) -> serde_json::Value {
    let dir = env!("CARGO_MANIFEST_DIR");
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{path}")).unwrap()).unwrap()
}

fn allowed(url: &str) -> bool {
    is_app_url(&Url::parse(url).unwrap())
}

#[test]
fn the_webview_stays_on_the_bundled_app() {
    assert!(allowed("tauri://localhost/"));
    assert!(allowed("tauri://localhost/#/s/a/b"));
    assert!(allowed("http://tauri.localhost/index.html"));
    assert!(allowed("https://tauri.localhost/"));
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
            "blob:tauri://localhost/x",
            "ipc://localhost/relay",
        ] {
            assert!(!allowed(url), "{url}");
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
