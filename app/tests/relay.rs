//! The app shell's relay command: which calls it lets through, and how it
//! talks to the relay. A local HTTP server stands in for sigylo.net.

use sigylo_app::relay::{Call, Failure, MAX_BODY_LEN, MAX_REPLY_LEN, Method, PRODUCTION, Refusal, Relay};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const ID: &str = "AAECAwQFBgcICQoLDA0ODw";

/// A 32-byte session token in base64url, as the web client sends it.
const SESSION: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn call(method: &str, path: &str, body: Option<&str>) -> Result<Call, Refusal> {
    Call::new(method, path, body.map(String::from), None)
}

fn signed_in(method: &str, path: &str, body: Option<&str>, session: &str) -> Result<Call, Refusal> {
    Call::new(method, path, body.map(String::from), Some(session.to_string()))
}

/// Serves one canned HTTP response per connection and reports every raw request.
async fn server(response: impl Into<Vec<u8>>) -> (String, mpsc::UnboundedReceiver<String>) {
    let response: Vec<u8> = response.into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/api", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request);
                if let Some(end) = text.find("\r\n\r\n") {
                    let declared = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + declared {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            tx.send(String::from_utf8_lossy(&request).into_owned()).unwrap();
            socket.write_all(&response).await.unwrap();
            socket.shutdown().await.ok();
        }
    });
    (base, rx)
}

fn http(status: &str, extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{extra}connection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn the_app_talks_to_the_production_relay_only() {
    assert_eq!(PRODUCTION, "https://sigylo.net/api");
}

#[test]
fn every_route_of_the_relay_api_is_allowed() {
    let body = Some("{}");
    for (method, path, body) in [
        ("POST", "/secrets".to_string(), body),
        ("POST", format!("/secrets/{ID}/open"), None),
        ("POST", format!("/secrets/{ID}/revoke"), body),
        ("POST", "/requests".to_string(), body),
        ("GET", format!("/requests/{ID}"), None),
        ("POST", format!("/requests/{ID}/answer"), body),
    ] {
        let checked = call(method, &path, body).unwrap_or_else(|e| panic!("{method} {path}: {e:?}"));
        assert_eq!(checked.path(), path);
        assert_eq!(checked.method(), if method == "GET" { Method::Get } else { Method::Post });
    }
}

#[test]
fn every_account_route_is_allowed() {
    let body = Some("{}");
    for path in ["/account/register/start", "/account/register/finish", "/account/login/start", "/account/login/finish"]
    {
        call("POST", path, body).unwrap_or_else(|e| panic!("{path}: {e:?}"));
    }
    for (method, path, body) in [
        ("POST", "/account/logout", None),
        ("GET", "/account/keyring", None),
        ("POST", "/account/keyring", body),
        ("POST", "/account/close", None),
    ] {
        let checked = signed_in(method, path, body, SESSION).unwrap_or_else(|e| panic!("{method} {path}: {e:?}"));
        assert_eq!(checked.method(), if method == "GET" { Method::Get } else { Method::Post });
    }
}

#[tokio::test]
async fn a_session_travels_as_a_bearer_token() {
    let (base, mut requests) = server(http("200 OK", "", r#"{"keyring":null,"version":0}"#)).await;
    let relay = Relay::new(&base, false);
    let reply = relay.send(&signed_in("GET", "/account/keyring", None, SESSION).unwrap()).await.unwrap();
    assert_eq!(reply.status, 200);
    let request = requests.recv().await.unwrap();
    assert!(request.starts_with("GET /api/account/keyring HTTP/1.1\r\n"), "{request}");
    assert!(
        request.to_ascii_lowercase().contains(&format!("authorization: bearer {}\r\n", SESSION.to_ascii_lowercase())),
        "{request}"
    );
}

#[tokio::test]
async fn calls_without_a_session_carry_no_authorization() {
    let (base, mut requests) = server(http("200 OK", "", "{}")).await;
    Relay::new(&base, false).send(&call("POST", "/account/login/start", Some("{}")).unwrap()).await.unwrap();
    assert!(!requests.recv().await.unwrap().to_ascii_lowercase().contains("authorization"));
}

#[tokio::test]
async fn forwards_the_call_and_returns_status_and_body() {
    let (base, mut requests) = server(http("201 Created", "", r#"{"id":"x","expires_at":7}"#)).await;
    let relay = Relay::new(&base, false);
    let reply = relay.send(&call("POST", "/secrets", Some(r#"{"payload":"AQI"}"#)).unwrap()).await.unwrap();
    assert_eq!(reply.status, 201);
    assert_eq!(reply.body, r#"{"id":"x","expires_at":7}"#);

    let request = requests.recv().await.unwrap();
    assert!(request.starts_with("POST /api/secrets HTTP/1.1\r\n"), "{request}");
    assert!(request.to_ascii_lowercase().contains("content-type: application/json\r\n"), "{request}");
    assert!(request.ends_with(r#"{"payload":"AQI"}"#), "{request}");
}

#[tokio::test]
async fn sends_no_cookie_and_no_referer() {
    let (base, mut requests) = server(http("200 OK", "set-cookie: track=1\r\n", "{}")).await;
    let relay = Relay::new(&base, false);
    relay.send(&call("GET", &format!("/requests/{ID}"), None).unwrap()).await.unwrap();
    relay.send(&call("GET", &format!("/requests/{ID}"), None).unwrap()).await.unwrap();
    requests.recv().await.unwrap();
    let second = requests.recv().await.unwrap().to_ascii_lowercase();
    assert!(!second.contains("cookie"), "{second}");
    assert!(!second.contains("referer"), "{second}");
}

#[tokio::test]
async fn error_statuses_reach_the_page_unchanged() {
    let (base, _requests) = server(http("404 Not Found", "", r#"{"error":"NotFound"}"#)).await;
    let reply =
        Relay::new(&base, false).send(&call("POST", &format!("/secrets/{ID}/open"), None).unwrap()).await.unwrap();
    assert_eq!((reply.status, reply.body.as_str()), (404, r#"{"error":"NotFound"}"#));
}

#[tokio::test]
async fn an_unreachable_relay_is_a_network_failure() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/api", listener.local_addr().unwrap());
    drop(listener);
    let result = Relay::new(&base, false).send(&call("POST", "/requests", Some("{}")).unwrap()).await;
    assert_eq!(result.unwrap_err(), Failure::Network);
}

mod adversary {
    use super::*;

    #[test]
    fn paths_outside_the_api_are_refused() {
        for path in [
            "",
            "/",
            "secrets",
            "/secrets/",
            "//evil.example/secrets",
            "/secrets/../admin",
            &format!("/secrets/{ID}/../../admin"),
            &format!("/secrets/{ID}/open?x=1"),
            &format!("/secrets/{ID}/open#x"),
            &format!("/secrets/{ID}/burn"),
            &format!("/secrets/{ID}/open/more"),
            &format!("/requests/{ID}/answer/"),
            "/secrets/%41AECAwQFBgcICQoLDA0ODw/open",
            "/secrets/AAECAwQFBgcICQoLDA0OD/open",
            "/secrets/AAECAwQFBgcICQoLDA0ODwA/open",
            "/secrets/AAECAwQFBgcICQoLDA0OD+/open",
            "/secrets/AAECAwQFBgcICQoLDA0OD=/open",
            "/SECRETS",
            "https://evil.example/api/secrets",
            "/secrets\r\nHost: evil.example",
        ] {
            assert_eq!(call("POST", path, Some("{}")).unwrap_err(), Refusal::UnknownRoute, "{path:?}");
        }
    }

    #[test]
    fn each_route_has_exactly_one_method() {
        assert_eq!(call("GET", "/secrets", None).unwrap_err(), Refusal::WrongMethod);
        assert_eq!(call("GET", &format!("/secrets/{ID}/open"), None).unwrap_err(), Refusal::WrongMethod);
        assert_eq!(call("POST", &format!("/requests/{ID}"), None).unwrap_err(), Refusal::WrongMethod);
        for method in ["post", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "", "POST "] {
            assert_eq!(call(method, "/secrets", Some("{}")).unwrap_err(), Refusal::WrongMethod, "{method:?}");
        }
    }

    #[test]
    fn bodies_go_only_where_the_api_expects_them() {
        assert_eq!(call("POST", "/secrets", None).unwrap_err(), Refusal::MissingBody);
        assert_eq!(call("POST", &format!("/secrets/{ID}/open"), Some("{}")).unwrap_err(), Refusal::UnexpectedBody);
        assert_eq!(call("GET", &format!("/requests/{ID}"), Some("{}")).unwrap_err(), Refusal::UnexpectedBody);
    }

    #[test]
    fn a_session_goes_only_to_the_routes_that_need_one() {
        assert_eq!(call("GET", "/account/keyring", None).unwrap_err(), Refusal::MissingSession);
        assert_eq!(call("POST", "/account/close", None).unwrap_err(), Refusal::MissingSession);
        for path in ["/secrets", "/requests", "/account/login/start", "/account/register/finish"] {
            assert_eq!(signed_in("POST", path, Some("{}"), SESSION).unwrap_err(), Refusal::UnexpectedSession, "{path}");
        }
        assert_eq!(
            signed_in("POST", &format!("/secrets/{ID}/open"), None, SESSION).unwrap_err(),
            Refusal::UnexpectedSession
        );
    }

    #[test]
    fn a_malformed_session_never_reaches_a_header() {
        for bad in [
            "",
            &SESSION[1..],
            &format!("{SESSION}A"),
            &format!("{}=", &SESSION[1..]),
            &format!("{}+", &SESSION[1..]),
            &format!("{}\r", &SESSION[1..]),
            &format!("{}\n", &SESSION[1..]),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGx\r\nHost: x",
        ] {
            assert_eq!(
                signed_in("GET", "/account/keyring", None, bad).unwrap_err(),
                Refusal::MalformedSession,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn account_paths_outside_the_api_are_refused() {
        for path in [
            "/account",
            "/account/",
            "/account/login",
            "/account/login/start/",
            "/account/keyring/x",
            "/account/admin",
            "/ACCOUNT/close",
        ] {
            assert_eq!(signed_in("POST", path, None, SESSION).unwrap_err(), Refusal::UnknownRoute, "{path}");
        }
        assert_eq!(signed_in("PUT", "/account/keyring", Some("{}"), SESSION).unwrap_err(), Refusal::WrongMethod);
        assert_eq!(signed_in("GET", "/account/close", None, SESSION).unwrap_err(), Refusal::WrongMethod);
    }

    #[test]
    fn a_body_larger_than_the_relay_accepts_never_leaves_the_device() {
        let largest = "x".repeat(MAX_BODY_LEN);
        assert!(call("POST", "/secrets", Some(&largest)).is_ok());
        let larger = "x".repeat(MAX_BODY_LEN + 1);
        assert_eq!(call("POST", "/secrets", Some(&larger)).unwrap_err(), Refusal::BodyTooLarge);
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let (elsewhere, mut followed) = server(http("200 OK", "", "{}")).await;
        let location = format!("location: {elsewhere}/secrets\r\n");
        let (base, _requests) = server(http("307 Temporary Redirect", &location, "")).await;
        let reply = Relay::new(&base, false).send(&call("POST", "/secrets", Some("{}")).unwrap()).await.unwrap();
        assert_eq!(reply.status, 307);
        assert!(followed.try_recv().is_err(), "the redirect was followed");
    }

    #[tokio::test]
    async fn an_oversized_reply_is_cut_off() {
        let huge = "x".repeat(MAX_REPLY_LEN + 1);
        let (base, _requests) = server(http("200 OK", "", &huge)).await;
        let result = Relay::new(&base, false).send(&call("POST", "/secrets", Some("{}")).unwrap()).await;
        assert_eq!(result.unwrap_err(), Failure::ReplyTooLarge);
    }

    #[tokio::test]
    async fn an_oversized_reply_without_length_is_cut_off_too() {
        let huge = "x".repeat(MAX_REPLY_LEN + 1);
        let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{huge}");
        let (base, _requests) = server(response).await;
        let result = Relay::new(&base, false).send(&call("POST", "/secrets", Some("{}")).unwrap()).await;
        assert_eq!(result.unwrap_err(), Failure::ReplyTooLarge);
    }

    #[tokio::test]
    async fn a_reply_that_is_not_text_is_refused() {
        let mut response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(&[0xff, 0xfe]);
        let (base, _requests) = server(response).await;
        let result = Relay::new(&base, false).send(&call("POST", "/secrets", Some("{}")).unwrap()).await;
        assert_eq!(result.unwrap_err(), Failure::NotText);
    }

    #[tokio::test]
    async fn the_production_relay_refuses_plain_http() {
        let (base, mut requests) = server(http("200 OK", "", "{}")).await;
        let result = Relay::new(&base, true).send(&call("POST", "/secrets", Some("{}")).unwrap()).await;
        assert_eq!(result.unwrap_err(), Failure::Network);
        assert!(requests.try_recv().is_err(), "a request went out over plain HTTP");
    }

    #[test]
    fn debug_never_prints_a_body() {
        let checked = call("POST", "/secrets", Some(r#"{"payload":"SEKRIT"}"#)).unwrap();
        assert!(!format!("{checked:?}").contains("SEKRIT"));
    }

    #[test]
    fn debug_never_prints_a_session() {
        let checked = signed_in("POST", "/account/keyring", Some("{}"), SESSION).unwrap();
        assert!(!format!("{checked:?}").contains(SESSION));
    }
}
