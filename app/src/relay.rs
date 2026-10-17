//! The page inside the app has no network access: its only way out is this
//! command, which knows the calls of the relay API and nothing else, and
//! sends them to https://sigylo.net only. Bodies are the JSON the web client
//! already sends to the relay in a browser (sealed envelopes and OPAQUE
//! messages, opaque here); a signed-in call adds its session as a bearer token.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

/// The relay the app talks to.
pub const PRODUCTION: &str = "https://sigylo.net/api";

/// Largest body sent: the relay refuses anything larger anyway.
pub const MAX_BODY_LEN: usize = 100 * 1024;

/// Largest reply read: a maximal envelope in base64 plus JSON fits easily.
pub const MAX_REPLY_LEN: usize = 128 * 1024;

/// Length of a 16-byte id in base64url without padding.
const ID_LEN: usize = 22;

/// Length of a 32-byte session token in base64url without padding.
const SESSION_LEN: usize = 43;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// Why the shell refused a call before anything left the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    UnknownRoute,
    WrongMethod,
    MissingBody,
    UnexpectedBody,
    BodyTooLarge,
    MissingSession,
    UnexpectedSession,
    MalformedSession,
}

/// Why a checked call got no usable reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Network,
    ReplyTooLarge,
    NotText,
}

/// A call of the relay API, checked against its routes.
#[derive(Clone, PartialEq, Eq)]
pub struct Call {
    method: Method,
    path: String,
    body: Option<String>,
    session: Option<String>,
}

impl fmt::Debug for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call").field("method", &self.method).field("path", &self.path).finish_non_exhaustive()
    }
}

fn is_base64url(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_id(segment: &str) -> bool {
    is_base64url(segment, ID_LEN)
}

/// What a route expects: its method, whether it takes a body, whether it needs a session.
struct Shape {
    method: Method,
    body: bool,
    session: bool,
}

const fn shape(method: Method, body: bool, session: bool) -> Option<Shape> {
    Some(Shape { method, body, session })
}

/// The shape of each route of the API, by method too where a path has two.
fn route(method: Method, path: &str) -> Option<Shape> {
    use Method::{Get, Post};
    let segments: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
    match segments.as_slice() {
        ["secrets"] | ["requests"] => shape(Post, true, false),
        ["secrets", id, "open"] if is_id(id) => shape(Post, false, false),
        ["secrets", id, "revoke"] | ["requests", id, "answer"] if is_id(id) => shape(Post, true, false),
        ["requests", id] if is_id(id) => shape(Get, false, false),
        ["account", "register" | "login", "start" | "finish"] => shape(Post, true, false),
        ["account", "logout" | "close"] => shape(Post, false, true),
        ["account", "keyring"] if method == Get => shape(Get, false, true),
        ["account", "keyring"] => shape(Post, true, true),
        _ => None,
    }
}

impl Call {
    pub fn new(method: &str, path: &str, body: Option<String>, session: Option<String>) -> Result<Self, Refusal> {
        let method = match method {
            "GET" => Some(Method::Get),
            "POST" => Some(Method::Post),
            _ => None,
        };
        let expected = route(method.unwrap_or(Method::Post), path).ok_or(Refusal::UnknownRoute)?;
        let method = method.ok_or(Refusal::WrongMethod)?;
        if method != expected.method {
            return Err(Refusal::WrongMethod);
        }
        match (&body, expected.body) {
            (None, true) => return Err(Refusal::MissingBody),
            (Some(_), false) => return Err(Refusal::UnexpectedBody),
            (Some(b), true) if b.len() > MAX_BODY_LEN => return Err(Refusal::BodyTooLarge),
            _ => {}
        }
        match (&session, expected.session) {
            (None, true) => return Err(Refusal::MissingSession),
            (Some(_), false) => return Err(Refusal::UnexpectedSession),
            (Some(s), true) if !is_base64url(s, SESSION_LEN) => return Err(Refusal::MalformedSession),
            _ => {}
        }
        Ok(Self { method, path: path.to_string(), body, session })
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

/// What the page gets back: the relay's status and JSON text, unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

#[derive(Debug)]
pub struct Relay {
    base: String,
    client: reqwest::Client,
}

impl Relay {
    pub fn production() -> Self {
        Self::new(PRODUCTION, true)
    }

    /// A relay at `base`. Redirects are never followed, no cookie is kept,
    /// and with `https_only` nothing is sent over plain HTTP.
    pub fn new(base: &str, https_only: bool) -> Self {
        let client = reqwest::Client::builder()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("Sigylo-App/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("the HTTP client configuration is static");
        Self { base: base.to_string(), client }
    }

    pub async fn send(&self, call: &Call) -> Result<Reply, Failure> {
        let url = format!("{}{}", self.base, call.path);
        let mut request = match call.method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url),
        };
        if let Some(body) = &call.body {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json").body(body.clone());
        }
        if let Some(session) = &call.session {
            request = request.bearer_auth(session);
        }
        let mut response = request.send().await.map_err(|_| Failure::Network)?;
        if response.content_length().is_some_and(|n| n > MAX_REPLY_LEN as u64) {
            return Err(Failure::ReplyTooLarge);
        }
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Failure::Network)? {
            if bytes.len() + chunk.len() > MAX_REPLY_LEN {
                return Err(Failure::ReplyTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(bytes).map_err(|_| Failure::NotText)?;
        Ok(Reply { status, body })
    }
}
