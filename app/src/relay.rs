//! The page inside the app has no network access: its only way out is this
//! command, which knows the calls of the relay API and nothing else, and
//! sends them to https://sigylo.net only. Bodies are the JSON the web client
//! already sends to the relay in a browser (sealed envelopes, opaque here),
//! except a file's sealed chunks: they cross the IPC boundary in base64url and
//! travel to and from the relay as raw bytes, as they do in a browser.

use std::fmt;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

/// The relay the app talks to.
pub const PRODUCTION: &str = "https://sigylo.net/api";

/// Largest body sent: the relay refuses anything larger anyway.
pub const MAX_BODY_LEN: usize = 100 * 1024;

/// Largest reply read: a maximal envelope in base64 plus JSON fits easily.
pub const MAX_REPLY_LEN: usize = 128 * 1024;

/// Largest sealed chunk of a file: 1 MiB plus its tag, as the relay stores it.
pub const MAX_CHUNK_LEN: usize = 1024 * 1024 + 16;

/// Length of a 16-byte id in base64url without padding.
const ID_LEN: usize = 22;

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
    MalformedBody,
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
    body: Body,
    binary_reply: bool,
}

/// What goes to the relay with a call.
#[derive(Clone, PartialEq, Eq)]
enum Body {
    None,
    Json(String),
    Chunk(Vec<u8>),
}

/// The body each route takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    None,
    Json,
    Chunk,
}

impl fmt::Debug for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call").field("method", &self.method).field("path", &self.path).finish_non_exhaustive()
    }
}

fn is_id(segment: &str) -> bool {
    segment.len() == ID_LEN && segment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// One of a file's ten chunks, written as the relay writes it: a single digit.
fn is_chunk_index(segment: &str) -> bool {
    matches!(segment.as_bytes(), [b'0'..=b'9'])
}

/// The method, the body and whether the reply is bytes, for each route of the API.
fn route(path: &str) -> Option<(Method, Shape, bool)> {
    let segments: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
    match segments.as_slice() {
        ["secrets"] | ["requests"] => Some((Method::Post, Shape::Json, false)),
        ["secrets", id, "open"] if is_id(id) => Some((Method::Post, Shape::None, false)),
        ["secrets", id, "revoke"] | ["requests", id, "answer"] if is_id(id) => Some((Method::Post, Shape::Json, false)),
        ["requests", id] if is_id(id) => Some((Method::Get, Shape::None, false)),
        ["secrets", id, "chunks", n] if is_id(id) && is_chunk_index(n) => Some((Method::Post, Shape::Chunk, false)),
        ["secrets", id, "chunks", n, "open"] if is_id(id) && is_chunk_index(n) => {
            Some((Method::Post, Shape::Json, true))
        }
        _ => None,
    }
}

/// A sealed chunk, from the canonical base64url the page sends.
fn chunk(text: &str) -> Result<Vec<u8>, Refusal> {
    // Checked before decoding, so a huge string is never decoded.
    if text.len() > (MAX_CHUNK_LEN * 4).div_ceil(3) {
        return Err(Refusal::BodyTooLarge);
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| Refusal::MalformedBody)?;
    match bytes.len() {
        0 => Err(Refusal::MalformedBody),
        n if n > MAX_CHUNK_LEN => Err(Refusal::BodyTooLarge),
        _ => Ok(bytes),
    }
}

impl Call {
    pub fn new(method: &str, path: &str, body: Option<String>) -> Result<Self, Refusal> {
        let (expected, shape, binary_reply) = route(path).ok_or(Refusal::UnknownRoute)?;
        let method = match method {
            "GET" => Method::Get,
            "POST" => Method::Post,
            _ => return Err(Refusal::WrongMethod),
        };
        if method != expected {
            return Err(Refusal::WrongMethod);
        }
        let body = match (body, shape) {
            (None, Shape::None) => Body::None,
            (None, _) => return Err(Refusal::MissingBody),
            (Some(_), Shape::None) => return Err(Refusal::UnexpectedBody),
            (Some(b), Shape::Json) if b.len() > MAX_BODY_LEN => return Err(Refusal::BodyTooLarge),
            (Some(b), Shape::Json) => Body::Json(b),
            (Some(b), Shape::Chunk) => Body::Chunk(chunk(&b)?),
        };
        Ok(Self { method, path: path.to_string(), body, binary_reply })
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

/// What the page gets back: the relay's status and JSON text, unchanged, or
/// a sealed chunk in base64url (`binary`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub binary: bool,
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
        request = match &call.body {
            Body::None => request,
            Body::Json(json) => request.header(reqwest::header::CONTENT_TYPE, "application/json").body(json.clone()),
            Body::Chunk(bytes) => {
                request.header(reqwest::header::CONTENT_TYPE, "application/octet-stream").body(bytes.clone())
            }
        };
        let mut response = request.send().await.map_err(|_| Failure::Network)?;
        let limit = if call.binary_reply { MAX_CHUNK_LEN } else { MAX_REPLY_LEN };
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Err(Failure::ReplyTooLarge);
        }
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Failure::Network)? {
            if bytes.len() + chunk.len() > limit {
                return Err(Failure::ReplyTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        // A chunk comes back only with success; a refusal is the relay's JSON.
        if call.binary_reply && response.status().is_success() {
            return Ok(Reply { status, body: URL_SAFE_NO_PAD.encode(bytes), binary: true });
        }
        let body = String::from_utf8(bytes).map_err(|_| Failure::NotText)?;
        Ok(Reply { status, body, binary: false })
    }
}
