//! The relay's HTTP contract, independent of the Workers runtime so it can
//! be tested natively: routing, JSON bodies, and error → status mapping.
//!
//! All binary fields are base64url without padding. Ids are 16 bytes and
//! always chosen by the relay: a deposit or request body that carries one is
//! refused, so nobody can put something under an id that already had a life.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use custody::{
    Answer, CustodyError, DropId, Lifetime, Receipt, RecipientKeyBlob, Retention, RevocationToken, SealedPayload,
    UnixTime,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Largest request body accepted (a maximal payload in base64 plus JSON).
pub const MAX_BODY_LEN: usize = 100 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Deposit,
    Open(DropId),
    Revoke(DropId),
    PostRequest,
    FetchRequest(DropId),
    AnswerRequest(DropId),
}

/// Why a request was refused before reaching the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    NotFound,
    MethodNotAllowed,
    /// A browser page of another origin tried to call the relay.
    CrossOrigin,
    BodyTooLarge,
    InvalidJson,
    InvalidEncoding,
    Custody(CustodyError),
}

impl From<CustodyError> for ApiError {
    fn from(e: CustodyError) -> Self {
        Self::Custody(e)
    }
}

impl ApiError {
    pub fn status(&self) -> u16 {
        match self {
            Self::NotFound | Self::Custody(CustodyError::NotFound) => 404,
            Self::MethodNotAllowed => 405,
            Self::CrossOrigin => 403,
            Self::BodyTooLarge | Self::Custody(CustodyError::PayloadTooLarge) => 413,
            Self::Custody(CustodyError::AlreadyExists) => 409,
            Self::Custody(CustodyError::VaultUnavailable | CustodyError::RandomnessUnavailable) => 503,
            Self::InvalidJson | Self::InvalidEncoding | Self::Custody(_) => 400,
        }
    }

    /// A stable machine-readable code for the client to localize.
    pub fn code(&self) -> String {
        match self {
            Self::Custody(e) => format!("{e:?}"),
            other => format!("{other:?}"),
        }
    }

    pub fn body(&self) -> String {
        serde_json::json!({ "error": self.code() }).to_string()
    }
}

/// Refuse a body whose declared length is already too large, before reading it.
pub fn check_declared_length(content_length: Option<&str>) -> Result<(), ApiError> {
    match content_length.map(|v| v.trim().parse::<u64>()) {
        Some(Ok(n)) if n > MAX_BODY_LEN as u64 => Err(ApiError::BodyTooLarge),
        _ => Ok(()),
    }
}

/// Refuse calls from pages of other origins. Browsers attach `Origin` to every
/// cross-origin request (and to same-origin POSTs), so a page elsewhere cannot
/// use its visitors' browsers as a botnet against the relay. Clients that send
/// no `Origin`, such as the app's shell, are not browsers acting for a page.
pub fn check_origin(origin: Option<&str>, own_origin: &str) -> Result<(), ApiError> {
    match origin {
        Some(origin) if origin != own_origin => Err(ApiError::CrossOrigin),
        _ => Ok(()),
    }
}

/// The key a client address is throttled under: an IPv4 address as is, an
/// IPv6 address by its /64, the network one subscriber usually gets, so
/// rotating addresses inside it does not buy a fresh allowance. Anything
/// unparsable shares a single bucket.
pub fn limiter_key(address: &str) -> String {
    match address.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        Err(_) => "unknown".into(),
    }
}

fn id_segment(segment: &str) -> Result<DropId, ApiError> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|_| ApiError::NotFound)?;
    DropId::from_slice(&bytes).map_err(|_| ApiError::NotFound)
}

/// Map method and path to a route. Anything unexpected is a plain 404/405.
pub fn route(method: &str, path: &str) -> Result<Route, ApiError> {
    let segments: Vec<&str> = path.strip_prefix("/api/").ok_or(ApiError::NotFound)?.split('/').collect();
    let (expected, route) = match segments.as_slice() {
        ["secrets"] => ("POST", Route::Deposit),
        ["secrets", id, "open"] => ("POST", Route::Open(id_segment(id)?)),
        ["secrets", id, "revoke"] => ("POST", Route::Revoke(id_segment(id)?)),
        ["requests"] => ("POST", Route::PostRequest),
        ["requests", id] => ("GET", Route::FetchRequest(id_segment(id)?)),
        ["requests", id, "answer"] => ("POST", Route::AnswerRequest(id_segment(id)?)),
        _ => return Err(ApiError::NotFound),
    };
    if method == expected { Ok(route) } else { Err(ApiError::MethodNotAllowed) }
}

fn decode(field: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD.decode(field).map_err(|_| ApiError::InvalidEncoding)
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn parse<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, ApiError> {
    if body.len() > MAX_BODY_LEN {
        return Err(ApiError::BodyTooLarge);
    }
    serde_json::from_slice(body).map_err(|_| ApiError::InvalidJson)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RetentionDto {
    BurnAfterReading,
    UntilExpiry,
}

impl From<RetentionDto> for Retention {
    fn from(r: RetentionDto) -> Self {
        match r {
            RetentionDto::BurnAfterReading => Retention::BurnAfterReading,
            RetentionDto::UntilExpiry => Retention::UntilExpiry,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositDto {
    payload: String,
    retention: RetentionDto,
    lifetime_seconds: u32,
    revocation_token: Option<String>,
}

/// A validated deposit command.
#[derive(Debug)]
pub struct DepositCommand {
    pub payload: SealedPayload,
    pub retention: Retention,
    pub lifetime: Lifetime,
    pub revocation: Option<RevocationToken>,
}

pub fn parse_deposit(body: &[u8]) -> Result<DepositCommand, ApiError> {
    let dto: DepositDto = parse(body)?;
    Ok(DepositCommand {
        payload: SealedPayload::new(decode(&dto.payload)?)?,
        retention: dto.retention.into(),
        lifetime: Lifetime::from_seconds(dto.lifetime_seconds)?,
        revocation: dto
            .revocation_token
            .map(|t| Ok::<_, ApiError>(RevocationToken::from_slice(&decode(&t)?)?))
            .transpose()?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeDto {
    token: String,
}

pub fn parse_revoke(body: &[u8]) -> Result<RevocationToken, ApiError> {
    let dto: RevokeDto = parse(body)?;
    Ok(RevocationToken::from_slice(&decode(&dto.token)?)?)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestDto {
    recipient_key: String,
    lifetime_seconds: u32,
}

/// A validated request command: the recipient's public key and how long it stays.
#[derive(Debug)]
pub struct RequestCommand {
    pub recipient_key: RecipientKeyBlob,
    pub lifetime: Lifetime,
}

pub fn parse_request(body: &[u8]) -> Result<RequestCommand, ApiError> {
    let dto: RequestDto = parse(body)?;
    Ok(RequestCommand {
        recipient_key: RecipientKeyBlob::new(decode(&dto.recipient_key)?)?,
        lifetime: Lifetime::from_seconds(dto.lifetime_seconds)?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerDto {
    payload: String,
    retention: RetentionDto,
    lifetime_seconds: u32,
}

pub fn parse_answer(body: &[u8]) -> Result<Answer, ApiError> {
    let dto: AnswerDto = parse(body)?;
    Ok(Answer {
        payload: SealedPayload::new(decode(&dto.payload)?)?,
        retention: dto.retention.into(),
        lifetime: Lifetime::from_seconds(dto.lifetime_seconds)?,
    })
}

/// Everything a route needs, validated before the vault is touched: a
/// malformed body never costs a database connection.
#[derive(Debug)]
pub enum Command {
    Deposit(DepositCommand),
    Open(DropId),
    Revoke(DropId, RevocationToken),
    PostRequest(RequestCommand),
    FetchRequest(DropId),
    AnswerRequest(DropId, Answer),
}

pub fn command(route: Route, body: &[u8]) -> Result<Command, ApiError> {
    Ok(match route {
        Route::Deposit => Command::Deposit(parse_deposit(body)?),
        Route::Open(id) => Command::Open(id),
        Route::Revoke(id) => Command::Revoke(id, parse_revoke(body)?),
        Route::PostRequest => Command::PostRequest(parse_request(body)?),
        Route::FetchRequest(id) => Command::FetchRequest(id),
        Route::AnswerRequest(id) => Command::AnswerRequest(id, parse_answer(body)?),
    })
}

#[derive(Debug, Serialize)]
struct ReceiptDto {
    id: String,
    expires_at: i64,
}

/// The id the relay chose and when it expires.
pub fn receipt_body(receipt: Receipt) -> String {
    serde_json::to_string(&ReceiptDto { id: encode(receipt.id.as_bytes()), expires_at: receipt.expires_at.0 })
        .expect("serializable")
}

#[derive(Debug, Serialize)]
struct ExpiresDto {
    expires_at: i64,
}

pub fn expires_body(expires: UnixTime) -> String {
    serde_json::to_string(&ExpiresDto { expires_at: expires.0 }).expect("serializable")
}

#[derive(Debug, Serialize)]
struct OpenedDto {
    payload: String,
    burned: bool,
}

pub fn opened_body(opened: custody::Opened) -> String {
    serde_json::to_string(&OpenedDto { payload: encode(opened.payload.as_bytes()), burned: opened.burned })
        .expect("serializable")
}

#[derive(Debug, Serialize)]
struct PostedRequestDto {
    recipient_key: String,
    expires_at: i64,
}

pub fn posted_request_body(posted: custody::PostedRequest) -> String {
    serde_json::to_string(&PostedRequestDto {
        recipient_key: encode(posted.recipient_key.as_bytes()),
        expires_at: posted.expires_at.0,
    })
    .expect("serializable")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "AAECAwQFBgcICQoLDA0ODw"; // bytes 0..16

    fn deposit_json(extra: &str) -> String {
        format!(r#"{{"payload":"U0dZAQ","retention":"burn_after_reading","lifetime_seconds":3600{extra}}}"#)
    }

    fn request_json(extra: &str) -> String {
        let key = encode(&[7; RecipientKeyBlob::LEN]);
        format!(r#"{{"recipient_key":"{key}","lifetime_seconds":3600{extra}}}"#)
    }

    #[test]
    fn routes_map_to_use_cases() {
        let id = id_segment(ID).unwrap();
        assert_eq!(route("POST", "/api/secrets"), Ok(Route::Deposit));
        assert_eq!(route("POST", &format!("/api/secrets/{ID}/open")), Ok(Route::Open(id)));
        assert_eq!(route("POST", &format!("/api/secrets/{ID}/revoke")), Ok(Route::Revoke(id)));
        assert_eq!(route("POST", "/api/requests"), Ok(Route::PostRequest));
        assert_eq!(route("GET", &format!("/api/requests/{ID}")), Ok(Route::FetchRequest(id)));
        assert_eq!(route("POST", &format!("/api/requests/{ID}/answer")), Ok(Route::AnswerRequest(id)));
    }

    #[test]
    fn deposit_body_becomes_a_validated_command() {
        let cmd = parse_deposit(deposit_json("").as_bytes()).unwrap();
        assert_eq!(cmd.retention, Retention::BurnAfterReading);
        assert_eq!(cmd.lifetime.seconds(), 3600);
        assert_eq!(cmd.payload.as_bytes(), b"SGY\x01");
        assert!(cmd.revocation.is_none());
    }

    #[test]
    fn request_body_becomes_a_validated_command() {
        let cmd = parse_request(request_json("").as_bytes()).unwrap();
        assert_eq!(cmd.recipient_key.as_bytes(), &[7; RecipientKeyBlob::LEN][..]);
        assert_eq!(cmd.lifetime.seconds(), 3600);
    }

    #[test]
    fn receipts_carry_the_relay_chosen_id() {
        let receipt = Receipt { id: id_segment(ID).unwrap(), expires_at: UnixTime(42) };
        assert_eq!(receipt_body(receipt), format!(r#"{{"id":"{ID}","expires_at":42}}"#));
    }

    #[test]
    fn every_route_becomes_a_command() {
        let id = id_segment(ID).unwrap();
        let token = format!(r#"{{"token":"{}"}}"#, encode(&[1; 32]));
        let answer = r#"{"payload":"U0dZAQ","retention":"until_expiry","lifetime_seconds":300}"#;
        assert!(matches!(command(Route::Deposit, deposit_json("").as_bytes()), Ok(Command::Deposit(_))));
        assert!(matches!(command(Route::Open(id), b""), Ok(Command::Open(i)) if i == id));
        assert!(matches!(command(Route::Revoke(id), token.as_bytes()), Ok(Command::Revoke(i, _)) if i == id));
        assert!(matches!(command(Route::PostRequest, request_json("").as_bytes()), Ok(Command::PostRequest(_))));
        assert!(matches!(command(Route::FetchRequest(id), b""), Ok(Command::FetchRequest(i)) if i == id));
        assert!(
            matches!(command(Route::AnswerRequest(id), answer.as_bytes()), Ok(Command::AnswerRequest(i, _)) if i == id)
        );
    }

    #[test]
    fn error_statuses() {
        assert_eq!(ApiError::Custody(CustodyError::NotFound).status(), 404);
        assert_eq!(ApiError::Custody(CustodyError::AlreadyExists).status(), 409);
        assert_eq!(ApiError::Custody(CustodyError::LifetimeOutOfRange).status(), 400);
        assert_eq!(ApiError::Custody(CustodyError::VaultUnavailable).status(), 503);
        assert_eq!(ApiError::Custody(CustodyError::RandomnessUnavailable).status(), 503);
        assert_eq!(ApiError::Custody(CustodyError::NotFound).body(), r#"{"error":"NotFound"}"#);
    }

    mod adversary {
        use super::*;

        #[test]
        fn wrong_methods_are_refused_so_prefetchers_cannot_burn() {
            // A link preview bot issues GET/HEAD: it must never reach `open`.
            for method in ["GET", "HEAD", "OPTIONS", "PUT"] {
                assert_eq!(route(method, &format!("/api/secrets/{ID}/open")), Err(ApiError::MethodNotAllowed));
            }
        }

        #[test]
        fn odd_paths_are_not_found() {
            for path in [
                "/api/secrets/",
                "/api/secrets/../requests",
                &format!("/api/secrets/{ID}/open/extra"),
                &format!("/api/secrets/{ID}%2Fopen"),
                "/api/secrets/AAEC/open", // 3-byte id
                "/api/secrets/not*base64/open",
                "/secrets",
                "/api//secrets",
            ] {
                assert_eq!(route("POST", path), Err(ApiError::NotFound), "{path}");
            }
        }

        #[test]
        fn malformed_bodies_are_rejected() {
            assert_eq!(parse_deposit(b"not json").unwrap_err(), ApiError::InvalidJson);
            let unknown = deposit_json(r#","owner":"me@example.com""#);
            assert_eq!(parse_deposit(unknown.as_bytes()).unwrap_err(), ApiError::InvalidJson);
            let bad_retention = deposit_json("").replace("burn_after_reading", "forever");
            assert_eq!(parse_deposit(bad_retention.as_bytes()).unwrap_err(), ApiError::InvalidJson);
            let padded = deposit_json("").replace("U0dZAQ", "U0dZAQ==");
            assert_eq!(parse_deposit(padded.as_bytes()).unwrap_err(), ApiError::InvalidEncoding);
            let forever = deposit_json("").replace("3600", "31536000");
            assert_eq!(
                parse_deposit(forever.as_bytes()).unwrap_err(),
                ApiError::Custody(CustodyError::LifetimeOutOfRange)
            );
        }

        #[test]
        fn oversized_bodies_are_rejected_before_parsing() {
            let huge = vec![b' '; MAX_BODY_LEN + 1];
            assert_eq!(parse_deposit(&huge).unwrap_err(), ApiError::BodyTooLarge);
            assert_eq!(ApiError::BodyTooLarge.status(), 413);
        }

        #[test]
        fn the_client_cannot_choose_the_id() {
            // A reader who burned a secret would otherwise refill its link with
            // a re-sealed copy or a forgery, and the recipient would not notice.
            let deposit = deposit_json(&format!(r#","id":"{ID}""#));
            assert_eq!(parse_deposit(deposit.as_bytes()).unwrap_err(), ApiError::InvalidJson);
            let request = request_json(&format!(r#","id":"{ID}""#));
            assert_eq!(parse_request(request.as_bytes()).unwrap_err(), ApiError::InvalidJson);
        }

        #[test]
        fn malformed_bodies_are_refused_before_the_vault_is_touched() {
            let id = id_segment(ID).unwrap();
            for (route, body) in [
                (Route::Deposit, &b"{}"[..]),
                (Route::Revoke(id), b"{\"token\":\"AAEC\"}"),
                (Route::PostRequest, b"[]"),
                (Route::AnswerRequest(id), b"null"),
            ] {
                assert!(command(route.clone(), body).is_err(), "{route:?}");
            }
        }

        #[test]
        fn a_declared_oversized_body_is_refused_before_it_is_read() {
            assert_eq!(check_declared_length(Some("104857600")), Err(ApiError::BodyTooLarge));
            assert_eq!(check_declared_length(Some(&(MAX_BODY_LEN + 1).to_string())), Err(ApiError::BodyTooLarge));
            assert_eq!(check_declared_length(Some(&MAX_BODY_LEN.to_string())), Ok(()));
            // Missing or odd headers fall through to the check on the bytes actually read.
            assert_eq!(check_declared_length(None), Ok(()));
            assert_eq!(check_declared_length(Some("lots")), Ok(()));
        }

        #[test]
        fn pages_of_other_sites_cannot_call_the_relay() {
            // A page elsewhere could otherwise make its visitors' browsers deposit
            // junk from thousands of addresses, past the per-address limit.
            let own = "https://sigylo.net";
            for origin in ["https://evil.example", "null", "http://sigylo.net", "https://sigylo.net.evil.example"] {
                assert_eq!(check_origin(Some(origin), own), Err(ApiError::CrossOrigin), "{origin}");
            }
            assert_eq!(ApiError::CrossOrigin.status(), 403);
            // Our own pages, and clients that send no Origin (the app's shell), pass.
            assert_eq!(check_origin(Some(own), own), Ok(()));
            assert_eq!(check_origin(None, own), Ok(()));
        }

        #[test]
        fn one_ipv6_network_is_one_client_for_the_limiter() {
            // A /64 is what one subscriber gets: rotating addresses inside it
            // must not buy a fresh allowance each time.
            let a = limiter_key("2001:db8:1:2:aaaa::1");
            assert_eq!(a, limiter_key("2001:db8:1:2:ffff:ffff:ffff:ffff"));
            assert_ne!(a, limiter_key("2001:db8:1:3::1"));
            assert_eq!(limiter_key("203.0.113.7"), "203.0.113.7");
            assert_ne!(limiter_key("203.0.113.7"), limiter_key("203.0.113.8"));
            // An IPv4-mapped address is the IPv4 client it maps.
            assert_eq!(limiter_key("::ffff:203.0.113.7"), "203.0.113.7");
            // Missing or garbled headers share one bucket rather than escape it.
            assert_eq!(limiter_key(""), limiter_key("not an address"));
        }

        #[test]
        fn short_revocation_tokens_are_rejected() {
            assert_eq!(
                parse_revoke(br#"{"token":"AAEC"}"#).unwrap_err(),
                ApiError::Custody(CustodyError::InvalidToken)
            );
        }
    }
}
