//! The relay's HTTP contract, independent of the Workers runtime so it can
//! be tested natively: routing, JSON bodies, and error → status mapping.
//!
//! All binary fields are base64url without padding. Ids are 16 bytes.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use custody::{
    Answer, CustodyError, DropId, Lifetime, RecipientKeyBlob, Request, Retention, RevocationToken, SealedPayload,
    UnixTime,
};
use serde::{Deserialize, Serialize};

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
            Self::BodyTooLarge | Self::Custody(CustodyError::PayloadTooLarge) => 413,
            Self::Custody(CustodyError::AlreadyExists) => 409,
            Self::Custody(CustodyError::VaultUnavailable) => 503,
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
    id: String,
    payload: String,
    retention: RetentionDto,
    lifetime_seconds: u32,
    revocation_token: Option<String>,
}

/// A validated deposit command.
#[derive(Debug)]
pub struct DepositCommand {
    pub id: DropId,
    pub payload: SealedPayload,
    pub retention: Retention,
    pub lifetime: Lifetime,
    pub revocation: Option<RevocationToken>,
}

pub fn parse_deposit(body: &[u8]) -> Result<DepositCommand, ApiError> {
    let dto: DepositDto = parse(body)?;
    Ok(DepositCommand {
        id: DropId::from_slice(&decode(&dto.id)?)?,
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
    id: String,
    recipient_key: String,
    lifetime_seconds: u32,
}

pub fn parse_request(body: &[u8]) -> Result<Request, ApiError> {
    let dto: RequestDto = parse(body)?;
    Ok(Request {
        id: DropId::from_slice(&decode(&dto.id)?)?,
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
        format!(r#"{{"id":"{ID}","payload":"U0dZAQ","retention":"burn_after_reading","lifetime_seconds":3600{extra}}}"#)
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
    fn error_statuses() {
        assert_eq!(ApiError::Custody(CustodyError::NotFound).status(), 404);
        assert_eq!(ApiError::Custody(CustodyError::AlreadyExists).status(), 409);
        assert_eq!(ApiError::Custody(CustodyError::LifetimeOutOfRange).status(), 400);
        assert_eq!(ApiError::Custody(CustodyError::VaultUnavailable).status(), 503);
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
        fn short_revocation_tokens_are_rejected() {
            assert_eq!(
                parse_revoke(br#"{"token":"AAEC"}"#).unwrap_err(),
                ApiError::Custody(CustodyError::InvalidToken)
            );
        }
    }
}
