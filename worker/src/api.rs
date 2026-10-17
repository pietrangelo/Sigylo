//! The relay's HTTP contract, independent of the Workers runtime so it can
//! be tested natively: routing, JSON bodies, and error → status mapping.
//!
//! All binary fields are base64url without padding. Ids are 16 bytes and
//! always chosen by the relay: a deposit or request body that carries one is
//! refused, so nobody can put something under an id that already had a life.
//!
//! Account routes (`/api/account/...`) carry OPAQUE messages, never a
//! password; a session travels as `Authorization: Bearer <token>`.

use access::{
    AccessError, CredentialFinalization, CredentialRequest, Keyring, KeyringSnapshot, KeyringVersion, LoginChallenge,
    LoginHandle, RegistrationRecord, RegistrationRequest, RegistrationResponse, Session, SessionToken, Username,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use custody::{
    Answer, CustodyError, DropId, Lifetime, Receipt, RecipientKeyBlob, Retention, RevocationToken, SealedPayload,
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
    RegisterStart,
    RegisterFinish,
    LoginStart,
    LoginFinish,
    Logout,
    ReadKeyring,
    StoreKeyring,
    CloseAccount,
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
    Access(AccessError),
}

impl From<CustodyError> for ApiError {
    fn from(e: CustodyError) -> Self {
        Self::Custody(e)
    }
}

impl From<AccessError> for ApiError {
    fn from(e: AccessError) -> Self {
        Self::Access(e)
    }
}

impl ApiError {
    pub fn status(&self) -> u16 {
        match self {
            Self::NotFound | Self::Custody(CustodyError::NotFound) => 404,
            Self::MethodNotAllowed => 405,
            Self::BodyTooLarge | Self::Custody(CustodyError::PayloadTooLarge) => 413,
            Self::Custody(CustodyError::AlreadyExists) => 409,
            Self::Custody(CustodyError::VaultUnavailable | CustodyError::RandomnessUnavailable) => 503,
            Self::InvalidJson | Self::InvalidEncoding | Self::Custody(_) => 400,
            Self::Access(e) => match e {
                AccessError::NotAuthentic | AccessError::Unauthorized => 401,
                AccessError::AlreadyRegistered | AccessError::Conflict => 409,
                AccessError::KeyringTooLarge => 413,
                AccessError::Throttled => 429,
                AccessError::StoreUnavailable | AccessError::NotConfigured | AccessError::RandomnessUnavailable => 503,
                AccessError::InvalidUsername
                | AccessError::InvalidPassword
                | AccessError::MalformedMessage
                | AccessError::KeyringEmpty => 400,
            },
        }
    }

    /// A stable machine-readable code for the client to localize.
    pub fn code(&self) -> String {
        match self {
            Self::Custody(e) => format!("{e:?}"),
            Self::Access(e) => format!("{e:?}"),
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
        ["account", "register", "start"] => ("POST", Route::RegisterStart),
        ["account", "register", "finish"] => ("POST", Route::RegisterFinish),
        ["account", "login", "start"] => ("POST", Route::LoginStart),
        ["account", "login", "finish"] => ("POST", Route::LoginFinish),
        ["account", "logout"] => ("POST", Route::Logout),
        ["account", "keyring"] if method == "GET" => ("GET", Route::ReadKeyring),
        ["account", "keyring"] => ("POST", Route::StoreKeyring),
        ["account", "close"] => ("POST", Route::CloseAccount),
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

fn username(text: &str) -> Result<Username, ApiError> {
    Ok(Username::new(text)?)
}

fn message<T>(field: &str, parse: impl FnOnce(&[u8]) -> Result<T, AccessError>) -> Result<T, ApiError> {
    Ok(parse(&decode(field)?)?)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaqueStartDto {
    username: String,
    request: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinishDto {
    username: String,
    record: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinishDto {
    handle: String,
    finalization: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreKeyringDto {
    keyring: String,
    version: u64,
}

/// A session presented as `Authorization: Bearer <base64url token>`.
pub fn parse_bearer(header: Option<&str>) -> Result<SessionToken, ApiError> {
    let token = header.and_then(|h| h.strip_prefix("Bearer ")).ok_or(AccessError::Unauthorized)?;
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| AccessError::Unauthorized)?;
    SessionToken::from_slice(&bytes).map_err(|_| ApiError::Access(AccessError::Unauthorized))
}

/// A validated account command. Nothing in it is a password.
#[derive(Debug)]
pub enum AccountCommand {
    RegisterStart(Username, RegistrationRequest),
    RegisterFinish(Username, RegistrationRecord),
    LoginStart(Username, CredentialRequest),
    LoginFinish(LoginHandle, CredentialFinalization),
    Logout(SessionToken),
    ReadKeyring(SessionToken),
    StoreKeyring(SessionToken, Keyring, KeyringVersion),
    Close(SessionToken),
}

fn parse_account(route: &Route, body: &[u8], bearer: Option<&str>) -> Result<AccountCommand, ApiError> {
    Ok(match route {
        Route::RegisterStart => {
            let dto: OpaqueStartDto = parse(body)?;
            AccountCommand::RegisterStart(
                username(&dto.username)?,
                message(&dto.request, RegistrationRequest::from_slice)?,
            )
        }
        Route::RegisterFinish => {
            let dto: RegisterFinishDto = parse(body)?;
            AccountCommand::RegisterFinish(
                username(&dto.username)?,
                message(&dto.record, RegistrationRecord::from_slice)?,
            )
        }
        Route::LoginStart => {
            let dto: OpaqueStartDto = parse(body)?;
            AccountCommand::LoginStart(username(&dto.username)?, message(&dto.request, CredentialRequest::from_slice)?)
        }
        Route::LoginFinish => {
            let dto: LoginFinishDto = parse(body)?;
            AccountCommand::LoginFinish(
                message(&dto.handle, LoginHandle::from_slice)?,
                message(&dto.finalization, CredentialFinalization::from_slice)?,
            )
        }
        Route::Logout => AccountCommand::Logout(parse_bearer(bearer)?),
        Route::ReadKeyring => AccountCommand::ReadKeyring(parse_bearer(bearer)?),
        Route::StoreKeyring => {
            let token = parse_bearer(bearer)?;
            let dto: StoreKeyringDto = parse(body)?;
            AccountCommand::StoreKeyring(
                token,
                message(&dto.keyring, |b| Keyring::new(b.to_vec()))?,
                KeyringVersion(dto.version),
            )
        }
        Route::CloseAccount => AccountCommand::Close(parse_bearer(bearer)?),
        _ => return Err(ApiError::NotFound),
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
    Account(AccountCommand),
}

/// `bearer` is the `Authorization` header, read only by account routes.
pub fn command(route: Route, body: &[u8], bearer: Option<&str>) -> Result<Command, ApiError> {
    Ok(match route {
        Route::Deposit => Command::Deposit(parse_deposit(body)?),
        Route::Open(id) => Command::Open(id),
        Route::Revoke(id) => Command::Revoke(id, parse_revoke(body)?),
        Route::PostRequest => Command::PostRequest(parse_request(body)?),
        Route::FetchRequest(id) => Command::FetchRequest(id),
        Route::AnswerRequest(id) => Command::AnswerRequest(id, parse_answer(body)?),
        account => Command::Account(parse_account(&account, body, bearer)?),
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

#[derive(Debug, Serialize)]
struct RegistrationResponseDto {
    response: String,
}

pub fn registration_response_body(response: &RegistrationResponse) -> String {
    serde_json::to_string(&RegistrationResponseDto { response: encode(response.as_bytes()) }).expect("serializable")
}

#[derive(Debug, Serialize)]
struct LoginChallengeDto {
    handle: String,
    response: String,
}

pub fn login_challenge_body(challenge: &LoginChallenge) -> String {
    serde_json::to_string(&LoginChallengeDto {
        handle: encode(challenge.handle.expose()),
        response: encode(challenge.response.as_bytes()),
    })
    .expect("serializable")
}

#[derive(Debug, Serialize)]
struct SessionDto {
    session: String,
    expires_at: i64,
}

pub fn session_body(session: &Session) -> String {
    serde_json::to_string(&SessionDto { session: encode(session.token.expose()), expires_at: session.expires_at.0 })
        .expect("serializable")
}

#[derive(Debug, Serialize)]
struct KeyringDto {
    keyring: Option<String>,
    version: u64,
}

pub fn keyring_body(snapshot: &KeyringSnapshot) -> String {
    serde_json::to_string(&KeyringDto {
        keyring: snapshot.keyring.as_ref().map(|k| encode(k.as_bytes())),
        version: snapshot.version.0,
    })
    .expect("serializable")
}

#[derive(Debug, Serialize)]
struct VersionDto {
    version: u64,
}

pub fn version_body(version: KeyringVersion) -> String {
    serde_json::to_string(&VersionDto { version: version.0 }).expect("serializable")
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
        assert!(matches!(command(Route::Deposit, deposit_json("").as_bytes(), None), Ok(Command::Deposit(_))));
        assert!(matches!(command(Route::Open(id), b"", None), Ok(Command::Open(i)) if i == id));
        assert!(matches!(command(Route::Revoke(id), token.as_bytes(), None), Ok(Command::Revoke(i, _)) if i == id));
        assert!(matches!(command(Route::PostRequest, request_json("").as_bytes(), None), Ok(Command::PostRequest(_))));
        assert!(matches!(command(Route::FetchRequest(id), b"", None), Ok(Command::FetchRequest(i)) if i == id));
        assert!(
            matches!(command(Route::AnswerRequest(id), answer.as_bytes(), None), Ok(Command::AnswerRequest(i, _)) if i == id)
        );
    }

    #[test]
    fn account_routes_map_to_use_cases() {
        assert_eq!(route("POST", "/api/account/register/start"), Ok(Route::RegisterStart));
        assert_eq!(route("POST", "/api/account/register/finish"), Ok(Route::RegisterFinish));
        assert_eq!(route("POST", "/api/account/login/start"), Ok(Route::LoginStart));
        assert_eq!(route("POST", "/api/account/login/finish"), Ok(Route::LoginFinish));
        assert_eq!(route("POST", "/api/account/logout"), Ok(Route::Logout));
        assert_eq!(route("GET", "/api/account/keyring"), Ok(Route::ReadKeyring));
        assert_eq!(route("POST", "/api/account/keyring"), Ok(Route::StoreKeyring));
        assert_eq!(route("POST", "/api/account/close"), Ok(Route::CloseAccount));
    }

    fn bearer() -> String {
        format!("Bearer {}", encode(&[5; 32]))
    }

    #[test]
    fn account_bodies_become_validated_commands() {
        let start = format!(r#"{{"username":"Ada","request":"{}"}}"#, encode(&[1; RegistrationRequest::LEN]));
        assert!(matches!(
            command(Route::RegisterStart, start.as_bytes(), None),
            Ok(Command::Account(AccountCommand::RegisterStart(name, _))) if name == Username::new("ada").unwrap()
        ));
        let finish = format!(r#"{{"username":"ada","record":"{}"}}"#, encode(&[1; RegistrationRecord::LEN]));
        assert!(matches!(
            command(Route::RegisterFinish, finish.as_bytes(), None),
            Ok(Command::Account(AccountCommand::RegisterFinish(..)))
        ));
        let login = format!(r#"{{"username":"ada","request":"{}"}}"#, encode(&[1; CredentialRequest::LEN]));
        assert!(matches!(
            command(Route::LoginStart, login.as_bytes(), None),
            Ok(Command::Account(AccountCommand::LoginStart(..)))
        ));
        let finish = format!(
            r#"{{"handle":"{}","finalization":"{}"}}"#,
            encode(&[2; LoginHandle::LEN]),
            encode(&[3; CredentialFinalization::LEN])
        );
        assert!(matches!(
            command(Route::LoginFinish, finish.as_bytes(), None),
            Ok(Command::Account(AccountCommand::LoginFinish(..)))
        ));
        let store = format!(r#"{{"keyring":"{}","version":4}}"#, encode(b"SGY\x01 sealed keyring"));
        assert!(matches!(
            command(Route::StoreKeyring, store.as_bytes(), Some(&bearer())),
            Ok(Command::Account(AccountCommand::StoreKeyring(_, _, KeyringVersion(4))))
        ));
        for route in [Route::Logout, Route::ReadKeyring, Route::CloseAccount] {
            assert!(command(route, b"", Some(&bearer())).is_ok());
        }
    }

    #[test]
    fn account_answers_carry_only_protocol_bytes() {
        let challenge = LoginChallenge {
            handle: LoginHandle::from_array([0; 16]),
            response: access::CredentialResponse::from_slice(&[0; access::CredentialResponse::LEN]).unwrap(),
        };
        let body = login_challenge_body(&challenge);
        assert!(body.starts_with(r#"{"handle":"AAAAAAAAAAAAAAAAAAAAAA","response":""#));
        let session = Session { token: SessionToken::from_array([0; 32]), expires_at: access::UnixTime(7) };
        assert_eq!(session_body(&session), format!(r#"{{"session":"{}","expires_at":7}}"#, encode(&[0; 32])));
        let empty = KeyringSnapshot { keyring: None, version: KeyringVersion::NONE };
        assert_eq!(keyring_body(&empty), r#"{"keyring":null,"version":0}"#);
    }

    #[test]
    fn account_error_statuses() {
        assert_eq!(ApiError::Access(AccessError::NotAuthentic).status(), 401);
        assert_eq!(ApiError::Access(AccessError::Unauthorized).status(), 401);
        assert_eq!(ApiError::Access(AccessError::AlreadyRegistered).status(), 409);
        assert_eq!(ApiError::Access(AccessError::Conflict).status(), 409);
        assert_eq!(ApiError::Access(AccessError::Throttled).status(), 429);
        assert_eq!(ApiError::Access(AccessError::NotConfigured).status(), 503);
        assert_eq!(ApiError::Access(AccessError::KeyringTooLarge).status(), 413);
        assert_eq!(ApiError::Access(AccessError::Conflict).body(), r#"{"error":"Conflict"}"#);
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
                assert!(command(route.clone(), body, None).is_err(), "{route:?}");
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
        fn account_routes_refuse_other_methods() {
            for path in ["/api/account/login/start", "/api/account/register/finish", "/api/account/close"] {
                assert_eq!(route("GET", path), Err(ApiError::MethodNotAllowed), "{path}");
            }
            assert_eq!(route("PUT", "/api/account/keyring"), Err(ApiError::MethodNotAllowed));
            assert_eq!(route("POST", "/api/account"), Err(ApiError::NotFound));
        }

        #[test]
        fn a_body_can_never_carry_a_password() {
            // OPAQUE needs none, so the relay refuses any field it does not know.
            let sneaky = format!(
                r#"{{"username":"ada","request":"{}","password":"hunter2hunter2"}}"#,
                encode(&[1; RegistrationRequest::LEN])
            );
            assert_eq!(command(Route::RegisterStart, sneaky.as_bytes(), None).unwrap_err(), ApiError::InvalidJson);
        }

        #[test]
        fn wrong_sized_protocol_messages_are_refused_before_the_store() {
            let short = format!(r#"{{"username":"ada","request":"{}"}}"#, encode(&[1; 95]));
            assert_eq!(
                command(Route::LoginStart, short.as_bytes(), None).unwrap_err(),
                ApiError::Access(AccessError::MalformedMessage)
            );
            let bad_name = format!(r#"{{"username":"a b","request":"{}"}}"#, encode(&[1; 96]));
            assert_eq!(
                command(Route::LoginStart, bad_name.as_bytes(), None).unwrap_err(),
                ApiError::Access(AccessError::InvalidUsername)
            );
            let empty = r#"{"keyring":"","version":0}"#.to_string();
            assert_eq!(
                command(Route::StoreKeyring, empty.as_bytes(), Some(&bearer())).unwrap_err(),
                ApiError::Access(AccessError::KeyringEmpty)
            );
        }

        #[test]
        fn sessions_need_a_well_formed_bearer_token() {
            for header in
                [None, Some(""), Some("Bearer"), Some("Basic Zm9vOmJhcg"), Some("bearer AAAA"), Some("Bearer AAEC")]
            {
                assert_eq!(
                    command(Route::ReadKeyring, b"", header).unwrap_err(),
                    ApiError::Access(AccessError::Unauthorized),
                    "{header:?}"
                );
            }
            let padded = format!("{}=", bearer());
            assert_eq!(parse_bearer(Some(&padded)).unwrap_err(), ApiError::Access(AccessError::Unauthorized));
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
