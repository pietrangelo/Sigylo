//! The relay's HTTP contract, independent of the Workers runtime so it can
//! be tested natively: routing, JSON bodies, and error → status mapping.
//!
//! All binary fields are base64url without padding. Ids are 16 bytes and
//! always chosen by the relay: a deposit or request body that carries one is
//! refused, so nobody can put something under an id that already had a life.
//!
//! Account routes (`/api/account/...`) carry OPAQUE messages, never a
//! password; a session travels as `Authorization: Bearer <token>`.
//!
//! File chunks are the exception to JSON: a chunk travels as the raw request
//! body (`POST /api/secrets/{id}/chunks/{n}`) and comes back as the raw
//! response body (`POST /api/secrets/{id}/chunks/{n}/open`), so a 1 MiB chunk
//! costs no base64 work in a Worker that has 10 ms of CPU per request.

use access::{
    AccessError, CredentialFinalization, CredentialRequest, DevicePass, Keyring, KeyringSnapshot, KeyringVersion,
    LoginChallenge, LoginHandle, RegistrationRecord, RegistrationRequest, RegistrationResponse, Session, SessionToken,
    Username,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use custody::{
    Answer, ChunkCount, ChunkIndex, ClaimToken, CustodyError, DropId, Lifetime, MAX_CHUNK_LEN, Receipt,
    RecipientKeyBlob, RequestReceipt, Retention, RevocationToken, SealedChunk, SealedPayload,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Largest JSON request body accepted (a maximal payload in base64 plus JSON).
pub const MAX_BODY_LEN: usize = 100 * 1024;

/// Most garbage batches one cron run deletes from R2 ([`custody::GARBAGE_BATCH`]
/// objects each): the run waits on the vault and R2 and stays within the
/// free plan's 10 ms of CPU.
pub const GARBAGE_ROUNDS: u32 = 5;
/// Wall time after which a cron run starts no new garbage batch.
pub const GARBAGE_MILLIS: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Deposit,
    Open(DropId),
    Revoke(DropId),
    PutChunk(DropId, ChunkIndex),
    OpenChunk(DropId, ChunkIndex),
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
    LogoutEverywhere,
    Canary,
}

impl Route {
    /// The largest body this route reads: a raw chunk, or a JSON document.
    pub fn max_body_len(&self) -> usize {
        match self {
            Self::PutChunk(..) => MAX_CHUNK_LEN,
            _ => MAX_BODY_LEN,
        }
    }

    /// Whether the route reads a request body at all. The others never read
    /// one, so nothing a client sends with them is buffered.
    pub fn takes_body(&self) -> bool {
        !matches!(
            self,
            Self::Open(_)
                | Self::FetchRequest(_)
                | Self::Logout
                | Self::LogoutEverywhere
                | Self::ReadKeyring
                | Self::CloseAccount
                | Self::Canary
        )
    }
}

/// Why a request was refused before reaching the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    NotFound,
    MethodNotAllowed,
    /// A browser page of another origin tried to call the relay.
    CrossOrigin,
    /// A body came without a `Content-Length` to check before reading it.
    LengthRequired,
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
            Self::CrossOrigin => 403,
            Self::LengthRequired => 411,
            Self::BodyTooLarge | Self::Custody(CustodyError::PayloadTooLarge) => 413,
            Self::Custody(CustodyError::AlreadyExists) => 409,
            Self::Custody(CustodyError::VaultUnavailable | CustodyError::RandomnessUnavailable) => 503,
            Self::Custody(CustodyError::StorageFull) => 507,
            Self::InvalidJson | Self::InvalidEncoding | Self::Custody(_) => 400,
            Self::Access(e) => match e {
                AccessError::NotAuthentic | AccessError::Unauthorized => 401,
                AccessError::AlreadyRegistered | AccessError::Conflict => 409,
                AccessError::KeyringTooLarge => 413,
                AccessError::Throttled => 429,
                AccessError::StorageFull => 507,
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

/// Refuse a body before reading it unless it declares its length, in plain
/// decimal, and that length fits its route. Without the header (chunked
/// encoding) the Worker would buffer whatever came, up to Cloudflare's 100 MB.
pub fn check_declared_length(route: &Route, content_length: Option<&str>) -> Result<(), ApiError> {
    let declared = content_length.map(str::trim).filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()));
    match declared.map(str::parse::<u64>) {
        Some(Ok(n)) if n <= route.max_body_len() as u64 => Ok(()),
        // All digits but past u64: too large in any case.
        Some(_) => Err(ApiError::BodyTooLarge),
        None => Err(ApiError::LengthRequired),
    }
}

/// Refuse calls from pages of other origins, so a page elsewhere cannot use
/// its visitors' browsers as a botnet against the relay. Browsers attach
/// `Origin` to cross-origin `fetch` calls and to POSTs, but not to no-cors
/// GETs such as `<img src>` or a prefetch: for those, `Sec-Fetch-Site` still
/// tells who asked, and anything but `same-origin` or `none` (an address the
/// user typed) is refused. Clients that send neither header, such as the
/// app's shell or curl, are not browsers acting for a page.
pub fn check_origin(origin: Option<&str>, fetch_site: Option<&str>, own_origin: &str) -> Result<(), ApiError> {
    match (origin, fetch_site) {
        (Some(origin), _) if origin != own_origin => Err(ApiError::CrossOrigin),
        (_, Some(site)) if site != "same-origin" && site != "none" => Err(ApiError::CrossOrigin),
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

/// The /48 an IPv6 client sits in, counted against a second, larger
/// allowance for writes and for reads alike: one site, or one free tunnel,
/// holds 65 536 /64s. None for IPv4 and anything unparsable, which have only
/// [`limiter_key`].
pub fn network_key(address: &str) -> Option<String> {
    let v6 = match address.trim().parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => v6,
        _ => return None,
    };
    let s = v6.segments();
    Some(format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]))
}

/// The binding (wrangler.toml) that counts a [`network_key`]: writes and
/// reads each have their own /48 allowance, as they have per address.
pub fn network_binding(write: bool) -> &'static str {
    if write { "NETWORK_WRITE_LIMITER" } else { "NETWORK_READ_LIMITER" }
}

/// The binding (wrangler.toml) that counts login and registration attempts
/// per account and budget in Cloudflare's memory, per location. Fails closed.
pub const LOGIN_BINDING: &str = "LOGIN_LIMITER";

/// Login and registration attempts per account and per minute, counted in
/// the accounts object for the whole world, behind the same limit in
/// [`LOGIN_BINDING`].
pub const LOGIN_ATTEMPTS_PER_MINUTE: u16 = 10;

/// Whether a call waits, given the limiter's verdict (`None` when it did not
/// answer). Writes fail closed: they fill the vault and spend its daily
/// allowance of rows. Reads fail open, so a broken limiter never keeps a
/// recipient from a secret.
pub fn throttled(write: bool, allowed: Option<bool>) -> bool {
    allowed.map_or(write, |ok| !ok)
}

fn id_segment(segment: &str) -> Result<DropId, ApiError> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|_| ApiError::NotFound)?;
    DropId::from_slice(&bytes).map_err(|_| ApiError::NotFound)
}

/// A chunk index in canonical decimal: "0" to "9", no sign, no leading zero.
fn index_segment(segment: &str) -> Result<ChunkIndex, ApiError> {
    let canonical = !segment.is_empty()
        && segment.len() <= 2
        && segment.bytes().all(|b| b.is_ascii_digit())
        && (segment == "0" || !segment.starts_with('0'));
    let index = segment.parse::<u16>().ok().filter(|_| canonical).ok_or(ApiError::NotFound)?;
    ChunkIndex::new(index).map_err(|_| ApiError::NotFound)
}

/// Map method and path to a route. Anything unexpected is a plain 404/405.
pub fn route(method: &str, path: &str) -> Result<Route, ApiError> {
    let segments: Vec<&str> = path.strip_prefix("/api/").ok_or(ApiError::NotFound)?.split('/').collect();
    let (expected, route) = match segments.as_slice() {
        ["secrets"] => ("POST", Route::Deposit),
        ["secrets", id, "open"] => ("POST", Route::Open(id_segment(id)?)),
        ["secrets", id, "revoke"] => ("POST", Route::Revoke(id_segment(id)?)),
        ["secrets", id, "chunks", n] => ("POST", Route::PutChunk(id_segment(id)?, index_segment(n)?)),
        ["secrets", id, "chunks", n, "open"] => ("POST", Route::OpenChunk(id_segment(id)?, index_segment(n)?)),
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
        ["account", "logout", "everywhere"] => ("POST", Route::LogoutEverywhere),
        ["account", "canary"] => ("GET", Route::Canary),
        _ => return Err(ApiError::NotFound),
    };
    if method == expected { Ok(route) } else { Err(ApiError::MethodNotAllowed) }
}

/// What the accounts' Durable Object lets in: only the relay's link, a POST
/// to `/call` (`vault_adapters::DurableLink`). Anything else never reaches
/// the ledger.
pub fn accounts_door(method: &str, path: &str) -> Result<(), ApiError> {
    if method != "POST" {
        return Err(ApiError::MethodNotAllowed);
    }
    if path != "/call" {
        return Err(ApiError::NotFound);
    }
    Ok(())
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
    chunks: Option<u16>,
}

/// A validated deposit command. With `chunks`, the payload is a file's
/// sealed manifest and that many chunks follow.
#[derive(Debug)]
pub struct DepositCommand {
    pub payload: SealedPayload,
    pub retention: Retention,
    pub lifetime: Lifetime,
    pub revocation: Option<RevocationToken>,
    pub chunks: Option<ChunkCount>,
}

fn chunk_count(chunks: Option<u16>) -> Result<Option<ChunkCount>, ApiError> {
    Ok(chunks.map(ChunkCount::new).transpose()?)
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
        chunks: chunk_count(dto.chunks)?,
    })
}

/// A raw chunk body, checked against the chunk bounds.
pub fn parse_chunk(body: &[u8]) -> Result<SealedChunk, ApiError> {
    if body.len() > MAX_CHUNK_LEN {
        return Err(ApiError::BodyTooLarge);
    }
    Ok(SealedChunk::new(body.to_vec())?)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenChunkDto {
    claim: Option<String>,
}

/// The claim token a burn-after-reading file's chunks need, if any.
pub fn parse_open_chunk(body: &[u8]) -> Result<Option<ClaimToken>, ApiError> {
    let dto: OpenChunkDto = parse(body)?;
    dto.claim.map(|c| Ok(ClaimToken::from_slice(&decode(&c)?)?)).transpose()
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
    chunks: Option<u16>,
}

pub fn parse_answer(body: &[u8]) -> Result<Answer, ApiError> {
    let dto: AnswerDto = parse(body)?;
    Ok(Answer {
        payload: SealedPayload::new(decode(&dto.payload)?)?,
        retention: dto.retention.into(),
        lifetime: Lifetime::from_seconds(dto.lifetime_seconds)?,
        chunks: chunk_count(dto.chunks)?,
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
struct LoginStartDto {
    username: String,
    request: String,
    /// The device pass of an earlier login, when the device has one.
    pass: Option<String>,
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
    LoginStart(Username, CredentialRequest, Option<DevicePass>),
    LoginFinish(LoginHandle, CredentialFinalization),
    Logout(SessionToken),
    LogoutEverywhere(SessionToken),
    ReadKeyring(SessionToken),
    StoreKeyring(SessionToken, Keyring, KeyringVersion),
    Close(SessionToken),
    /// The public fingerprint of the relay's OPAQUE secret.
    Canary,
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
            let dto: LoginStartDto = parse(body)?;
            AccountCommand::LoginStart(
                username(&dto.username)?,
                message(&dto.request, CredentialRequest::from_slice)?,
                dto.pass.as_deref().map(|p| message(p, DevicePass::from_slice)).transpose()?,
            )
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
        Route::LogoutEverywhere => AccountCommand::LogoutEverywhere(parse_bearer(bearer)?),
        Route::Canary => AccountCommand::Canary,
        _ => return Err(ApiError::NotFound),
    })
}

/// Everything a route needs, validated before the vault is touched: a
/// malformed body never costs a Durable Object request.
#[derive(Debug)]
pub enum Command {
    Deposit(DepositCommand),
    Open(DropId),
    Revoke(DropId, RevocationToken),
    PutChunk(DropId, ChunkIndex, SealedChunk),
    OpenChunk(DropId, ChunkIndex, Option<ClaimToken>),
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
        Route::PutChunk(id, index) => Command::PutChunk(id, index, parse_chunk(body)?),
        Route::OpenChunk(id, index) => Command::OpenChunk(id, index, parse_open_chunk(body)?),
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
struct RequestReceiptDto {
    id: String,
    inbox: String,
    expires_at: i64,
}

/// The request's public id (for the sender's link) and its private inbox
/// (for the recipient's link only), both chosen by the relay.
pub fn request_receipt_body(receipt: RequestReceipt) -> String {
    serde_json::to_string(&RequestReceiptDto {
        id: encode(receipt.id.as_bytes()),
        inbox: encode(receipt.inbox.as_bytes()),
        expires_at: receipt.expires_at.0,
    })
    .expect("serializable")
}

#[derive(Debug, Serialize)]
struct OpenedDto {
    payload: String,
    burned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunks: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim: Option<String>,
}

/// A text secret keeps the original shape; a file adds its chunk count and,
/// when burning, the claim that only this response carries.
pub fn opened_body(opened: custody::Opened) -> String {
    serde_json::to_string(&OpenedDto {
        payload: encode(opened.payload.as_bytes()),
        burned: opened.burned,
        chunks: opened.chunks.map(|c| c.get()),
        claim: opened.claim.as_ref().map(|c| encode(c.expose())),
    })
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
    pass: String,
}

pub fn session_body(session: &Session) -> String {
    serde_json::to_string(&SessionDto {
        session: encode(session.token.expose()),
        expires_at: session.expires_at.0,
        pass: encode(session.pass.expose()),
    })
    .expect("serializable")
}

#[derive(Debug, Serialize)]
struct CanaryDto {
    canary: String,
}

pub fn canary_body(canary: &[u8; 32]) -> String {
    serde_json::to_string(&CanaryDto { canary: encode(canary) }).expect("serializable")
}

/// Accounts are served only under the secret they were made with: when
/// `expected` (the `OPAQUE_CANARY` variable) names a canary, the live one
/// must match it. Empty or unset means none was recorded yet.
pub fn check_canary(expected: Option<&str>, live: &[u8; 32]) -> Result<(), ApiError> {
    match expected.map(str::trim) {
        None | Some("") => Ok(()),
        Some(expected) if expected == encode(live) => Ok(()),
        Some(_) => Err(ApiError::Access(AccessError::NotConfigured)),
    }
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
    use custody::UnixTime;

    const ID: &str = "AAECAwQFBgcICQoLDA0ODw"; // bytes 0..16

    /// The smallest envelope a sealer makes.
    fn envelope() -> Vec<u8> {
        let mut bytes = b"SGY\x01".to_vec();
        bytes.resize(custody::MIN_PAYLOAD_LEN, 0x5A);
        bytes
    }

    fn payload64() -> String {
        encode(&envelope())
    }

    fn deposit_json(extra: &str) -> String {
        let payload = payload64();
        format!(r#"{{"payload":"{payload}","retention":"burn_after_reading","lifetime_seconds":3600{extra}}}"#)
    }

    fn answer_json(extra: &str) -> String {
        let payload = payload64();
        format!(r#"{{"payload":"{payload}","retention":"until_expiry","lifetime_seconds":300{extra}}}"#)
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
        let nine = ChunkIndex::new(9).unwrap();
        assert_eq!(route("POST", &format!("/api/secrets/{ID}/chunks/9")), Ok(Route::PutChunk(id, nine)));
        assert_eq!(route("POST", &format!("/api/secrets/{ID}/chunks/9/open")), Ok(Route::OpenChunk(id, nine)));
    }

    #[test]
    fn file_deposits_and_answers_carry_a_chunk_count() {
        let cmd = parse_deposit(deposit_json(r#","chunks":10"#).as_bytes()).unwrap();
        assert_eq!(cmd.chunks, Some(ChunkCount::new(10).unwrap()));
        assert!(parse_deposit(deposit_json("").as_bytes()).unwrap().chunks.is_none());
        let answer = answer_json(r#","chunks":2"#);
        assert_eq!(parse_answer(answer.as_bytes()).unwrap().chunks, Some(ChunkCount::new(2).unwrap()));
    }

    #[test]
    fn chunks_travel_raw_and_claims_in_json() {
        assert_eq!(parse_chunk(&[7; MAX_CHUNK_LEN]).unwrap().as_bytes().len(), MAX_CHUNK_LEN);
        assert_eq!(parse_open_chunk(b"{}"), Ok(None));
        let claim = format!(r#"{{"claim":"{}"}}"#, encode(&[3; 32]));
        assert_eq!(parse_open_chunk(claim.as_bytes()).unwrap().unwrap().expose(), &[3; 32]);
        let id = id_segment(ID).unwrap();
        let index = ChunkIndex::new(0).unwrap();
        assert_eq!(Route::PutChunk(id, index).max_body_len(), MAX_CHUNK_LEN);
        assert_eq!(Route::OpenChunk(id, index).max_body_len(), MAX_BODY_LEN);
    }

    #[test]
    fn opened_bodies_add_chunks_and_claim_only_for_files() {
        let payload = SealedPayload::new(envelope()).unwrap();
        let text = custody::Opened { payload: payload.clone(), burned: true, chunks: None, claim: None };
        let b64 = payload64();
        assert_eq!(opened_body(text), format!(r#"{{"payload":"{b64}","burned":true}}"#));
        let file = custody::Opened {
            payload,
            burned: true,
            chunks: Some(ChunkCount::new(3).unwrap()),
            claim: Some(ClaimToken::from_array([0; 32])),
        };
        let claim = encode(&[0; 32]);
        assert_eq!(opened_body(file), format!(r#"{{"payload":"{b64}","burned":true,"chunks":3,"claim":"{claim}"}}"#));
    }

    #[test]
    fn deposit_body_becomes_a_validated_command() {
        let cmd = parse_deposit(deposit_json("").as_bytes()).unwrap();
        assert_eq!(cmd.retention, Retention::BurnAfterReading);
        assert_eq!(cmd.lifetime.seconds(), 3600);
        assert_eq!(cmd.payload.as_bytes(), envelope());
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
    fn request_receipts_carry_the_public_id_and_the_private_inbox() {
        let inbox = DropId::from_slice(&[9; 16]).unwrap();
        let receipt = RequestReceipt { id: id_segment(ID).unwrap(), inbox, expires_at: UnixTime(42) };
        assert_eq!(
            request_receipt_body(receipt),
            format!(r#"{{"id":"{ID}","inbox":"{}","expires_at":42}}"#, encode(&[9; 16]))
        );
    }

    #[test]
    fn every_route_becomes_a_command() {
        let id = id_segment(ID).unwrap();
        let token = format!(r#"{{"token":"{}"}}"#, encode(&[1; 32]));
        let answer = answer_json("");
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
        assert_eq!(route("POST", "/api/account/logout/everywhere"), Ok(Route::LogoutEverywhere));
        assert_eq!(route("GET", "/api/account/canary"), Ok(Route::Canary));
        assert_eq!(route("POST", "/api/account/canary"), Err(ApiError::MethodNotAllowed));
        assert_eq!(route("GET", "/api/account/logout/everywhere"), Err(ApiError::MethodNotAllowed));
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
            Ok(Command::Account(AccountCommand::LoginStart(_, _, None)))
        ));
        let with_pass = format!(
            r#"{{"username":"ada","request":"{}","pass":"{}"}}"#,
            encode(&[1; CredentialRequest::LEN]),
            encode(&[4; DevicePass::LEN])
        );
        assert!(matches!(
            command(Route::LoginStart, with_pass.as_bytes(), None),
            Ok(Command::Account(AccountCommand::LoginStart(_, _, Some(pass)))) if pass.expose() == &[4; DevicePass::LEN]
        ));
        let short_pass = with_pass.replace(&encode(&[4; DevicePass::LEN]), &encode(&[4; 8]));
        assert!(command(Route::LoginStart, short_pass.as_bytes(), None).is_err());
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
        for route in [Route::Logout, Route::LogoutEverywhere, Route::ReadKeyring, Route::CloseAccount] {
            assert!(command(route.clone(), b"", Some(&bearer())).is_ok());
            assert_eq!(
                command(route, b"", None).unwrap_err(),
                ApiError::Access(AccessError::Unauthorized),
                "a session route needs its bearer"
            );
        }
        assert!(matches!(command(Route::Canary, b"", None), Ok(Command::Account(AccountCommand::Canary))));
    }

    #[test]
    fn account_answers_carry_only_protocol_bytes() {
        let challenge = LoginChallenge {
            handle: LoginHandle::from_array([0; 16]),
            response: access::CredentialResponse::from_slice(&[0; access::CredentialResponse::LEN]).unwrap(),
        };
        let body = login_challenge_body(&challenge);
        assert!(body.starts_with(r#"{"handle":"AAAAAAAAAAAAAAAAAAAAAA","response":""#));
        let session = Session {
            token: SessionToken::from_array([0; 32]),
            expires_at: access::UnixTime(7),
            pass: DevicePass::from_array([1; DevicePass::LEN]),
        };
        assert_eq!(
            session_body(&session),
            format!(
                r#"{{"session":"{}","expires_at":7,"pass":"{}"}}"#,
                encode(&[0; 32]),
                encode(&[1; DevicePass::LEN])
            )
        );
        assert_eq!(canary_body(&[0; 32]), format!(r#"{{"canary":"{}"}}"#, encode(&[0; 32])));
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
        // Full account storage reads like full custody, so the client shows one message for both.
        assert_eq!(ApiError::Access(AccessError::StorageFull).status(), 507);
        assert_eq!(
            ApiError::Access(AccessError::StorageFull).body(),
            ApiError::Custody(CustodyError::StorageFull).body()
        );
    }

    #[test]
    fn error_statuses() {
        assert_eq!(ApiError::Custody(CustodyError::NotFound).status(), 404);
        assert_eq!(ApiError::Custody(CustodyError::AlreadyExists).status(), 409);
        assert_eq!(ApiError::Custody(CustodyError::LifetimeOutOfRange).status(), 400);
        assert_eq!(ApiError::Custody(CustodyError::VaultUnavailable).status(), 503);
        assert_eq!(ApiError::Custody(CustodyError::RandomnessUnavailable).status(), 503);
        assert_eq!(ApiError::Custody(CustodyError::StorageFull).status(), 507);
        assert_eq!(ApiError::Custody(CustodyError::StorageFull).body(), r#"{"error":"StorageFull"}"#);
        assert_eq!(ApiError::Custody(CustodyError::InvalidChunk).status(), 400);
        assert_eq!(ApiError::Custody(CustodyError::NotFound).body(), r#"{"error":"NotFound"}"#);
    }

    mod adversary {
        use super::*;

        #[test]
        fn wrong_methods_are_refused_so_prefetchers_cannot_burn() {
            // A link preview bot issues GET/HEAD: it must never reach `open`.
            for method in ["GET", "HEAD", "OPTIONS", "PUT"] {
                assert_eq!(route(method, &format!("/api/secrets/{ID}/open")), Err(ApiError::MethodNotAllowed));
                let chunk = format!("/api/secrets/{ID}/chunks/0/open");
                assert_eq!(route(method, &chunk), Err(ApiError::MethodNotAllowed));
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
                &format!("/api/secrets/{ID}/chunks"),
                &format!("/api/secrets/{ID}/chunks/10"),
                &format!("/api/secrets/{ID}/chunks/01"),
                &format!("/api/secrets/{ID}/chunks/+1"),
                &format!("/api/secrets/{ID}/chunks/-0"),
                &format!("/api/secrets/{ID}/chunks/1%30"),
                &format!("/api/secrets/{ID}/chunks/65536"),
                &format!("/api/secrets/{ID}/chunks/18446744073709551617/open"),
                &format!("/api/secrets/{ID}/chunks//open"),
                &format!("/api/secrets/{ID}/chunks/0/revoke"),
            ] {
                assert_eq!(route("POST", path), Err(ApiError::NotFound), "{path}");
            }
        }

        #[test]
        fn the_accounts_object_answers_only_a_post_to_call() {
            assert_eq!(accounts_door("POST", "/call"), Ok(()));
            for method in ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "post", ""] {
                assert_eq!(accounts_door(method, "/call"), Err(ApiError::MethodNotAllowed), "{method}");
            }
            for path in
                ["", "/", "/call/", "/Call", "/calls", "//call", "/vault/call", "/call/../call", "/api/account/keyring"]
            {
                assert_eq!(accounts_door("POST", path), Err(ApiError::NotFound), "{path}");
            }
        }

        #[test]
        fn malformed_bodies_are_rejected() {
            assert_eq!(parse_deposit(b"not json").unwrap_err(), ApiError::InvalidJson);
            let unknown = deposit_json(r#","owner":"me@example.com""#);
            assert_eq!(parse_deposit(unknown.as_bytes()).unwrap_err(), ApiError::InvalidJson);
            let bad_retention = deposit_json("").replace("burn_after_reading", "forever");
            assert_eq!(parse_deposit(bad_retention.as_bytes()).unwrap_err(), ApiError::InvalidJson);
            let padded = deposit_json("").replace(&payload64(), &format!("{}=", payload64()));
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
            let json = Route::Deposit;
            assert_eq!(check_declared_length(&json, Some("104857600")), Err(ApiError::BodyTooLarge));
            let over = (MAX_BODY_LEN + 1).to_string();
            assert_eq!(check_declared_length(&json, Some(&over)), Err(ApiError::BodyTooLarge));
            assert_eq!(check_declared_length(&json, Some(&MAX_BODY_LEN.to_string())), Ok(()));
            // A chunk may be larger than a JSON body, but no larger than a chunk.
            let chunk = Route::PutChunk(id_segment(ID).unwrap(), ChunkIndex::new(0).unwrap());
            assert_eq!(check_declared_length(&chunk, Some(&MAX_CHUNK_LEN.to_string())), Ok(()));
            let over = (MAX_CHUNK_LEN + 1).to_string();
            assert_eq!(check_declared_length(&chunk, Some(&over)), Err(ApiError::BodyTooLarge));
        }

        #[test]
        fn a_body_of_undeclared_length_is_refused_before_it_is_read() {
            // Chunked encoding would otherwise have the Worker buffer up to
            // Cloudflare's 100 MB limit before any size check.
            let id = id_segment(ID).unwrap();
            let chunk = Route::PutChunk(id, ChunkIndex::new(0).unwrap());
            for route in [Route::Deposit, chunk, Route::OpenChunk(id, ChunkIndex::new(0).unwrap()), Route::LoginStart] {
                assert!(route.takes_body(), "{route:?}");
                for header in [None, Some(""), Some("lots"), Some("-1"), Some("1e3")] {
                    assert_eq!(check_declared_length(&route, header), Err(ApiError::LengthRequired), "{header:?}");
                }
            }
            assert_eq!(ApiError::LengthRequired.status(), 411);
            assert_eq!(ApiError::LengthRequired.body(), r#"{"error":"LengthRequired"}"#);
        }

        #[test]
        fn accounts_answer_only_under_the_secret_they_were_made_with() {
            // A lost or replaced OPAQUE_SERVER_SEED would lock every account
            // out and quietly start new ones under the wrong key: with the
            // canary of the old secret configured, the relay refuses instead.
            let live = [3u8; 32];
            assert_eq!(check_canary(None, &live), Ok(()));
            assert_eq!(check_canary(Some(""), &live), Ok(()), "not recorded yet");
            assert_eq!(check_canary(Some(&encode(&live)), &live), Ok(()));
            assert_eq!(check_canary(Some(&format!(" {} ", encode(&live))), &live), Ok(()));
            let other = encode(&[4u8; 32]);
            assert_eq!(check_canary(Some(&other), &live), Err(ApiError::Access(AccessError::NotConfigured)));
            assert_eq!(check_canary(Some("not base64!"), &live), Err(ApiError::Access(AccessError::NotConfigured)));
            assert_eq!(ApiError::Access(AccessError::NotConfigured).status(), 503);
        }

        #[test]
        fn one_collection_outpaces_many_addresses_filling_the_garbage() {
            // 30 writes a minute per address, each at most one chunk, and a
            // cron run every 15 minutes.
            let per_address_per_run = 30 * 15;
            let per_run = GARBAGE_ROUNDS as usize * usize::from(custody::GARBAGE_BATCH);
            assert!(per_run >= 10 * per_address_per_run, "{per_run}");
        }

        #[test]
        fn routes_without_a_body_never_read_one() {
            let id = id_segment(ID).unwrap();
            for route in [
                Route::Open(id),
                Route::FetchRequest(id),
                Route::Logout,
                Route::LogoutEverywhere,
                Route::ReadKeyring,
                Route::CloseAccount,
                Route::Canary,
            ] {
                assert!(!route.takes_body(), "{route:?}");
            }
        }

        #[test]
        fn payloads_and_chunks_smaller_than_the_sealer_makes_are_refused() {
            // Each costs a vault record: a flood of tiny ones would fill it
            // while the ceiling counted almost nothing.
            let tiny = deposit_json("").replace(&payload64(), "U0dZAQ");
            let too_small = ApiError::Custody(CustodyError::PayloadTooSmall);
            assert_eq!(parse_deposit(tiny.as_bytes()).unwrap_err(), too_small);
            let tiny = answer_json("").replace(&payload64(), "U0dZAQ");
            assert_eq!(parse_answer(tiny.as_bytes()).unwrap_err(), too_small);
            assert_eq!(too_small.status(), 400);
            for len in [1, 271, 300, 4096, custody::MAX_CHUNK_LEN - 1] {
                assert_eq!(parse_chunk(&vec![0; len]).unwrap_err(), ApiError::Custody(CustodyError::InvalidChunk));
            }
            assert!(parse_chunk(&[0; custody::MIN_CHUNK_LEN]).is_ok());
        }

        #[test]
        fn hostile_chunk_bodies_are_refused() {
            assert_eq!(parse_chunk(&[]).unwrap_err(), ApiError::Custody(CustodyError::PayloadEmpty));
            assert_eq!(parse_chunk(&vec![0; MAX_CHUNK_LEN + 1]).unwrap_err(), ApiError::BodyTooLarge);
            let too_many = deposit_json(r#","chunks":11"#);
            assert_eq!(parse_deposit(too_many.as_bytes()).unwrap_err(), ApiError::Custody(CustodyError::InvalidChunk));
            let none = deposit_json(r#","chunks":0"#);
            assert_eq!(parse_deposit(none.as_bytes()).unwrap_err(), ApiError::Custody(CustodyError::InvalidChunk));
            let negative = deposit_json(r#","chunks":-1"#);
            assert_eq!(parse_deposit(negative.as_bytes()).unwrap_err(), ApiError::InvalidJson);
            let short = r#"{"claim":"AAEC"}"#;
            assert_eq!(parse_open_chunk(short.as_bytes()).unwrap_err(), ApiError::Custody(CustodyError::InvalidToken));
            let extra = r#"{"claim":null,"index":3}"#;
            assert_eq!(parse_open_chunk(extra.as_bytes()).unwrap_err(), ApiError::InvalidJson);
        }

        #[test]
        fn pages_of_other_sites_cannot_call_the_relay() {
            // A page elsewhere could otherwise make its visitors' browsers deposit
            // junk from thousands of addresses, past the per-address limit.
            let own = "https://sigylo.net";
            for origin in ["https://evil.example", "null", "http://sigylo.net", "https://sigylo.net.evil.example"] {
                assert_eq!(check_origin(Some(origin), None, own), Err(ApiError::CrossOrigin), "{origin}");
            }
            assert_eq!(ApiError::CrossOrigin.status(), 403);
            // Our own pages, and clients that send no Origin (the app's shell), pass.
            assert_eq!(check_origin(Some(own), None, own), Ok(()));
            assert_eq!(check_origin(None, None, own), Ok(()));
            // An <img src> or a prefetch of /api/requests/{id} carries no Origin,
            // but the browser still says who asked in Sec-Fetch-Site.
            for site in ["cross-site", "same-site", "CROSS-SITE", ""] {
                assert_eq!(check_origin(None, Some(site), own), Err(ApiError::CrossOrigin), "{site}");
            }
            // A forged Origin is refused even next to a same-origin claim.
            assert_eq!(
                check_origin(Some("https://evil.example"), Some("same-origin"), own),
                Err(ApiError::CrossOrigin)
            );
            // Our pages, a typed address, and clients that send neither header
            // (the app's shell, curl) pass.
            assert_eq!(check_origin(Some(own), Some("same-origin"), own), Ok(()));
            assert_eq!(check_origin(None, Some("same-origin"), own), Ok(()));
            assert_eq!(check_origin(None, Some("none"), own), Ok(()));
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
        fn a_whole_ipv6_site_shares_a_second_allowance() {
            // A free tunnel hands anyone a /48: 65 536 /64s, each with its own
            // allowance, unless the /48 is counted too.
            let site = network_key("2001:db8:1:ffff::1");
            assert_eq!(site.as_deref(), Some("2001:db8:1::/48"));
            assert_eq!(site, network_key("2001:db8:1:2::9"));
            assert_ne!(site, network_key("2001:db8:2::1"));
            assert_ne!(site.as_deref(), Some(limiter_key("2001:db8:1:ffff::1").as_str()));
            // IPv4 (mapped or not) and garbled headers have only their own key.
            for address in ["203.0.113.7", "::ffff:203.0.113.7", "", "not an address"] {
                assert_eq!(network_key(address), None, "{address}");
            }
        }

        #[test]
        fn a_whole_ipv6_site_shares_a_read_allowance() {
            // GETs cost a Durable Object request too: 65 536 /64s reading at
            // their own pace would flood the one vault and the one accounts object.
            assert_eq!(network_binding(true), "NETWORK_WRITE_LIMITER");
            assert_eq!(network_binding(false), "NETWORK_READ_LIMITER");
            // The /48 key depends only on the address, never on the method.
            for address in ["2001:db8:1:2::3", "2001:db8:1:ffff::9"] {
                assert_eq!(network_key(address).as_deref(), Some("2001:db8:1::/48"), "{address}");
            }
            // IPv4 (mapped or not) and garbled headers have only their own key.
            for address in ["198.51.100.7", "::ffff:198.51.100.7", "", "not an address", "2001:db8::1::2"] {
                assert_eq!(network_key(address), None, "{address}");
            }
        }

        #[test]
        fn every_limiter_the_relay_calls_is_declared() {
            // A binding missing from wrangler.toml would silently let reads
            // through (they fail open) or stop every write (they fail closed).
            let toml = include_str!("../wrangler.toml");
            let limit = |name: &str| {
                let start = toml.find(&format!("name = \"{name}\""))?;
                let rest = &toml[start..];
                let table = &rest[..rest.find("[[").unwrap_or(rest.len())];
                let at = table.find("limit = ")? + "limit = ".len();
                table[at..].split(|c: char| !c.is_ascii_digit()).next()?.parse::<u32>().ok()
            };
            assert_eq!(limit(network_binding(true)), Some(300));
            assert_eq!(limit(network_binding(false)), Some(600));
            // Ten clients' worth per /48, for reads as for writes.
            assert_eq!(limit("READ_LIMITER").map(|n| n * 10), limit(network_binding(false)));
            assert_eq!(limit("WRITE_LIMITER").map(|n| n * 10), limit(network_binding(true)));
            // Logins fail closed too: without this binding no one signs in or
            // registers. It counts per location what the accounts object
            // counts for the whole world, so the two limits agree.
            assert_eq!(limit(LOGIN_BINDING), Some(u32::from(LOGIN_ATTEMPTS_PER_MINUTE)));
        }

        #[test]
        fn a_broken_limiter_stops_writes_but_not_reads() {
            // Writes fill the vault and spend its daily allowance: without a
            // limiter they wait. Reads only hand out what is already there.
            assert!(throttled(true, None));
            assert!(!throttled(false, None));
            for write in [true, false] {
                assert!(throttled(write, Some(false)));
                assert!(!throttled(write, Some(true)));
            }
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
