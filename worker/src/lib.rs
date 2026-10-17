//! # Sigylo relay (Cloudflare Worker)
//!
//! A blind relay: it receives envelopes that were sealed in the browser and
//! keeps them in PostgreSQL through Hyperdrive, and the chunks of files in
//! Cloudflare R2, via the Custody use cases.
//! It never sees a key or a plaintext and logs neither ids nor payloads.
//! The static web client is served by Workers Static Assets on the same
//! origin, so the browser never talks to a third party.
//!
//! Accounts use OPAQUE through the Access use cases: the relay's OPAQUE keys
//! come from the Worker secret `OPAQUE_SERVER_SEED` (32 bytes, base64url),
//! and logins and registrations are throttled per account by the `LOGIN_LIMITER` binding.
#![forbid(unsafe_code)]

pub mod api;

#[cfg(target_arch = "wasm32")]
mod runtime {
    use access::{AccessError, AccountId, Gatekeeper, Throttle};
    use access_adapters::{OpaqueKeys, PostgresAccounts, RandomTokens, Sha256SessionDigest};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use custody::Custodian;
    use custody_adapters::{PostgresVault, R2ChunkStore, RandomIds, Sha256TokenDigest};
    use tokio_postgres::{Client, NoTls};
    use worker::postgres_tls::PassthroughTls;
    use worker::{
        Context, Env, Method, Request, Response, Result, ScheduleContext, ScheduledEvent, SecureTransport, Socket,
        event,
    };
    use zeroize::Zeroizing;

    use crate::api::{self, AccountCommand, ApiError, Command};

    fn unavailable<E>(_: E) -> worker::Error {
        worker::Error::RustError("database unavailable".into())
    }

    /// Connects through Hyperdrive with TLS. `DB_TLS = "disable"` exists only
    /// for `wrangler dev` against a local PostgreSQL without certificates.
    async fn connect(env: &Env) -> Result<Client> {
        let hyperdrive = env.hyperdrive("DB")?;
        let config: tokio_postgres::Config = hyperdrive.connection_string().parse().map_err(unavailable)?;
        let plaintext_dev = env.var("DB_TLS").is_ok_and(|v| v.to_string() == "disable");
        if plaintext_dev {
            let socket = Socket::builder().connect(hyperdrive.host(), hyperdrive.port())?;
            let (client, connection) = config.connect_raw(socket, NoTls).await.map_err(unavailable)?;
            wasm_bindgen_futures::spawn_local(async move {
                let _ = connection.await;
            });
            return Ok(client);
        }
        let socket = Socket::builder()
            .secure_transport(SecureTransport::StartTls)
            .connect(hyperdrive.host(), hyperdrive.port())?;
        let (client, connection) = config.connect_raw(socket, PassthroughTls).await.map_err(unavailable)?;
        wasm_bindgen_futures::spawn_local(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    /// The R2 bucket that holds the sealed chunks of files.
    fn chunk_store(env: &Env) -> Result<R2ChunkStore> {
        Ok(R2ChunkStore::new(env.bucket("CHUNKS")?))
    }

    fn respond(status: u16, body: String) -> Result<Response> {
        let mut response = Response::ok(body)?.with_status(status);
        let headers = response.headers_mut();
        headers.set("Content-Type", "application/json")?;
        headers.set("Cache-Control", "no-store")?;
        headers.set("X-Content-Type-Options", "nosniff")?;
        headers.set("Referrer-Policy", "no-referrer")?;
        Ok(response)
    }

    fn fail(error: ApiError) -> Result<Response> {
        respond(error.status(), error.body())
    }

    /// What a use case answers: JSON, or the raw bytes of a chunk.
    enum Reply {
        Json(u16, String),
        Chunk(Vec<u8>),
    }

    fn reply(reply: Reply) -> Result<Response> {
        match reply {
            Reply::Json(status, body) => respond(status, body),
            Reply::Chunk(bytes) => {
                let mut response = Response::from_bytes(bytes)?;
                let headers = response.headers_mut();
                headers.set("Content-Type", "application/octet-stream")?;
                headers.set("Cache-Control", "no-store")?;
                headers.set("X-Content-Type-Options", "nosniff")?;
                headers.set("Referrer-Policy", "no-referrer")?;
                Ok(response)
            }
        }
    }

    async fn rate_limited(env: &Env, req: &Request) -> bool {
        // The client address is used in memory for throttling and never stored.
        let Ok(limiter) = env.rate_limiter("WRITE_LIMITER") else { return false };
        let key = req.headers().get("CF-Connecting-IP").ok().flatten().unwrap_or_default();
        limiter.limit(key).await.map(|o| !o.success).unwrap_or(false)
    }

    /// Login and registration attempts per account, wherever they come from
    /// (kept in memory by Cloudflare, keyed by a prefix of the account's
    /// keyed hash). Fails closed: without a working limiter, no guessing.
    struct LoginLimiter<'a>(&'a Env);

    impl Throttle for LoginLimiter<'_> {
        async fn admit(&self, account: &AccountId) -> bool {
            let Ok(limiter) = self.0.rate_limiter("LOGIN_LIMITER") else { return false };
            let key: String = account.as_bytes()[..16].iter().map(|b| format!("{b:02x}")).collect();
            limiter.limit(key).await.map(|o| o.success).unwrap_or(false)
        }
    }

    fn opaque_keys(env: &Env) -> std::result::Result<OpaqueKeys, AccessError> {
        let secret = env.secret("OPAQUE_SERVER_SEED").map_err(|_| AccessError::NotConfigured)?.to_string();
        let seed = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret.trim()).map_err(|_| AccessError::NotConfigured)?);
        OpaqueKeys::from_seed(&seed)
    }

    async fn account(command: AccountCommand, env: &Env) -> std::result::Result<Reply, ApiError> {
        let keys = opaque_keys(env)?;
        let client = connect(env).await.map_err(|_| AccessError::StoreUnavailable)?;
        let gatekeeper =
            Gatekeeper::new(keys, PostgresAccounts::new(&client), RandomTokens, Sha256SessionDigest, LoginLimiter(env));
        Ok(match command {
            AccountCommand::RegisterStart(username, request) => Reply::Json(
                200,
                api::registration_response_body(&gatekeeper.registration_response(&username, &request).await?),
            ),
            AccountCommand::RegisterFinish(username, record) => {
                gatekeeper.register(&username, &record).await?;
                Reply::Json(201, "{}".into())
            }
            AccountCommand::LoginStart(username, request) => {
                Reply::Json(200, api::login_challenge_body(&gatekeeper.begin_login(&username, &request).await?))
            }
            AccountCommand::LoginFinish(handle, finalization) => {
                Reply::Json(200, api::session_body(&gatekeeper.finish_login(&handle, &finalization).await?))
            }
            AccountCommand::Logout(token) => {
                gatekeeper.sign_out(&token).await?;
                Reply::Json(200, "{}".into())
            }
            AccountCommand::ReadKeyring(token) => {
                Reply::Json(200, api::keyring_body(&gatekeeper.keyring(&token).await?))
            }
            AccountCommand::StoreKeyring(token, keyring, expected) => {
                Reply::Json(200, api::version_body(gatekeeper.store_keyring(&token, &keyring, expected).await?))
            }
            AccountCommand::Close(token) => {
                gatekeeper.close_account(&token).await?;
                Reply::Json(200, "{}".into())
            }
        })
    }

    async fn execute(command: Command, env: &Env) -> std::result::Result<Reply, ApiError> {
        match command {
            Command::Account(command) => account(command, env).await,
            custody => safekeeping(custody, env).await,
        }
    }

    async fn safekeeping(command: Command, env: &Env) -> std::result::Result<Reply, ApiError> {
        let client = connect(env).await.map_err(|_| custody::CustodyError::VaultUnavailable)?;
        let store = chunk_store(env).map_err(|_| custody::CustodyError::VaultUnavailable)?;
        let custodian = Custodian::new(PostgresVault::new(&client), store, Sha256TokenDigest, RandomIds);
        Ok(match command {
            Command::Deposit(cmd) => {
                let revocation = cmd.revocation.as_ref();
                let receipt = match cmd.chunks {
                    Some(chunks) => {
                        custodian.deposit_file(cmd.payload, chunks, cmd.retention, cmd.lifetime, revocation).await?
                    }
                    None => custodian.deposit(cmd.payload, cmd.retention, cmd.lifetime, revocation).await?,
                };
                Reply::Json(201, api::receipt_body(receipt))
            }
            Command::Open(id) => Reply::Json(200, api::opened_body(custodian.open(&id).await?)),
            Command::Revoke(id, token) => {
                custodian.revoke(&id, &token).await?;
                Reply::Json(200, "{}".into())
            }
            Command::PutChunk(id, index, chunk) => {
                custodian.put_chunk(&id, index, chunk).await?;
                Reply::Json(201, "{}".into())
            }
            Command::OpenChunk(id, index, claim) => {
                Reply::Chunk(custodian.open_chunk(&id, index, claim.as_ref()).await?.into_bytes())
            }
            Command::PostRequest(cmd) => {
                Reply::Json(201, api::receipt_body(custodian.post_request(cmd.recipient_key, cmd.lifetime).await?))
            }
            Command::FetchRequest(id) => {
                Reply::Json(200, api::posted_request_body(custodian.fetch_request(&id).await?))
            }
            Command::AnswerRequest(id, answer) => {
                Reply::Json(201, api::expires_body(custodian.answer_request(id, answer).await?))
            }
            Command::Account(_) => return Err(ApiError::NotFound),
        })
    }

    #[event(fetch)]
    async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let method = req.method().to_string();
        let route = match api::route(&method, &req.path()) {
            Ok(route) => route,
            Err(error) => return fail(error),
        };
        if req.method() == Method::Post && rate_limited(&env, &req).await {
            return respond(429, r#"{"error":"RateLimited"}"#.into());
        }
        let body = if req.method() == Method::Post {
            if let Err(error) = api::check_declared_length(&route, req.headers().get("Content-Length")?.as_deref()) {
                return fail(error);
            }
            req.bytes().await?
        } else {
            Vec::new()
        };
        if body.len() > route.max_body_len() {
            return fail(ApiError::BodyTooLarge);
        }
        let bearer = req.headers().get("Authorization")?;
        let command = match api::command(route, &body, bearer.as_deref()) {
            Ok(command) => command,
            Err(error) => return fail(error),
        };
        match execute(command, &env).await {
            Ok(answer) => reply(answer),
            Err(error) => fail(error),
        }
    }

    #[event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        // Expired rows go first, so their chunks' objects join this round's garbage.
        if let (Ok(client), Ok(store)) = (connect(&env).await, chunk_store(&env)) {
            let custodian = Custodian::new(PostgresVault::new(&client), store, Sha256TokenDigest, RandomIds);
            let _ = custodian.purge_expired().await;
            let _ = custodian.collect_garbage().await;
            if let Ok(keys) = opaque_keys(&env) {
                let store = PostgresAccounts::new(&client);
                let gatekeeper = Gatekeeper::new(keys, store, RandomTokens, Sha256SessionDigest, LoginLimiter(&env));
                let _ = gatekeeper.purge_expired().await;
            }
        }
    }
}
