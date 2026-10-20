//! # Sigylo relay (Cloudflare Worker)
//!
//! A blind relay: it receives envelopes that were sealed in the browser and
//! hands them, via the Custody use cases, to Sigylo's own vault: one Durable
//! Object in the EU ([`SigyloVault`](runtime::SigyloVault)) keeps the records,
//! and R2 the sealed bytes, payloads and chunks of files alike. While the
//! custody that used to live in PostgreSQL drains (`LEGACY_VAULT = "drain"`),
//! whatever the vault does not know is looked for there too.
//! It never sees a key or a plaintext and logs neither ids nor payloads.
//! The static web client is served by Workers Static Assets on the same
//! origin, so the browser never talks to a third party.
//!
//! Accounts use OPAQUE through the Access use cases: the relay's OPAQUE keys
//! come from the Worker secret `OPAQUE_SERVER_SEED` (32 bytes, base64url),
//! and logins and registrations are throttled per account and budget by the
//! `LOGIN_LIMITER` binding and the database. When `OPAQUE_CANARY` is set,
//! accounts answer only if the secret is the one it names.
#![forbid(unsafe_code)]

pub mod api;

#[cfg(target_arch = "wasm32")]
mod runtime {
    use access::{AccessError, AccountId, Budget, Gatekeeper, Throttle, UnixTime};
    use access_adapters::{OpaqueKeys, PostgresAccounts, PostgresThrottle, RandomTokens, throttle_bucket};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use core::cell::OnceCell;

    use custody::{
        ChunkIndex, ChunkRef, ClaimDigest, Custodian, CustodyError, Deposit, DropId, ObjectName, Opened, PostedRequest,
        Receipt, Request as Asked, RevocationDigest, Vault,
    };
    use custody_adapters::{PostgresVault, R2ChunkStore, RandomIds, Sha256TokenDigest};
    use tokio_postgres::{Client, NoTls};
    use vault::{Draining, LedgerVault, RemoteVault};
    use vault_adapters::{DurableKv, DurableLink, Placement, R2Payloads, WorkerClock};
    use worker::postgres_tls::PassthroughTls;
    use worker::{
        Context, DurableObject, Env, Method, Request, Response, Result, ScheduleContext, ScheduledEvent,
        SecureTransport, Socket, State, durable_object, event,
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
        // Writes and reads have their own allowance, so fetching a request does
        // not eat into the allowance for answering it.
        let write = req.method() == Method::Post;
        let binding = if write { "WRITE_LIMITER" } else { "READ_LIMITER" };
        let Ok(limiter) = env.rate_limiter(binding) else { return api::throttled(write, None) };
        let address = req.headers().get("CF-Connecting-IP").ok().flatten().unwrap_or_default();
        if api::throttled(write, limiter.limit(api::limiter_key(&address)).await.ok().map(|o| o.success)) {
            return true;
        }
        // Writes from IPv6 also spend their /48's allowance, closed like the first.
        let Some(network) = api::network_key(&address).filter(|_| write) else { return false };
        let Ok(limiter) = env.rate_limiter("NETWORK_WRITE_LIMITER") else { return true };
        api::throttled(true, limiter.limit(network).await.ok().map(|o| o.success))
    }

    /// Login and registration attempts per account and per minute, counted
    /// in the database for the whole world (`access.admit`), behind the
    /// same limit in `LOGIN_LIMITER` (wrangler.toml).
    const LOGIN_ATTEMPTS_PER_MINUTE: u16 = 10;

    /// Login and registration attempts per account and budget in Cloudflare's
    /// memory, keyed by a prefix of the budget's bucket. Its count is per
    /// Cloudflare location, so it only spares the database the obvious
    /// floods. Fails closed: without a working limiter, no guessing.
    struct LoginLimiter<'a>(&'a Env);

    impl Throttle for LoginLimiter<'_> {
        async fn admit(&self, account: &AccountId, budget: &Budget) -> bool {
            let Ok(limiter) = self.0.rate_limiter("LOGIN_LIMITER") else { return false };
            let key: String = throttle_bucket(account, budget)[..16].iter().map(|b| format!("{b:02x}")).collect();
            limiter.limit(key).await.map(|o| o.success).unwrap_or(false)
        }
    }

    fn opaque_keys(env: &Env) -> std::result::Result<OpaqueKeys, AccessError> {
        let secret = env.secret("OPAQUE_SERVER_SEED").map_err(|_| AccessError::NotConfigured)?.to_string();
        let seed = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret.trim()).map_err(|_| AccessError::NotConfigured)?);
        OpaqueKeys::from_seed(&seed)
    }

    /// The relay's clock, which dates device passes.
    fn now() -> UnixTime {
        UnixTime((worker::Date::now().as_millis() / 1000) as i64)
    }

    async fn account(command: AccountCommand, env: &Env) -> std::result::Result<Reply, ApiError> {
        let keys = opaque_keys(env)?;
        let canary = keys.canary();
        // The canary always reports the live secret, so the deploy can compare it.
        if let AccountCommand::Canary = command {
            return Ok(Reply::Json(200, api::canary_body(&canary)));
        }
        let expected = env.var("OPAQUE_CANARY").ok().map(|v| v.to_string());
        api::check_canary(expected.as_deref(), &canary)?;
        let client = connect(env).await.map_err(|_| AccessError::StoreUnavailable)?;
        let digest = keys.session_digest();
        let passes = keys.passes(now());
        // The binding is a cheap first filter; the database holds the one global count.
        let throttle = (LoginLimiter(env), PostgresThrottle::new(&client, LOGIN_ATTEMPTS_PER_MINUTE));
        let gatekeeper = Gatekeeper::new(keys, PostgresAccounts::new(&client), RandomTokens, digest, throttle, passes);
        Ok(match command {
            AccountCommand::RegisterStart(username, request) => Reply::Json(
                200,
                api::registration_response_body(&gatekeeper.registration_response(&username, &request).await?),
            ),
            AccountCommand::RegisterFinish(username, record) => {
                gatekeeper.register(&username, &record).await?;
                Reply::Json(201, "{}".into())
            }
            AccountCommand::LoginStart(username, request, pass) => Reply::Json(
                200,
                api::login_challenge_body(&gatekeeper.begin_login(&username, &request, pass.as_ref()).await?),
            ),
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
            AccountCommand::LogoutEverywhere(token) => {
                gatekeeper.sign_out_everywhere(&token).await?;
                Reply::Json(200, "{}".into())
            }
            AccountCommand::Canary => Reply::Json(200, api::canary_body(&canary)),
        })
    }

    async fn execute(command: Command, env: &Env) -> std::result::Result<Reply, ApiError> {
        match command {
            Command::Account(command) => account(command, env).await,
            custody => safekeeping(custody, env).await,
        }
    }

    /// The vault in its Durable Object, in the EU. `VAULT_PLACEMENT = "local"`
    /// exists only for `wrangler dev`, whose runtime has no jurisdictions.
    fn remote_vault(env: &Env) -> std::result::Result<RemoteVault<DurableLink>, CustodyError> {
        let local = env.var("VAULT_PLACEMENT").is_ok_and(|v| v.to_string() == "local");
        let placement = if local { Placement::Local } else { Placement::Jurisdiction };
        DurableLink::new(env, "VAULT", placement).map(RemoteVault::new).map_err(|_| CustodyError::VaultUnavailable)
    }

    /// Whether custody kept in PostgreSQL before the vault still drains.
    fn draining(env: &Env) -> bool {
        env.var("LEGACY_VAULT").is_ok_and(|v| v.to_string() == "drain")
    }

    /// The custody of PostgreSQL, connected only if the vault did not have
    /// what was asked for, so new things never wait on the database.
    struct Legacy<'e> {
        env: &'e Env,
        client: OnceCell<Client>,
    }

    impl<'e> Legacy<'e> {
        fn new(env: &'e Env) -> Self {
            Self { env, client: OnceCell::new() }
        }

        async fn vault(&self) -> std::result::Result<PostgresVault<'_>, CustodyError> {
            if self.client.get().is_none() {
                let client = connect(self.env).await.map_err(|_| CustodyError::VaultUnavailable)?;
                let _ = self.client.set(client);
            }
            self.client.get().map(PostgresVault::new).ok_or(CustodyError::VaultUnavailable)
        }
    }

    impl Vault for Legacy<'_> {
        async fn deposit(&self, deposit: &Deposit) -> std::result::Result<custody::UnixTime, CustodyError> {
            self.vault().await?.deposit(deposit).await
        }

        async fn open(&self, id: &DropId, claim: &ClaimDigest) -> std::result::Result<Option<Opened>, CustodyError> {
            self.vault().await?.open(id, claim).await
        }

        async fn reserve_chunk(
            &self,
            id: &DropId,
            index: ChunkIndex,
            object: &ObjectName,
            len: u32,
        ) -> std::result::Result<bool, CustodyError> {
            self.vault().await?.reserve_chunk(id, index, object, len).await
        }

        async fn put_chunk(
            &self,
            id: &DropId,
            index: ChunkIndex,
            object: &ObjectName,
            len: u32,
        ) -> std::result::Result<bool, CustodyError> {
            self.vault().await?.put_chunk(id, index, object, len).await
        }

        async fn open_chunk(
            &self,
            id: &DropId,
            index: ChunkIndex,
            claim: Option<&ClaimDigest>,
        ) -> std::result::Result<Option<ChunkRef>, CustodyError> {
            self.vault().await?.open_chunk(id, index, claim).await
        }

        async fn burn_chunk(
            &self,
            id: &DropId,
            index: ChunkIndex,
            claim: &ClaimDigest,
        ) -> std::result::Result<bool, CustodyError> {
            self.vault().await?.burn_chunk(id, index, claim).await
        }

        async fn garbage(&self, limit: u16) -> std::result::Result<Vec<ObjectName>, CustodyError> {
            self.vault().await?.garbage(limit).await
        }

        async fn forget_garbage(&self, objects: &[ObjectName]) -> std::result::Result<(), CustodyError> {
            self.vault().await?.forget_garbage(objects).await
        }

        async fn revoke(
            &self,
            id: &DropId,
            digest: &RevocationDigest,
        ) -> std::result::Result<Option<Vec<ObjectName>>, CustodyError> {
            self.vault().await?.revoke(id, digest).await
        }

        async fn post_request(&self, request: &Asked) -> std::result::Result<custody::UnixTime, CustodyError> {
            self.vault().await?.post_request(request).await
        }

        async fn fetch_request(&self, id: &DropId) -> std::result::Result<Option<PostedRequest>, CustodyError> {
            self.vault().await?.fetch_request(id).await
        }

        async fn answer_request(&self, answer: &Deposit) -> std::result::Result<Option<Receipt>, CustodyError> {
            self.vault().await?.answer_request(answer).await
        }

        async fn purge_expired(&self) -> std::result::Result<u64, CustodyError> {
            self.vault().await?.purge_expired().await
        }
    }

    async fn safekeeping(command: Command, env: &Env) -> std::result::Result<Reply, ApiError> {
        let store = chunk_store(env).map_err(|_| CustodyError::VaultUnavailable)?;
        let vault = remote_vault(env)?;
        if draining(env) {
            let custodian = Custodian::new(Draining::new(vault, Legacy::new(env)), store, Sha256TokenDigest, RandomIds);
            keep(command, &custodian).await
        } else {
            keep(command, &Custodian::new(vault, store, Sha256TokenDigest, RandomIds)).await
        }
    }

    async fn keep<V: Vault>(
        command: Command,
        custodian: &Custodian<V, R2ChunkStore, Sha256TokenDigest, RandomIds>,
    ) -> std::result::Result<Reply, ApiError> {
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
            Command::PostRequest(cmd) => Reply::Json(
                201,
                api::request_receipt_body(custodian.post_request(cmd.recipient_key, cmd.lifetime).await?),
            ),
            Command::FetchRequest(id) => {
                Reply::Json(200, api::posted_request_body(custodian.fetch_request(&id).await?))
            }
            // The receipt names the inbox, where the sender uploads a file's chunks.
            Command::AnswerRequest(id, answer) => {
                Reply::Json(201, api::receipt_body(custodian.answer_request(id, answer).await?))
            }
            Command::Account(_) => return Err(ApiError::NotFound),
        })
    }

    /// Sigylo's vault: one Durable Object (in the EU, by name, see
    /// `vault_adapters::DurableLink`) that runs every [`vault::Call`] on its
    /// own storage, one atomic step at a time, with the sealed bytes in R2.
    /// Only this Worker can reach it, through its binding.
    #[durable_object(fetch)]
    pub struct SigyloVault {
        state: State,
        env: Env,
    }

    impl core::fmt::Debug for SigyloVault {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("SigyloVault")
        }
    }

    impl DurableObject for SigyloVault {
        fn new(state: State, env: Env) -> Self {
            Self { state, env }
        }

        async fn fetch(&self, mut req: Request) -> Result<Response> {
            if req.method() != Method::Post {
                return Response::error("", 405);
            }
            let call = req.bytes().await?;
            let payloads = R2Payloads::new(self.env.bucket("CHUNKS")?);
            let vault = LedgerVault::new(DurableKv::new(&self.state), payloads, RandomIds, WorkerClock);
            Response::from_bytes(vault::serve(&vault, &call).await)
        }
    }

    #[event(fetch)]
    async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let method = req.method().to_string();
        let route = match api::route(&method, &req.path()) {
            Ok(route) => route,
            Err(error) => return fail(error),
        };
        let own_origin = req.url()?.origin().ascii_serialization();
        if let Err(error) = api::check_origin(req.headers().get("Origin")?.as_deref(), &own_origin) {
            return fail(error);
        }
        // Every call costs a database query, reads included: all of them are throttled.
        if rate_limited(&env, &req).await {
            return respond(429, r#"{"error":"RateLimited"}"#.into());
        }
        // A body is read only where the route takes one, and only once its
        // declared length fits.
        let body = if route.takes_body() {
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

    /// Runs the vault's chores: expired records go first, so their objects
    /// join this round's garbage, then the garbage leaves R2, batch after
    /// batch, within a few rounds and seconds (the work waits on the vault
    /// and R2, and stays inside the free plan's CPU allowance).
    async fn chores<V: Vault>(custodian: &Custodian<V, R2ChunkStore, Sha256TokenDigest, RandomIds>) {
        let _ = custodian.purge_expired().await;
        let deadline = worker::Date::now().as_millis() + api::GARBAGE_MILLIS;
        let mut rounds = 1;
        let _ = custodian
            .collect_garbage(|| {
                rounds += 1;
                rounds <= api::GARBAGE_ROUNDS && worker::Date::now().as_millis() < deadline
            })
            .await;
    }

    #[event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        if let (Ok(vault), Ok(store)) = (remote_vault(&env), chunk_store(&env)) {
            if draining(&env) {
                chores(&Custodian::new(Draining::new(vault, Legacy::new(&env)), store, Sha256TokenDigest, RandomIds))
                    .await;
            } else {
                chores(&Custodian::new(vault, store, Sha256TokenDigest, RandomIds)).await;
            }
        }
        if let (Ok(client), Ok(keys)) = (connect(&env).await, opaque_keys(&env)) {
            let store = PostgresAccounts::new(&client);
            let digest = keys.session_digest();
            let passes = keys.passes(now());
            let gatekeeper = Gatekeeper::new(keys, store, RandomTokens, digest, LoginLimiter(&env), passes);
            let _ = gatekeeper.purge_expired().await;
        }
    }
}
