//! # Sigylo relay (Cloudflare Worker)
//!
//! A blind relay: it receives envelopes that were sealed in the browser and
//! hands them, via the Custody use cases, to Sigylo's own vault: one Durable
//! Object in the EU ([`SigyloVault`](runtime::SigyloVault)) keeps the records,
//! and R2 the sealed bytes, payloads and chunks of files alike.
//! It never sees a key or a plaintext and logs neither ids nor payloads.
//! The static web client is served by Workers Static Assets on the same
//! origin, so the browser never talks to a third party.
//!
//! Accounts use OPAQUE through the Access use cases: the relay's OPAQUE keys
//! come from the Worker secret `OPAQUE_SERVER_SEED` (32 bytes, base64url),
//! accounts, keyrings and sessions live in a Durable Object of their own in
//! the EU ([`SigyloAccounts`](runtime::SigyloAccounts)), and logins and
//! registrations are throttled per account and budget by the
//! `LOGIN_LIMITER` binding and that object. When `OPAQUE_CANARY` is set,
//! accounts answer only if the secret is the one it names.
#![forbid(unsafe_code)]

pub mod api;

#[cfg(target_arch = "wasm32")]
mod runtime {
    use access::{AccessError, AccountId, AccountStore, Budget, Gatekeeper, Throttle, UnixTime};
    use access_adapters::{OpaqueKeys, RandomTokens, throttle_bucket};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use custody::{Custodian, CustodyError, Vault};
    use custody_adapters::{R2ChunkStore, RandomIds, Sha256TokenDigest};
    use vault::{AccountLedger, LedgerVault, RemoteAccounts, RemoteVault, Scratch, VaultThrottle};
    use vault_adapters::{
        ACCOUNTS_BINDING, ACCOUNTS_NAME, DurableKv, DurableLink, Placement, R2Payloads, VAULT_BINDING, WorkerClock,
    };
    use worker::{
        Context, DurableObject, Env, Method, Request, Response, Result, ScheduleContext, ScheduledEvent, State,
        durable_object, event,
    };
    use zeroize::Zeroizing;

    use crate::api::{self, AccountCommand, ApiError, Command};

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
        // Calls from IPv6 also spend their /48's allowance, writes and reads
        // apart, with the same failure policy as the first.
        let Some(network) = api::network_key(&address) else { return false };
        let Ok(limiter) = env.rate_limiter(api::network_binding(write)) else { return api::throttled(write, None) };
        api::throttled(write, limiter.limit(network).await.ok().map(|o| o.success))
    }

    /// Login and registration attempts per account and budget in Cloudflare's
    /// memory, keyed by a prefix of the budget's bucket. Its count is per
    /// Cloudflare location, so it only spares the accounts object the
    /// obvious floods. Fails closed: without a working limiter, no guessing.
    struct LoginLimiter<'a>(&'a Env);

    impl Throttle for LoginLimiter<'_> {
        async fn admit(&self, account: &AccountId, budget: &Budget) -> bool {
            let Ok(limiter) = self.0.rate_limiter(api::LOGIN_BINDING) else { return false };
            let key: String = throttle_bucket(account, budget)[..16].iter().map(|b| format!("{b:02x}")).collect();
            limiter.limit(key).await.map(|o| o.success).unwrap_or(false)
        }
    }

    fn opaque_keys(env: &Env) -> std::result::Result<OpaqueKeys, AccessError> {
        let secret =
            Zeroizing::new(env.secret("OPAQUE_SERVER_SEED").map_err(|_| AccessError::NotConfigured)?.to_string());
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
        let accounts = remote_accounts(env)?;
        let digest = keys.session_digest();
        let passes = keys.passes(now());
        // The binding is a cheap first filter; the accounts object holds the one global count.
        let throttle =
            (LoginLimiter(env), VaultThrottle::new(&accounts, api::LOGIN_ATTEMPTS_PER_MINUTE, throttle_bucket));
        let gatekeeper = Gatekeeper::new(keys, &accounts, RandomTokens, digest, throttle, passes);
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

    /// Where the Durable Objects live: in the EU. `VAULT_PLACEMENT = "local"`
    /// exists only for `wrangler dev`, whose runtime has no jurisdictions.
    fn placement(env: &Env) -> Placement {
        let local = env.var("VAULT_PLACEMENT").is_ok_and(|v| v.to_string() == "local");
        if local { Placement::Local } else { Placement::Jurisdiction }
    }

    /// The vault in its Durable Object.
    fn remote_vault(env: &Env) -> std::result::Result<RemoteVault<DurableLink>, CustodyError> {
        DurableLink::new(env, VAULT_BINDING, placement(env))
            .map(RemoteVault::new)
            .map_err(|_| CustodyError::VaultUnavailable)
    }

    /// The accounts in their Durable Object, which counts attempts under the
    /// same buckets as `LOGIN_LIMITER`.
    fn remote_accounts(env: &Env) -> std::result::Result<RemoteAccounts<DurableLink>, AccessError> {
        DurableLink::named(env, ACCOUNTS_BINDING, ACCOUNTS_NAME, placement(env))
            .map(|link| RemoteAccounts::new(link, throttle_bucket))
            .map_err(|_| AccessError::StoreUnavailable)
    }

    async fn safekeeping(command: Command, env: &Env) -> std::result::Result<Reply, ApiError> {
        let store = chunk_store(env).map_err(|_| CustodyError::VaultUnavailable)?;
        keep(command, &Custodian::new(remote_vault(env)?, store, Sha256TokenDigest, RandomIds)).await
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

    /// Sigylo's accounts: one Durable Object of its own class (in the EU, by
    /// name, see `vault_adapters::DurableLink::named`) that runs every
    /// [`vault::AccountCall`] on its own storage, one synchronous step at a
    /// time. Logins in progress and attempt counters live only in its
    /// memory ([`Scratch`]), never on disk. Only this Worker can reach it,
    /// through its binding, and only with a POST to `/call`.
    #[durable_object(fetch)]
    pub struct SigyloAccounts {
        state: State,
        scratch: Scratch,
    }

    impl core::fmt::Debug for SigyloAccounts {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("SigyloAccounts")
        }
    }

    impl DurableObject for SigyloAccounts {
        fn new(state: State, _env: Env) -> Self {
            Self { state, scratch: Scratch::default() }
        }

        async fn fetch(&self, mut req: Request) -> Result<Response> {
            if let Err(error) = api::accounts_door(req.method().as_ref(), &req.path()) {
                return Response::error("", error.status());
            }
            let call = req.bytes().await?;
            // From here to the reply nothing awaits: one call, one step.
            let ledger = AccountLedger::new(DurableKv::new(&self.state), &self.scratch, WorkerClock);
            Response::from_bytes(vault::serve_accounts(&ledger, &call))
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
        let headers = req.headers();
        let (origin, fetch_site) = (headers.get("Origin")?, headers.get("Sec-Fetch-Site")?);
        if let Err(error) = api::check_origin(origin.as_deref(), fetch_site.as_deref(), &own_origin) {
            return fail(error);
        }
        // Every call costs a Durable Object request, reads included: all of them are throttled.
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
            chores(&Custodian::new(vault, store, Sha256TokenDigest, RandomIds)).await;
        }
        // Expired sessions, and logins and counters left in the object's memory.
        if let Ok(accounts) = remote_accounts(&env) {
            let _ = accounts.purge_expired().await;
        }
    }
}
