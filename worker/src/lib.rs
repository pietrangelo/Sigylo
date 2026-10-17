//! # Sigylo relay (Cloudflare Worker)
//!
//! A blind relay: it receives envelopes that were sealed in the browser and
//! keeps them in PostgreSQL through Hyperdrive, via the Custody use cases.
//! It never sees a key or a plaintext and logs neither ids nor payloads.
//! The static web client is served by Workers Static Assets on the same
//! origin, so the browser never talks to a third party.
#![forbid(unsafe_code)]

pub mod api;

#[cfg(target_arch = "wasm32")]
mod runtime {
    use custody::Custodian;
    use custody_adapters::{PostgresVault, RandomIds, Sha256TokenDigest};
    use tokio_postgres::{Client, NoTls};
    use worker::postgres_tls::PassthroughTls;
    use worker::{
        Context, Env, Method, Request, Response, Result, ScheduleContext, ScheduledEvent, SecureTransport, Socket,
        event,
    };

    use crate::api::{self, ApiError, Command};

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

    async fn rate_limited(env: &Env, req: &Request) -> bool {
        // The client address is used in memory for throttling and never stored.
        let Ok(limiter) = env.rate_limiter("API_LIMITER") else { return false };
        let address = req.headers().get("CF-Connecting-IP").ok().flatten().unwrap_or_default();
        limiter.limit(api::limiter_key(&address)).await.map(|o| !o.success).unwrap_or(false)
    }

    async fn execute(command: Command, env: &Env) -> std::result::Result<(u16, String), ApiError> {
        let client = connect(env).await.map_err(|_| custody::CustodyError::VaultUnavailable)?;
        let custodian = Custodian::new(PostgresVault::new(&client), Sha256TokenDigest, RandomIds);
        Ok(match command {
            Command::Deposit(cmd) => {
                let receipt =
                    custodian.deposit(cmd.payload, cmd.retention, cmd.lifetime, cmd.revocation.as_ref()).await?;
                (201, api::receipt_body(receipt))
            }
            Command::Open(id) => (200, api::opened_body(custodian.open(&id).await?)),
            Command::Revoke(id, token) => {
                custodian.revoke(&id, &token).await?;
                (200, "{}".into())
            }
            Command::PostRequest(cmd) => {
                (201, api::request_receipt_body(custodian.post_request(cmd.recipient_key, cmd.lifetime).await?))
            }
            Command::FetchRequest(id) => (200, api::posted_request_body(custodian.fetch_request(&id).await?)),
            Command::AnswerRequest(id, answer) => (201, api::expires_body(custodian.answer_request(id, answer).await?)),
        })
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
        let body = if req.method() == Method::Post {
            if let Err(error) = api::check_declared_length(req.headers().get("Content-Length")?.as_deref()) {
                return fail(error);
            }
            req.bytes().await?
        } else {
            Vec::new()
        };
        if body.len() > api::MAX_BODY_LEN {
            return fail(ApiError::BodyTooLarge);
        }
        let command = match api::command(route, &body) {
            Ok(command) => command,
            Err(error) => return fail(error),
        };
        match execute(command, &env).await {
            Ok((status, body)) => respond(status, body),
            Err(error) => fail(error),
        }
    }

    #[event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        if let Ok(client) = connect(&env).await {
            let custodian = Custodian::new(PostgresVault::new(&client), Sha256TokenDigest, RandomIds);
            let _ = custodian.purge_expired().await;
        }
    }
}
