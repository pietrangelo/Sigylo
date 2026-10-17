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
    use custody_adapters::{PostgresVault, Sha256TokenDigest};
    use tokio_postgres::{Client, NoTls};
    use worker::postgres_tls::PassthroughTls;
    use worker::{
        Context, Env, Method, Request, Response, Result, ScheduleContext, ScheduledEvent, SecureTransport, Socket,
        event,
    };

    use crate::api::{self, ApiError, Route};

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
        let Ok(limiter) = env.rate_limiter("WRITE_LIMITER") else { return false };
        let key = req.headers().get("CF-Connecting-IP").ok().flatten().unwrap_or_default();
        limiter.limit(key).await.map(|o| !o.success).unwrap_or(false)
    }

    async fn dispatch(route: Route, body: &[u8], env: &Env) -> std::result::Result<(u16, String), ApiError> {
        let client = connect(env).await.map_err(|_| custody::CustodyError::VaultUnavailable)?;
        let custodian = Custodian::new(PostgresVault::new(&client), Sha256TokenDigest);
        Ok(match route {
            Route::Deposit => {
                let cmd = api::parse_deposit(body)?;
                let expires = custodian
                    .deposit(cmd.id, cmd.payload, cmd.retention, cmd.lifetime, cmd.revocation.as_ref())
                    .await?;
                (201, api::expires_body(expires))
            }
            Route::Open(id) => (200, api::opened_body(custodian.open(&id).await?)),
            Route::Revoke(id) => {
                custodian.revoke(&id, &api::parse_revoke(body)?).await?;
                (200, "{}".into())
            }
            Route::PostRequest => (201, api::expires_body(custodian.post_request(api::parse_request(body)?).await?)),
            Route::FetchRequest(id) => (200, api::posted_request_body(custodian.fetch_request(&id).await?)),
            Route::AnswerRequest(id) => {
                (201, api::expires_body(custodian.answer_request(id, api::parse_answer(body)?).await?))
            }
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
        let body = if req.method() == Method::Post { req.bytes().await? } else { Vec::new() };
        if body.len() > api::MAX_BODY_LEN {
            return fail(ApiError::BodyTooLarge);
        }
        match dispatch(route, &body, &env).await {
            Ok((status, body)) => respond(status, body),
            Err(error) => fail(error),
        }
    }

    #[event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        if let Ok(client) = connect(&env).await {
            let custodian = Custodian::new(PostgresVault::new(&client), Sha256TokenDigest);
            let _ = custodian.purge_expired().await;
        }
    }
}
