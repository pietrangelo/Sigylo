//! Adapters for the Custody ports.
//!
//! * [`PostgresVault`] — the vault on PostgreSQL (Supabase), reached through
//!   the `custody.*` functions of `supabase/migrations`. It works with any
//!   connected `tokio_postgres::Client`: a native TCP connection in tests,
//!   a Cloudflare Hyperdrive socket in the Worker.
//! * [`Sha256TokenDigest`] — SHA-256 of revocation tokens.
#![forbid(unsafe_code)]

mod postgres_vault;
mod token_digest;

pub use postgres_vault::PostgresVault;
pub use token_digest::Sha256TokenDigest;
