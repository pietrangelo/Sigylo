//! Adapters for the Access ports.
//!
//! * [`OpaqueKeys`] — the relay's side of OPAQUE, from one 32-byte secret.
//! * [`OpaqueDevice`] — the device's side of OPAQUE.
//! * [`HkdfKeyringKdf`] — export key → keyring key (HKDF-SHA-512).
//! * [`RandomTokens`], [`HmacSessionDigest`] — session tokens, login
//!   handles and the digest the store keeps instead of a token.
//! * [`HmacPasses`], [`throttle_bucket`] — device passes, and the key under
//!   which a throttle counts each budget.
//! * `PostgresAccounts` (feature `postgres`) — the account store, reached
//!   through the `access.*` functions of `supabase/migrations`.
//!
//! The OPAQUE suite of Sigylo v1 is [`Suite`]: ristretto255 for the OPRF and
//! the 3DH key exchange, SHA-512, and Argon2id (64 MiB, 3 passes, 1 lane) as
//! the key stretching function. Changing any part of it locks every account
//! out, so `tests/opaque_pin.rs` pins it.
#![forbid(unsafe_code)]

mod client;
mod keyring;
mod passes;
#[cfg(feature = "postgres")]
mod postgres_store;
mod rng;
mod server;
mod suite;
mod tokens;

pub use client::OpaqueDevice;
pub use keyring::HkdfKeyringKdf;
pub use passes::{HmacPasses, throttle_bucket};
#[cfg(feature = "postgres")]
pub use postgres_store::{PostgresAccounts, PostgresThrottle};
pub use server::OpaqueKeys;
pub use suite::{HARDENING_LANES, HARDENING_MEMORY_KIB, HARDENING_PASSES, Hardening, Suite};
pub use tokens::{HmacSessionDigest, RandomTokens};
