//! # Vault (bounded context)
//!
//! Sigylo's own store for the Custody context, so the relay needs nothing
//! but Cloudflare: the custody rules (burn after reading, expiry, claims,
//! garbage, ceilings) written in Rust over an ordered key-value store whose
//! calls are synchronous, so each step is atomic (a Durable Object's
//! storage), while every sealed byte, payloads and chunks alike, lives in an
//! object store (R2) where a burn really deletes it.
//!
//! The vault runs inside one Durable Object; the relay reaches it through a
//! [`RemoteVault`], one call per [`custody::Vault`] method. The accounts
//! (the Access store) run in a Durable Object of their own, reached
//! through a [`RemoteAccounts`].
#![forbid(unsafe_code)]

pub mod application;
pub mod core;

pub use crate::core::{
    AccountCall, AccountReply, Call, Class, DepositRecord, GarbageEntry, INCOMPLETE_FILE_SECONDS, OBJECT_BYTES_CEILING,
    PURGE_BATCH, RECORD_CEILING, Reply, RequestRecord, STORING_WRITES_PER_DAY, Stored, TEARDOWN_WRITES_PER_DAY, Usage,
};
pub use application::{
    AccountLedger, Accounts, Bucket, Clock, KeyValue, Ledger, LedgerVault, Link, PayloadStore, RemoteAccounts,
    RemoteVault, Scratch, VaultThrottle, serve, serve_accounts,
};
