//! # Custody (bounded context)
//!
//! The relay's whole job, and nothing more: keep a sealed envelope for a
//! limited time, hand it to whoever presents its unguessable id, and destroy
//! it on first read (burn after reading) or at expiry. Custody never sees a
//! key or a plaintext; a payload is opaque bytes.
#![forbid(unsafe_code)]

pub mod application;
pub mod core;

pub use crate::core::{
    CustodyError, Deposit, DropId, Lifetime, MAX_PAYLOAD_LEN, Opened, PostedRequest, RecipientKeyBlob, Request,
    Retention, RevocationDigest, RevocationToken, SealedPayload, UnixTime,
};
pub use application::{Answer, Custodian, TokenDigest, Vault};
