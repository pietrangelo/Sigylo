//! # Custody (bounded context)
//!
//! The relay's whole job, and nothing more: keep a sealed envelope for a
//! limited time under an unguessable id of its own choosing, hand it to
//! whoever presents that id, and destroy it on first read (burn after
//! reading) or at expiry. Custody never sees a key or a plaintext; a payload
//! is opaque bytes.
#![forbid(unsafe_code)]

pub mod application;
pub mod core;

pub use crate::core::{
    CLAIM_WINDOW_SECONDS, ChunkCount, ChunkIndex, ClaimDigest, ClaimToken, CustodyError, Deposit, DropId, Lifetime,
    MAX_CHUNK_LEN, MAX_CHUNKS, MAX_PAYLOAD_LEN, Opened, PostedRequest, Receipt, RecipientKeyBlob, Request, Retention,
    RevocationDigest, RevocationToken, SealedChunk, SealedPayload, UnixTime,
};
pub use application::{Answer, Custodian, IdSource, TokenDigest, Vault};
