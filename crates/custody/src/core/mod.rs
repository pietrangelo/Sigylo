//! Core ring: value objects of the Custody context. Pure and deterministic.
//!
//! The relay is blind: a [`SealedPayload`] is opaque bytes. Custody knows
//! how big a payload may be and how long it may live, never what it says.

mod error;
mod values;

pub use error::CustodyError;
pub use values::{
    CLAIM_WINDOW_SECONDS, ChunkCount, ChunkIndex, ClaimDigest, ClaimToken, Deposit, DropId, Lifetime, MAX_CHUNK_LEN,
    MAX_CHUNKS, MAX_PAYLOAD_LEN, Opened, PostedRequest, Receipt, RecipientKeyBlob, Request, Retention,
    RevocationDigest, RevocationToken, SealedChunk, SealedPayload, UnixTime,
};
