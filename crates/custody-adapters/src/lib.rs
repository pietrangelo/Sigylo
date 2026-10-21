//! Adapters for the Custody ports.
//!
//! * [`Sha256TokenDigest`] — SHA-256 of revocation tokens.
//! * [`RandomIds`] — the ids of deposits and requests, from the CSPRNG.
//! * `R2ChunkStore` — the chunks of files in a Cloudflare R2 bucket (in the
//!   Worker only: it needs the bucket binding).
#![forbid(unsafe_code)]

mod r2_chunk_store;
mod random_ids;
mod token_digest;

#[cfg(target_arch = "wasm32")]
pub use r2_chunk_store::R2ChunkStore;
pub use r2_chunk_store::object_key;
pub use random_ids::RandomIds;
pub use token_digest::Sha256TokenDigest;
