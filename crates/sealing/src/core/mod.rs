//! Core ring: immutable value objects and the envelope wire format.
//! Pure Rust, no I/O, no clock, no randomness: everything here is deterministic.

mod envelope;
mod error;
mod file;
mod kdf;
pub mod padding;
mod recipient;
mod secrets;

pub use envelope::{Envelope, EnvelopeHeader, KeySource, Nonce, PassphraseLock, TAG_LEN};
pub use error::SealError;
pub use file::{
    CHUNK_LEN, ChunkPosition, FileBytes, FileManifest, FileName, FileSize, MAX_CHUNKS, MAX_FILE_LEN, MAX_NAME_LEN,
    SealedChunk,
};
pub use kdf::{KdfCost, Salt};
pub use recipient::{
    Encapsulation, Fingerprint, MLKEM768_CIPHERTEXT_LEN, MLKEM768_PUBLIC_LEN, RecipientPublicKey, X25519_LEN,
};
pub use secrets::{
    FileKey, KEY_LEN, LinkKey, MAX_PASSPHRASE_LEN, MAX_PLAINTEXT_LEN, Passphrase, Plaintext, RecipientSeed,
    SymmetricKey,
};
