//! Core ring: immutable value objects and the envelope wire format.
//! Pure Rust, no I/O, no clock, no randomness: everything here is deterministic.

mod envelope;
mod error;
mod kdf;
pub mod padding;
mod recipient;
mod secrets;
mod sender;
mod signed;

pub use envelope::{Envelope, EnvelopeHeader, KeySource, Nonce, PassphraseLock, TAG_LEN};
pub use error::SealError;
pub use kdf::{KdfCost, Salt};
pub use recipient::{
    Encapsulation, Fingerprint, MLKEM768_CIPHERTEXT_LEN, MLKEM768_PUBLIC_LEN, RecipientPublicKey, X25519_LEN,
};
pub use secrets::{
    KEY_LEN, LinkKey, MAX_PASSPHRASE_LEN, MAX_PLAINTEXT_LEN, Passphrase, Plaintext, RecipientSeed, SenderSeed,
    SymmetricKey,
};
pub use sender::{
    ED25519_PUBLIC_LEN, ED25519_SIGNATURE_LEN, MLDSA65_PUBLIC_LEN, MLDSA65_SIGNATURE_LEN, SenderFingerprint,
    SenderPublicKey, SenderSignature,
};
pub use signed::{MAX_SIGNED_PLAINTEXT_LEN, SIGNATURE_BLOCK_LEN, SignedPlaintext, signed_message};
