//! # Sealing (bounded context)
//!
//! Turns a secret into an envelope that only the intended reader can open,
//! and back. Pure domain: the cryptographic primitives arrive through the
//! ports in [`application`], implemented in `sealing-adapters`.
//!
//! Two ways to seal:
//!
//! * **Link mode** — [`Sealer::seal_for_link`]: a fresh 256-bit key per
//!   secret, carried only in the URL fragment. Symmetric 256-bit keys are
//!   already post-quantum (Grover leaves 2^128 work).
//! * **Recipient mode** — [`Sealer::seal_for_recipient`]: the recipient makes
//!   a hybrid X25519 + ML-KEM-768 key pair on their device and shares only the
//!   public key's fingerprint. No decryption key travels over any channel,
//!   and recorded traffic stays safe unless both X25519 and ML-KEM fall.
//!
//! Files ride on either mode: a sealed manifest carries a fresh key that
//! opens the file's chunks ([`Sealer::seal_file_for_link`],
//! [`Sealer::seal_file_for_recipient`], [`Sealer::open_file`]).
//!
//! Either mode can add a passphrase, stretched with Argon2id.
#![forbid(unsafe_code)]

pub mod application;
pub mod core;

pub use crate::core::{
    CHUNK_LEN, Encapsulation, Envelope, FileBytes, FileManifest, FileName, Fingerprint, KdfCost, LinkKey, MAX_CHUNKS,
    MAX_FILE_LEN, MAX_NAME_LEN, MAX_PASSPHRASE_LEN, MAX_PLAINTEXT_LEN, Passphrase, Plaintext, RecipientPublicKey,
    RecipientSeed, SealError, SealedChunk, SymmetricKey,
};
pub use application::{CryptoSuite, NewRecipient, SealedFile, Sealer};
