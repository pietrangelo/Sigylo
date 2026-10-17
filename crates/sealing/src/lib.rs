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
//! Either mode can add a passphrase, stretched with Argon2id.
//!
//! In recipient mode the sender can also **sign** the answer with a hybrid
//! Ed25519 + ML-DSA-65 identity ([`Sealer::new_sender`]): the recipient sees
//! the sender's [`SenderFingerprint::code`] and compares it out of band, so
//! whoever races the legitimate sender to the request link is caught.
#![forbid(unsafe_code)]

pub mod application;
pub mod core;

pub use crate::core::{
    Encapsulation, Envelope, Fingerprint, KdfCost, LinkKey, MAX_PASSPHRASE_LEN, MAX_PLAINTEXT_LEN,
    MAX_SIGNED_PLAINTEXT_LEN, Passphrase, Plaintext, RecipientPublicKey, RecipientSeed, SealError, SenderCode,
    SenderFingerprint, SenderPin, SenderPublicKey, SenderSeed, SenderSignature, SymmetricKey,
};
pub use application::{CryptoSuite, NewRecipient, NewSender, Received, Sealer};
