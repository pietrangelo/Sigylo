//! Adapters for the Sealing ports, built on pure-Rust RustCrypto crates
//! (constant-time implementations, no C, compile unchanged to Wasm).
//!
//! | Port | Adapter | Primitive |
//! |---|---|---|
//! | `Randomness` | [`SystemRandomness`] | OS CSPRNG / `crypto.getRandomValues` |
//! | `Aead` | [`XChaCha20Poly1305Aead`] | XChaCha20-Poly1305 |
//! | `PassphraseStretcher` | [`Argon2idStretcher`] | Argon2id v1.3 |
//! | `KeyDerivation` | [`HkdfSha3`] | HKDF-SHA3-256 |
//! | `HybridKem` | [`X25519MlKem768`] | X25519 + ML-KEM-768 (FIPS 203), X-Wing-style combiner |
//! | `HybridSigner` | [`Ed25519MlDsa65`] | Ed25519 + ML-DSA-65 (FIPS 204), both must verify |
#![forbid(unsafe_code)]

mod aead;
mod hybrid_kem;
mod hybrid_signer;
mod kdf;
mod randomness;

pub use aead::XChaCha20Poly1305Aead;
pub use hybrid_kem::X25519MlKem768;
pub use hybrid_signer::Ed25519MlDsa65;
pub use kdf::{Argon2idStretcher, HkdfSha3};
pub use randomness::SystemRandomness;

use sealing::CryptoSuite;

/// The production suite: every port wired to its RustCrypto adapter.
pub fn rustcrypto_suite() -> CryptoSuite<'static> {
    CryptoSuite {
        randomness: &SystemRandomness,
        aead: &XChaCha20Poly1305Aead,
        stretcher: &Argon2idStretcher,
        kdf: &HkdfSha3,
        kem: &X25519MlKem768,
        signer: &Ed25519MlDsa65,
    }
}
