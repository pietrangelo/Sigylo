//! Ports: the cryptographic capabilities the domain needs, without naming
//! any library. `sealing-adapters` implements them with audited RustCrypto
//! primitives; tests can plug in deterministic fakes.

use zeroize::Zeroizing;

use crate::core::{
    Encapsulation, Fingerprint, KdfCost, Nonce, Passphrase, RecipientPublicKey, RecipientSeed, Salt, SealError,
    SenderFingerprint, SenderPublicKey, SenderSeed, SenderSignature, SymmetricKey,
};

/// A cryptographically secure random source.
pub trait Randomness {
    fn fill(&self, buf: &mut [u8]) -> Result<(), SealError>;
}

/// Authenticated encryption with associated data (XChaCha20-Poly1305).
pub trait Aead {
    fn seal(&self, key: &SymmetricKey, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// Must return [`SealError::NotAuthentic`] on any authentication failure
    /// and never release unauthenticated plaintext.
    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError>;
}

/// Memory-hard passphrase stretching (Argon2id).
pub trait PassphraseStretcher {
    fn stretch(&self, passphrase: &Passphrase, salt: &Salt, cost: &KdfCost) -> Result<SymmetricKey, SealError>;
}

/// Extract-and-expand key derivation (HKDF-SHA3-256).
pub trait KeyDerivation {
    fn derive(&self, salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> SymmetricKey;
}

/// The hybrid X25519 + ML-KEM-768 key encapsulation mechanism.
pub trait HybridKem {
    /// The public key belonging to `seed` (deterministic).
    fn public_key(&self, seed: &RecipientSeed) -> RecipientPublicKey;

    /// A domain-separated hash of the public key.
    fn fingerprint(&self, public_key: &RecipientPublicKey) -> Fingerprint;

    fn encapsulate(
        &self,
        public_key: &RecipientPublicKey,
        randomness: &dyn Randomness,
    ) -> Result<(Encapsulation, SymmetricKey), SealError>;

    fn decapsulate(&self, seed: &RecipientSeed, encapsulation: &Encapsulation) -> Result<SymmetricKey, SealError>;
}

/// The hybrid Ed25519 + ML-DSA-65 signature scheme of sender identities.
pub trait HybridSigner {
    /// The public key belonging to `seed` (deterministic).
    fn public_key(&self, seed: &SenderSeed) -> SenderPublicKey;

    /// A domain-separated hash of the public key.
    fn fingerprint(&self, public_key: &SenderPublicKey) -> SenderFingerprint;

    fn sign(&self, seed: &SenderSeed, message: &[u8]) -> SenderSignature;

    /// True only if every half of the hybrid signature verifies under its
    /// half of `public_key`. Must never panic, whatever the bytes.
    fn verify(&self, public_key: &SenderPublicKey, message: &[u8], signature: &SenderSignature) -> bool;
}

/// The set of ports one [`crate::Sealer`] works with.
#[derive(Clone, Copy)]
pub struct CryptoSuite<'a> {
    pub randomness: &'a dyn Randomness,
    pub aead: &'a dyn Aead,
    pub stretcher: &'a dyn PassphraseStretcher,
    pub kdf: &'a dyn KeyDerivation,
    pub kem: &'a dyn HybridKem,
    pub signer: &'a dyn HybridSigner,
}

impl core::fmt::Debug for CryptoSuite<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CryptoSuite")
    }
}
