//! Use cases of the Sealing context.
//!
//! Key schedule, the same for both modes:
//!
//! ```text
//! ikm = base_secret || Argon2id(passphrase)      (second part only with a passphrase)
//! key = HKDF-SHA3-256(salt = "sigylo/v1", ikm, info = "sigylo/v1/aead" || mode)
//! ```
//!
//! `base_secret` is the link key (link mode) or the hybrid KEM shared secret
//! (recipient mode). The whole envelope header is the AEAD associated data.

use zeroize::Zeroizing;

use super::ports::CryptoSuite;
use crate::core::{
    Envelope, EnvelopeHeader, Fingerprint, KdfCost, KeySource, LinkKey, Nonce, Passphrase, PassphraseLock, Plaintext,
    RecipientPublicKey, RecipientSeed, Salt, SealError, SymmetricKey, padding,
};

const HKDF_SALT: &[u8] = b"sigylo/v1";
const AEAD_INFO: &[u8] = b"sigylo/v1/aead";

/// A recipient key pair fresh from [`Sealer::new_recipient`].
#[derive(Debug)]
pub struct NewRecipient {
    /// Stays on the recipient's device (in their private link).
    pub seed: RecipientSeed,
    /// Uploaded to the relay.
    pub public_key: RecipientPublicKey,
    /// Shared with the sender inside the request link.
    pub fingerprint: Fingerprint,
}

/// Seals and opens envelopes using the ports of a [`CryptoSuite`].
#[derive(Debug, Clone, Copy)]
pub struct Sealer<'a> {
    suite: CryptoSuite<'a>,
    kdf_cost: KdfCost,
}

impl<'a> Sealer<'a> {
    pub fn new(suite: CryptoSuite<'a>) -> Self {
        Self { suite, kdf_cost: KdfCost::RECOMMENDED }
    }

    /// Use a different (still in-range) Argon2id cost when sealing.
    pub fn with_kdf_cost(self, kdf_cost: KdfCost) -> Self {
        Self { kdf_cost, ..self }
    }

    /// Link mode: seal under a fresh random key that only the link will carry.
    pub fn seal_for_link(
        &self,
        plaintext: &Plaintext,
        passphrase: Option<&Passphrase>,
    ) -> Result<(Envelope, LinkKey), SealError> {
        let mut key = Zeroizing::new([0u8; 32]);
        self.suite.randomness.fill(&mut *key)?;
        let link_key = LinkKey::from_array(*key);
        let envelope = self.seal(KeySource::LinkKey, link_key.expose(), plaintext, passphrase)?;
        Ok((envelope, link_key))
    }

    /// Link mode under a key the caller already holds (an account's keyring
    /// key): the same envelope as [`Self::seal_for_link`], opened with
    /// [`Self::open_link`]. A fresh nonce every time, so resealing is safe.
    pub fn seal_with_link_key(&self, plaintext: &Plaintext, key: &LinkKey) -> Result<Envelope, SealError> {
        self.seal(KeySource::LinkKey, key.expose(), plaintext, None)
    }

    pub fn open_link(
        &self,
        envelope: &Envelope,
        key: &LinkKey,
        passphrase: Option<&Passphrase>,
    ) -> Result<Plaintext, SealError> {
        if envelope.header().source != KeySource::LinkKey {
            return Err(SealError::WrongMode);
        }
        self.open(envelope, key.expose(), passphrase)
    }

    /// Request mode, recipient side: make a key pair to receive one secret.
    pub fn new_recipient(&self) -> Result<NewRecipient, SealError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        self.suite.randomness.fill(&mut *seed)?;
        let seed = RecipientSeed::from_array(*seed);
        let public_key = self.suite.kem.public_key(&seed);
        let fingerprint = self.suite.kem.fingerprint(&public_key);
        Ok(NewRecipient { seed, public_key, fingerprint })
    }

    /// Request mode, sender side. Refuses to seal if the relay served a
    /// public key that does not match the fingerprint from the request link.
    pub fn seal_for_recipient(
        &self,
        plaintext: &Plaintext,
        public_key: &RecipientPublicKey,
        expected: &Fingerprint,
        passphrase: Option<&Passphrase>,
    ) -> Result<Envelope, SealError> {
        if self.suite.kem.fingerprint(public_key) != *expected {
            return Err(SealError::FingerprintMismatch);
        }
        let (encapsulation, shared) = self.suite.kem.encapsulate(public_key, self.suite.randomness)?;
        self.seal(KeySource::Recipient(encapsulation), shared.expose(), plaintext, passphrase)
    }

    pub fn open_as_recipient(
        &self,
        envelope: &Envelope,
        seed: &RecipientSeed,
        passphrase: Option<&Passphrase>,
    ) -> Result<Plaintext, SealError> {
        let KeySource::Recipient(encapsulation) = &envelope.header().source else {
            return Err(SealError::WrongMode);
        };
        let shared = self.suite.kem.decapsulate(seed, encapsulation)?;
        self.open(envelope, shared.expose(), passphrase)
    }

    fn seal(
        &self,
        source: KeySource,
        base: &[u8; 32],
        plaintext: &Plaintext,
        passphrase: Option<&Passphrase>,
    ) -> Result<Envelope, SealError> {
        let lock = match passphrase {
            Some(_) => {
                let mut salt = [0u8; Salt::LEN];
                self.suite.randomness.fill(&mut salt)?;
                Some(PassphraseLock { salt: Salt::from_array(salt), cost: self.kdf_cost })
            }
            None => None,
        };
        let mut nonce = [0u8; Nonce::LEN];
        self.suite.randomness.fill(&mut nonce)?;
        let header = EnvelopeHeader { source, passphrase: lock, nonce: Nonce::from_array(nonce) };

        let key = self.message_key(&header, base, passphrase)?;
        let aad = header.to_bytes();
        let ciphertext = self.suite.aead.seal(&key, &header.nonce, &aad, &padding::pad(plaintext));
        Envelope::new(header, ciphertext)
    }

    fn open(
        &self,
        envelope: &Envelope,
        base: &[u8; 32],
        passphrase: Option<&Passphrase>,
    ) -> Result<Plaintext, SealError> {
        let header = envelope.header();
        let key = self.message_key(header, base, passphrase)?;
        let padded = self.suite.aead.open(&key, &header.nonce, &header.to_bytes(), envelope.ciphertext())?;
        padding::unpad(&padded)
    }

    fn message_key(
        &self,
        header: &EnvelopeHeader,
        base: &[u8; 32],
        passphrase: Option<&Passphrase>,
    ) -> Result<SymmetricKey, SealError> {
        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(base);
        match (&header.passphrase, passphrase) {
            (Some(lock), Some(passphrase)) => {
                let stretched = self.suite.stretcher.stretch(passphrase, &lock.salt, &lock.cost)?;
                ikm.extend_from_slice(stretched.expose());
            }
            (None, None) => {}
            _ => return Err(SealError::PassphraseExpectationMismatch),
        }
        let mode = [header.source.mode_byte()];
        Ok(self.suite.kdf.derive(HKDF_SALT, &ikm, &[AEAD_INFO, &mode]))
    }
}
