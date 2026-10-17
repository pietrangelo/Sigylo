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
//!
//! A file is a manifest sealed exactly like that, plus chunks sealed under
//! `HKDF-SHA3-256(salt = "sigylo/v1", ikm = file key, info = "sigylo/v1/chunk")`
//! (see [`crate::core::FileManifest`] for the chunk layout).

use zeroize::Zeroizing;

use super::ports::CryptoSuite;
use crate::core::{
    Envelope, EnvelopeHeader, FileBytes, FileKey, FileManifest, FileName, Fingerprint, KdfCost, KeySource, LinkKey,
    Nonce, Passphrase, PassphraseLock, Plaintext, RecipientPublicKey, RecipientSeed, Salt, SealError, SealedChunk,
    SymmetricKey, padding,
};

const HKDF_SALT: &[u8] = b"sigylo/v1";
const AEAD_INFO: &[u8] = b"sigylo/v1/aead";
const CHUNK_INFO: &[u8] = b"sigylo/v1/chunk";

/// A sealed file: the manifest goes where a text envelope would, the chunks
/// are uploaded after it, in order.
#[derive(Debug)]
pub struct SealedFile {
    pub manifest: Envelope,
    pub chunks: Vec<SealedChunk>,
}

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

    /// Link mode for a file: the link key opens the manifest, the manifest
    /// opens the chunks.
    pub fn seal_file_for_link(
        &self,
        name: FileName,
        contents: &FileBytes,
        passphrase: Option<&Passphrase>,
    ) -> Result<(SealedFile, LinkKey), SealError> {
        let (manifest, chunks) = self.seal_chunks(name, contents)?;
        let (envelope, key) = self.seal_for_link(&manifest.to_plaintext(), passphrase)?;
        Ok((SealedFile { manifest: envelope, chunks }, key))
    }

    /// Request mode for a file. The fingerprint is checked before any work.
    pub fn seal_file_for_recipient(
        &self,
        name: FileName,
        contents: &FileBytes,
        public_key: &RecipientPublicKey,
        expected: &Fingerprint,
        passphrase: Option<&Passphrase>,
    ) -> Result<SealedFile, SealError> {
        if self.suite.kem.fingerprint(public_key) != *expected {
            return Err(SealError::FingerprintMismatch);
        }
        let (manifest, chunks) = self.seal_chunks(name, contents)?;
        let envelope = self.seal_for_recipient(&manifest.to_plaintext(), public_key, expected, passphrase)?;
        Ok(SealedFile { manifest: envelope, chunks })
    }

    /// Opens the chunks of a file whose manifest was opened (and recognized)
    /// already. Chunks must come in order and all of them: a missing,
    /// reordered, resized or foreign chunk is [`SealError::NotAuthentic`].
    pub fn open_file(&self, manifest: &FileManifest, chunks: &[SealedChunk]) -> Result<FileBytes, SealError> {
        let positions = manifest.size().chunks();
        if positions.len() != chunks.len() {
            return Err(SealError::NotAuthentic);
        }
        let key = self.chunk_key(manifest.key());
        // Exact capacity: no reallocation leaves a copy of the contents behind.
        let mut contents = Zeroizing::new(Vec::with_capacity(manifest.size().bytes() as usize));
        for (position, chunk) in positions.zip(chunks) {
            if chunk.as_bytes().len() != position.sealed_len() {
                return Err(SealError::NotAuthentic);
            }
            let padded =
                self.suite.aead.open(&key, &position.nonce(), &position.associated_data(), chunk.as_bytes())?;
            contents.extend_from_slice(position.unpad(&padded)?);
        }
        FileBytes::new(core::mem::take(&mut *contents))
    }

    fn seal_chunks(&self, name: FileName, contents: &FileBytes) -> Result<(FileManifest, Vec<SealedChunk>), SealError> {
        let mut key = Zeroizing::new([0u8; FileKey::LEN]);
        self.suite.randomness.fill(&mut *key)?;
        let manifest = FileManifest::new(FileKey::from_array(*key), contents.size(), name);
        let chunk_key = self.chunk_key(manifest.key());
        let chunks = manifest
            .size()
            .chunks()
            .map(|position| {
                let padded = position.pad(contents.expose());
                let sealed = self.suite.aead.seal(&chunk_key, &position.nonce(), &position.associated_data(), &padded);
                SealedChunk::new(sealed)
            })
            .collect::<Result<_, _>>()?;
        Ok((manifest, chunks))
    }

    fn chunk_key(&self, key: &FileKey) -> SymmetricKey {
        self.suite.kdf.derive(HKDF_SALT, key.expose(), &[CHUNK_INFO])
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
