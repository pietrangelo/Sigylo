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
//!
//! A sender may sign an answer to a request with their identity: the sealed
//! plaintext becomes a [`SignedPlaintext`] over [`signed_message`], and the
//! recipient learns who signed only after the signature verifies.

use zeroize::Zeroizing;

use super::ports::CryptoSuite;
use crate::core::{
    Envelope, EnvelopeHeader, FileBytes, FileKey, FileManifest, FileName, Fingerprint, KdfCost, KeySource, LinkKey,
    MAX_SIGNED_PLAINTEXT_LEN, Nonce, Passphrase, PassphraseLock, Plaintext, RecipientPublicKey, RecipientSeed, Salt,
    SealError, SealedChunk, SenderCode, SenderFingerprint, SenderPin, SenderPublicKey, SenderSeed, SignedPlaintext,
    SymmetricKey, padding, signed_message,
};

const HKDF_SALT: &[u8] = b"sigylo/v1";
const AEAD_INFO: &[u8] = b"sigylo/v1/aead";
const PIN_INFO: &[u8] = b"sigylo/v1/expected-sender";

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

/// A sender identity fresh from [`Sealer::new_sender`].
#[derive(Debug)]
pub struct NewSender {
    /// Stays on the sender's device.
    pub seed: SenderSeed,
    /// Travels, sealed, inside every signed answer.
    pub public_key: SenderPublicKey,
    /// What the sender reads out so the recipient can recognize them.
    pub fingerprint: SenderFingerprint,
}

/// What a recipient gets from opening an answer.
#[derive(Debug, PartialEq, Eq)]
pub struct Received {
    pub plaintext: Plaintext,
    /// Who signed, once the signature has verified; `None` if unsigned.
    pub sender: Option<SenderFingerprint>,
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
        let header = self.header(KeySource::LinkKey, passphrase, false)?;
        let envelope = self.encrypt(header, link_key.expose(), plaintext, passphrase)?;
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

    /// Request mode, sender side: make the identity that signs answers.
    pub fn new_sender(&self) -> Result<NewSender, SealError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        self.suite.randomness.fill(&mut *seed)?;
        let seed = SenderSeed::from_array(*seed);
        let public_key = self.suite.signer.public_key(&seed);
        let fingerprint = self.suite.signer.fingerprint(&public_key);
        Ok(NewSender { seed, public_key, fingerprint })
    }

    /// The fingerprint of a stored identity, to show the sender their code.
    pub fn sender_fingerprint(&self, seed: &SenderSeed) -> SenderFingerprint {
        self.suite.signer.fingerprint(&self.suite.signer.public_key(seed))
    }

    /// Request mode, recipient side: commit to the sender expected to
    /// answer the request whose key has fingerprint `recipient`.
    ///
    /// ```text
    /// pin = HKDF-SHA3-256(salt = "sigylo/v1", ikm = code, info = "sigylo/v1/expected-sender" || recipient)
    /// ```
    ///
    /// Every request has its own key, so the same code gives unrelated pins.
    pub fn sender_pin(&self, recipient: &Fingerprint, code: &SenderCode) -> SenderPin {
        let key = self.suite.kdf.derive(HKDF_SALT, code.as_bytes(), &[PIN_INFO, recipient.as_bytes()]);
        SenderPin::from_array(*key.expose())
    }

    /// Request mode, sender side: whether `seed` is the sender `pin` expects.
    pub fn is_expected_sender(&self, recipient: &Fingerprint, pin: &SenderPin, seed: &SenderSeed) -> bool {
        self.sender_pin(recipient, &self.sender_fingerprint(seed).sender_code()) == *pin
    }

    /// Request mode, sender side. Refuses to seal if the relay served a
    /// public key that does not match the fingerprint from the request link,
    /// or if the request expects another sender (`expected_sender`): an
    /// honest sender then keeps the request's single answer free.
    /// With a `sender` identity the answer is signed, bound to this recipient
    /// and to this very envelope.
    pub fn seal_for_recipient(
        &self,
        plaintext: &Plaintext,
        public_key: &RecipientPublicKey,
        expected: &Fingerprint,
        passphrase: Option<&Passphrase>,
        sender: Option<&SenderSeed>,
        expected_sender: Option<&SenderPin>,
    ) -> Result<Envelope, SealError> {
        if self.suite.kem.fingerprint(public_key) != *expected {
            return Err(SealError::FingerprintMismatch);
        }
        if let Some(pin) = expected_sender
            && !sender.is_some_and(|seed| self.is_expected_sender(expected, pin, seed))
        {
            return Err(SealError::UnexpectedSender);
        }
        if sender.is_some() && plaintext.expose().len() > MAX_SIGNED_PLAINTEXT_LEN {
            return Err(SealError::PlaintextTooLarge);
        }
        let (encapsulation, shared) = self.suite.kem.encapsulate(public_key, self.suite.randomness)?;
        let header = self.header(KeySource::Recipient(encapsulation), passphrase, sender.is_some())?;
        let Some(seed) = sender else {
            return self.encrypt(header, shared.expose(), plaintext, passphrase);
        };
        let message = signed_message(expected, &header.to_bytes(), plaintext);
        let signed = SignedPlaintext {
            sender: self.suite.signer.public_key(seed),
            signature: self.suite.signer.sign(seed, &message),
            plaintext: plaintext.clone(),
        };
        self.encrypt(header, shared.expose(), &signed.to_plaintext()?, passphrase)
    }

    /// Request mode, recipient side. A signed answer opens only if its
    /// signature verifies for this recipient; a bad one is as
    /// [`SealError::NotAuthentic`] as a tampered envelope. With an
    /// `expected_sender`, an answer from anyone else, or unsigned, is
    /// [`SealError::UnexpectedSender`] and its plaintext is wiped unread.
    pub fn open_as_recipient(
        &self,
        envelope: &Envelope,
        seed: &RecipientSeed,
        passphrase: Option<&Passphrase>,
        expected_sender: Option<&SenderPin>,
    ) -> Result<Received, SealError> {
        let received = self.open_answer(envelope, seed, passphrase)?;
        if let Some(pin) = expected_sender {
            let me = self.suite.kem.fingerprint(&self.suite.kem.public_key(seed));
            let matches = received.sender.is_some_and(|sender| self.sender_pin(&me, &sender.sender_code()) == *pin);
            if !matches {
                return Err(SealError::UnexpectedSender);
            }
        }
        Ok(received)
    }

    fn open_answer(
        &self,
        envelope: &Envelope,
        seed: &RecipientSeed,
        passphrase: Option<&Passphrase>,
    ) -> Result<Received, SealError> {
        let KeySource::Recipient(encapsulation) = &envelope.header().source else {
            return Err(SealError::WrongMode);
        };
        let shared = self.suite.kem.decapsulate(seed, encapsulation)?;
        let inner = self.open(envelope, shared.expose(), passphrase)?;
        if !envelope.is_signed() {
            return Ok(Received { plaintext: inner, sender: None });
        }
        let signed = SignedPlaintext::parse(&inner).map_err(|_| SealError::NotAuthentic)?;
        let me = self.suite.kem.fingerprint(&self.suite.kem.public_key(seed));
        let message = signed_message(&me, &envelope.header().to_bytes(), &signed.plaintext);
        if !self.suite.signer.verify(&signed.sender, &message, &signed.signature) {
            return Err(SealError::NotAuthentic);
        }
        Ok(Received { sender: Some(self.suite.signer.fingerprint(&signed.sender)), plaintext: signed.plaintext })
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

    /// Request mode for a file, signed with `sender` if given. The fingerprint
    /// and the expected sender are checked before any work.
    #[allow(clippy::too_many_arguments)] // seal_for_recipient's arguments, with a name and contents for the plaintext
    pub fn seal_file_for_recipient(
        &self,
        name: FileName,
        contents: &FileBytes,
        public_key: &RecipientPublicKey,
        expected: &Fingerprint,
        passphrase: Option<&Passphrase>,
        sender: Option<&SenderSeed>,
        expected_sender: Option<&SenderPin>,
    ) -> Result<SealedFile, SealError> {
        if self.suite.kem.fingerprint(public_key) != *expected {
            return Err(SealError::FingerprintMismatch);
        }
        if let Some(pin) = expected_sender
            && !sender.is_some_and(|seed| self.is_expected_sender(expected, pin, seed))
        {
            return Err(SealError::UnexpectedSender);
        }
        let (manifest, chunks) = self.seal_chunks(name, contents)?;
        let envelope = self.seal_for_recipient(
            &manifest.to_plaintext(),
            public_key,
            expected,
            passphrase,
            sender,
            expected_sender,
        )?;
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

    fn header(
        &self,
        source: KeySource,
        passphrase: Option<&Passphrase>,
        signed: bool,
    ) -> Result<EnvelopeHeader, SealError> {
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
        Ok(EnvelopeHeader { source, passphrase: lock, signed, nonce: Nonce::from_array(nonce) })
    }

    fn encrypt(
        &self,
        header: EnvelopeHeader,
        base: &[u8; 32],
        plaintext: &Plaintext,
        passphrase: Option<&Passphrase>,
    ) -> Result<Envelope, SealError> {
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
