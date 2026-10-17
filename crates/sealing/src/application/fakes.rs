//! Deterministic stand-ins for the crypto ports. They are NOT secure; they
//! exist so the use cases can be tested without any crypto library, which
//! keeps the domain's tests about the domain's rules.

use core::cell::Cell;

use zeroize::Zeroizing;

use super::ports::{Aead, HybridKem, HybridSigner, KeyDerivation, PassphraseStretcher, Randomness};
use crate::core::{
    Encapsulation, Fingerprint, KdfCost, Nonce, Passphrase, RecipientPublicKey, RecipientSeed, Salt, SealError,
    SenderFingerprint, SenderPublicKey, SenderSeed, SenderSignature, SymmetricKey,
};

fn fnv(parts: &[&[u8]], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = 0xcbf2_9ce4_8422_2325u64 ^ i as u64;
        for part in parts {
            for &b in *part {
                h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01B3);
            }
            h = (h ^ 0xFF).wrapping_mul(0x0000_0100_0000_01B3);
        }
        chunk.copy_from_slice(&h.to_le_bytes()[..chunk.len()]);
    }
}

#[derive(Debug, Default)]
pub struct CountingRandomness {
    counter: Cell<u8>,
    pub broken: Cell<bool>,
}

impl Randomness for CountingRandomness {
    fn fill(&self, buf: &mut [u8]) -> Result<(), SealError> {
        if self.broken.get() {
            return Err(SealError::RandomnessUnavailable);
        }
        for b in buf {
            self.counter.set(self.counter.get().wrapping_add(1));
            *b = self.counter.get();
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ToyAead;

impl Aead for ToyAead {
    fn seal(&self, key: &SymmetricKey, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut stream = vec![0u8; plaintext.len()];
        fnv(&[key.expose(), nonce.as_bytes()], &mut stream);
        let mut out: Vec<u8> = plaintext.iter().zip(&stream).map(|(p, s)| p ^ s).collect();
        let mut tag = [0u8; 16];
        fnv(&[key.expose(), nonce.as_bytes(), aad, &out], &mut tag);
        out.extend_from_slice(&tag);
        out
    }

    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let (body, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut expected = [0u8; 16];
        fnv(&[key.expose(), nonce.as_bytes(), aad, body], &mut expected);
        if expected != tag {
            return Err(SealError::NotAuthentic);
        }
        let mut stream = vec![0u8; body.len()];
        fnv(&[key.expose(), nonce.as_bytes()], &mut stream);
        Ok(Zeroizing::new(body.iter().zip(&stream).map(|(c, s)| c ^ s).collect()))
    }
}

#[derive(Debug, Default)]
pub struct RecordingStretcher {
    pub calls: Cell<u32>,
    pub last_cost: Cell<Option<KdfCost>>,
}

impl PassphraseStretcher for RecordingStretcher {
    fn stretch(&self, passphrase: &Passphrase, salt: &Salt, cost: &KdfCost) -> Result<SymmetricKey, SealError> {
        self.calls.set(self.calls.get() + 1);
        self.last_cost.set(Some(*cost));
        let mut out = [0u8; 32];
        fnv(&[b"stretch", passphrase.expose(), salt.as_bytes()], &mut out);
        Ok(SymmetricKey::from_array(out))
    }
}

#[derive(Debug)]
pub struct ToyKdf;

impl KeyDerivation for ToyKdf {
    fn derive(&self, salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> SymmetricKey {
        let mut parts = vec![salt, ikm];
        parts.extend_from_slice(info);
        let mut out = [0u8; 32];
        fnv(&parts, &mut out);
        SymmetricKey::from_array(out)
    }
}

/// Public key = seed || zeros; encapsulation = shared XOR seed || zeros.
#[derive(Debug, Default)]
pub struct ToyKem {
    pub encapsulations: Cell<u32>,
}

impl HybridKem for ToyKem {
    fn public_key(&self, seed: &RecipientSeed) -> RecipientPublicKey {
        let mut pk = vec![0u8; RecipientPublicKey::LEN];
        pk[..32].copy_from_slice(seed.expose());
        RecipientPublicKey::from_slice(&pk).unwrap()
    }

    fn fingerprint(&self, public_key: &RecipientPublicKey) -> Fingerprint {
        let mut out = [0u8; 32];
        fnv(&[public_key.as_bytes()], &mut out);
        Fingerprint::from_array(out)
    }

    fn encapsulate(
        &self,
        public_key: &RecipientPublicKey,
        randomness: &dyn Randomness,
    ) -> Result<(Encapsulation, SymmetricKey), SealError> {
        self.encapsulations.set(self.encapsulations.get() + 1);
        let mut shared = [0u8; 32];
        randomness.fill(&mut shared)?;
        let mut enc = vec![0u8; Encapsulation::LEN];
        for i in 0..32 {
            enc[i] = shared[i] ^ public_key.x25519_part()[i];
        }
        Ok((Encapsulation::from_slice(&enc)?, SymmetricKey::from_array(shared)))
    }

    fn decapsulate(&self, seed: &RecipientSeed, encapsulation: &Encapsulation) -> Result<SymmetricKey, SealError> {
        let mut shared = [0u8; 32];
        for ((s, e), k) in shared.iter_mut().zip(encapsulation.x25519_part()).zip(seed.expose()) {
            *s = e ^ k;
        }
        Ok(SymmetricKey::from_array(shared))
    }
}

/// Public key = seed || zeros; signature = hash(seed, message) || zeros, so
/// anyone holding the public key could forge one: fine for testing rules.
#[derive(Debug, Default)]
pub struct ToySigner {
    pub signatures: Cell<u32>,
}

impl HybridSigner for ToySigner {
    fn public_key(&self, seed: &SenderSeed) -> SenderPublicKey {
        let mut pk = vec![0u8; SenderPublicKey::LEN];
        pk[..32].copy_from_slice(seed.expose());
        SenderPublicKey::from_slice(&pk).unwrap()
    }

    fn fingerprint(&self, public_key: &SenderPublicKey) -> SenderFingerprint {
        let mut out = [0u8; 32];
        fnv(&[b"sender", public_key.as_bytes()], &mut out);
        SenderFingerprint::from_array(out)
    }

    fn sign(&self, seed: &SenderSeed, message: &[u8]) -> SenderSignature {
        self.signatures.set(self.signatures.get() + 1);
        let mut sig = vec![0u8; SenderSignature::LEN];
        fnv(&[seed.expose(), message], &mut sig[..32]);
        SenderSignature::from_slice(&sig).unwrap()
    }

    fn verify(&self, public_key: &SenderPublicKey, message: &[u8], signature: &SenderSignature) -> bool {
        let mut expected = vec![0u8; SenderSignature::LEN];
        fnv(&[&public_key.as_bytes()[..32], message], &mut expected[..32]);
        public_key.as_bytes()[32..].iter().all(|&b| b == 0) && expected == signature.as_bytes()
    }
}
