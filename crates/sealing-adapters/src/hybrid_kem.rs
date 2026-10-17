//! X25519 + ML-KEM-768 hybrid KEM.
//!
//! The construction follows X-Wing (draft-connolly-cfrg-xwing-kem): one
//! 32-byte seed is expanded with SHAKE256 into an ML-KEM-768 seed and an
//! X25519 secret, and the two shared secrets are combined as
//!
//! ```text
//! ss = SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || label)
//! ```
//!
//! with Sigylo's own labels for domain separation. The result stays secret
//! as long as either X25519 or ML-KEM-768 is unbroken.

use ml_kem::{B32, DecapsulationKey768, EncapsulationKey768, KeyExport, Seed, array::Array, kem::Decapsulate};
use sealing::{
    Encapsulation, Fingerprint, RecipientPublicKey, RecipientSeed, SealError, SymmetricKey,
    application::{HybridKem, Randomness},
};
use sha3::{
    Digest, Sha3_256, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const SEED_EXPAND_LABEL: &[u8] = b"sigylo/v1/hybrid-seed-expand";
const COMBINER_LABEL: &[u8] = b"sigylo/v1/x25519-mlkem768";
const FINGERPRINT_LABEL: &[u8] = b"sigylo/v1/recipient-fingerprint";

#[derive(Debug, Clone, Copy, Default)]
pub struct X25519MlKem768;

fn expand(seed: &RecipientSeed) -> (DecapsulationKey768, StaticSecret) {
    let mut xof = Shake256::default();
    xof.update(SEED_EXPAND_LABEL);
    xof.update(seed.expose());
    let mut reader = xof.finalize_xof();
    let mut mlkem_seed = Zeroizing::new([0u8; 64]);
    let mut x_secret = Zeroizing::new([0u8; 32]);
    reader.read(&mut *mlkem_seed);
    reader.read(&mut *x_secret);
    (DecapsulationKey768::from_seed(Seed::from(*mlkem_seed)), StaticSecret::from(*x_secret))
}

fn combine(ss_m: &[u8; 32], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> SymmetricKey {
    let mut h = Sha3_256::new();
    for part in [&ss_m[..], ss_x, ct_x, pk_x, COMBINER_LABEL] {
        Digest::update(&mut h, part);
    }
    SymmetricKey::from_array(h.finalize().into())
}

fn x25519_array(bytes: &[u8]) -> [u8; 32] {
    // The domain value objects guarantee the 32-byte boundary.
    bytes.try_into().expect("x25519 part is 32 bytes")
}

impl HybridKem for X25519MlKem768 {
    fn public_key(&self, seed: &RecipientSeed) -> RecipientPublicKey {
        let (dk, x_secret) = expand(seed);
        let mut out = Vec::with_capacity(RecipientPublicKey::LEN);
        out.extend_from_slice(PublicKey::from(&x_secret).as_bytes());
        out.extend_from_slice(&dk.encapsulation_key().to_bytes());
        RecipientPublicKey::from_slice(&out).expect("x25519 and ML-KEM-768 sizes add up")
    }

    fn fingerprint(&self, public_key: &RecipientPublicKey) -> Fingerprint {
        let mut h = Sha3_256::new();
        Digest::update(&mut h, FINGERPRINT_LABEL);
        Digest::update(&mut h, public_key.as_bytes());
        Fingerprint::from_array(h.finalize().into())
    }

    fn encapsulate(
        &self,
        public_key: &RecipientPublicKey,
        randomness: &dyn Randomness,
    ) -> Result<(Encapsulation, SymmetricKey), SealError> {
        let pk_x = x25519_array(public_key.x25519_part());
        let ek_bytes = Array::try_from(public_key.mlkem_part()).map_err(|_| SealError::InvalidKeyMaterial)?;
        let ek = EncapsulationKey768::new(&ek_bytes).map_err(|_| SealError::InvalidKeyMaterial)?;

        let mut eph = Zeroizing::new([0u8; 32]);
        randomness.fill(&mut *eph)?;
        let eph = StaticSecret::from(*eph);
        let ct_x = PublicKey::from(&eph);
        let ss_x = eph.diffie_hellman(&PublicKey::from(pk_x));
        if !ss_x.was_contributory() {
            return Err(SealError::InvalidKeyMaterial);
        }

        let mut m = Zeroizing::new([0u8; 32]);
        randomness.fill(&mut *m)?;
        let (ct_m, ss_m) = ek.encapsulate_deterministic(&B32::from(*m));
        let ss_m = Zeroizing::new(<[u8; 32]>::from(ss_m));

        let mut enc = Vec::with_capacity(Encapsulation::LEN);
        enc.extend_from_slice(ct_x.as_bytes());
        enc.extend_from_slice(&ct_m);
        Ok((Encapsulation::from_slice(&enc)?, combine(&ss_m, ss_x.as_bytes(), ct_x.as_bytes(), &pk_x)))
    }

    fn decapsulate(&self, seed: &RecipientSeed, encapsulation: &Encapsulation) -> Result<SymmetricKey, SealError> {
        let (dk, x_secret) = expand(seed);
        let ct_x = x25519_array(encapsulation.x25519_part());
        let ct_m = Array::try_from(encapsulation.mlkem_part()).map_err(|_| SealError::MalformedEnvelope)?;

        // ML-KEM decapsulation never fails: a bad ciphertext yields a pseudorandom
        // secret (implicit rejection), so the AEAD tag check catches it.
        let ss_m = Zeroizing::new(<[u8; 32]>::from(dk.decapsulate(&ct_m)));
        let ss_x = x_secret.diffie_hellman(&PublicKey::from(ct_x));
        if !ss_x.was_contributory() {
            return Err(SealError::NotAuthentic);
        }
        let pk_x = PublicKey::from(&x_secret);
        Ok(combine(&ss_m, ss_x.as_bytes(), &ct_x, pk_x.as_bytes()))
    }
}
