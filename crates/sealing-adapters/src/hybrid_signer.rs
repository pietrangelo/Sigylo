//! Ed25519 + ML-DSA-65 hybrid signatures.
//!
//! One 32-byte seed is expanded with SHAKE256 into an ML-DSA-65 seed
//! (FIPS 204 `KeyGen_internal`) and an Ed25519 secret key. Both halves sign
//! the same message, prefixed with a label and the whole hybrid public key,
//! so neither half can be lifted into another key or another protocol:
//!
//! ```text
//! m'      = label || pk_ed25519 || vk_mldsa65 || message
//! sig     = Ed25519.Sign(m') || ML-DSA-65.Sign(m', ctx = label)
//! valid  <=> Ed25519.VerifyStrict(m') AND ML-DSA-65.Verify(m', ctx = label)
//! ```
//!
//! A forgery needs both schemes broken: Ed25519 holds against today's
//! attackers, ML-DSA-65 against a future quantum computer. ML-DSA signs in
//! its deterministic variant, like Ed25519, so the port needs no randomness.

use ed25519_dalek::{Signer, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Seed, Signature as MlDsaSignature, SigningKey,
    VerifyingKey,
};
use sealing::{SenderFingerprint, SenderPublicKey, SenderSeed, SenderSignature, application::HybridSigner};
use sha3::{
    Digest, Sha3_256, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

const SEED_EXPAND_LABEL: &[u8] = b"sigylo/v1/signer-seed-expand";
const SIGNATURE_LABEL: &[u8] = b"sigylo/v1/ed25519-mldsa65";
const FINGERPRINT_LABEL: &[u8] = b"sigylo/v1/sender-fingerprint";

#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519MlDsa65;

fn expand(seed: &SenderSeed) -> (SigningKey<MlDsa65>, EdSigningKey) {
    let mut xof = Shake256::default();
    xof.update(SEED_EXPAND_LABEL);
    xof.update(seed.expose());
    let mut reader = xof.finalize_xof();
    let mut mldsa_seed = Zeroizing::new([0u8; 32]);
    let mut ed_secret = Zeroizing::new([0u8; 32]);
    reader.read(&mut *mldsa_seed);
    reader.read(&mut *ed_secret);
    (SigningKey::from_seed(&Seed::from(*mldsa_seed)), EdSigningKey::from_bytes(&ed_secret))
}

fn bound_message(public_key: &SenderPublicKey, message: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(SIGNATURE_LABEL.len() + SenderPublicKey::LEN + message.len()));
    out.extend_from_slice(SIGNATURE_LABEL);
    out.extend_from_slice(public_key.as_bytes());
    out.extend_from_slice(message);
    out
}

impl HybridSigner for Ed25519MlDsa65 {
    fn public_key(&self, seed: &SenderSeed) -> SenderPublicKey {
        let (mldsa, ed) = expand(seed);
        let mut out = Vec::with_capacity(SenderPublicKey::LEN);
        out.extend_from_slice(ed.verifying_key().as_bytes());
        out.extend_from_slice(&mldsa.verifying_key().encode());
        SenderPublicKey::from_slice(&out).expect("Ed25519 and ML-DSA-65 sizes add up")
    }

    fn fingerprint(&self, public_key: &SenderPublicKey) -> SenderFingerprint {
        let mut h = Sha3_256::new();
        Digest::update(&mut h, FINGERPRINT_LABEL);
        Digest::update(&mut h, public_key.as_bytes());
        SenderFingerprint::from_array(h.finalize().into())
    }

    fn sign(&self, seed: &SenderSeed, message: &[u8]) -> SenderSignature {
        let (mldsa, ed) = expand(seed);
        let m = bound_message(&self.public_key(seed), message);
        let mut out = Vec::with_capacity(SenderSignature::LEN);
        out.extend_from_slice(&ed.sign(&m).to_bytes());
        let pq = mldsa.expanded_key().sign_deterministic(&m, SIGNATURE_LABEL).expect("the label is under 255 bytes");
        out.extend_from_slice(&pq.encode());
        SenderSignature::from_slice(&out).expect("Ed25519 and ML-DSA-65 signature sizes add up")
    }

    fn verify(&self, public_key: &SenderPublicKey, message: &[u8], signature: &SenderSignature) -> bool {
        let m = bound_message(public_key, message);
        // The domain value objects guarantee every length below.
        let ed_pk: &[u8; 32] = public_key.ed25519_part().try_into().expect("32 bytes");
        let ed_sig: &[u8; 64] = signature.ed25519_part().try_into().expect("64 bytes");
        let Ok(ed_pk) = EdVerifyingKey::from_bytes(ed_pk) else {
            return false;
        };
        let classical = ed_pk.verify_strict(&m, &ed25519_dalek::Signature::from_bytes(ed_sig)).is_ok();

        let vk = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.mldsa_part()).expect("1952 bytes");
        let sig = EncodedSignature::<MlDsa65>::try_from(signature.mldsa_part()).expect("3309 bytes");
        let post_quantum = MlDsaSignature::<MlDsa65>::decode(&sig)
            .is_some_and(|sig| VerifyingKey::<MlDsa65>::decode(&vk).verify_with_context(&m, SIGNATURE_LABEL, &sig));

        classical && post_quantum
    }
}
