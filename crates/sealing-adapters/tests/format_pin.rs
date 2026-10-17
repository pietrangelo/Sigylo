//! Known-answer tests that pin the wire format and key schedule. If one of
//! these changes, envelopes sealed by older clients stop opening: bump the
//! envelope version instead of updating the constants.

use sealing::{
    KdfCost, Passphrase, Plaintext, RecipientSeed, SealError, Sealer,
    application::{CryptoSuite, HybridKem, Randomness},
};
use sealing_adapters::{Argon2idStretcher, HkdfSha3, X25519MlKem768, XChaCha20Poly1305Aead};
use sha3::{Digest, Sha3_256};

/// Counts upwards from 1: deterministic "randomness" for reproducible vectors.
#[derive(Default)]
struct Counter(std::cell::Cell<u8>);

impl Randomness for Counter {
    fn fill(&self, buf: &mut [u8]) -> Result<(), SealError> {
        for b in buf {
            self.0.set(self.0.get().wrapping_add(1));
            *b = self.0.get();
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha3_256::digest(bytes))
}

#[test]
fn recipient_public_key_from_a_fixed_seed() {
    let seed = RecipientSeed::from_array([7; 32]);
    let public_key = X25519MlKem768.public_key(&seed);
    assert_eq!(digest(public_key.as_bytes()), PK_DIGEST);
    assert_eq!(hex(X25519MlKem768.fingerprint(&public_key).as_bytes()), FINGERPRINT);
}

#[test]
fn envelopes_from_fixed_randomness() {
    let counter = Counter::default();
    let suite = CryptoSuite {
        randomness: &counter,
        aead: &XChaCha20Poly1305Aead,
        stretcher: &Argon2idStretcher,
        kdf: &HkdfSha3,
        kem: &X25519MlKem768,
    };
    let sealer = Sealer::new(suite).with_kdf_cost(KdfCost::MINIMUM);
    let plaintext = Plaintext::new(b"sigylo".to_vec()).unwrap();
    let pass = Passphrase::new(b"pw".to_vec()).unwrap();
    let (link_envelope, key) = sealer.seal_for_link(&plaintext, Some(&pass)).unwrap();
    assert_eq!(hex(key.expose()), hex(&(1..=32).collect::<Vec<u8>>()));
    assert_eq!(digest(&link_envelope.to_bytes()), LINK_ENVELOPE_DIGEST);

    let seed = RecipientSeed::from_array([7; 32]);
    let public_key = X25519MlKem768.public_key(&seed);
    let fingerprint = X25519MlKem768.fingerprint(&public_key);
    let recipient_envelope = sealer.seal_for_recipient(&plaintext, &public_key, &fingerprint, None).unwrap();
    assert_eq!(digest(&recipient_envelope.to_bytes()), RECIPIENT_ENVELOPE_DIGEST);
    assert_eq!(sealer.open_as_recipient(&recipient_envelope, &seed, None).unwrap(), plaintext);
}

const PK_DIGEST: &str = "bf9ea6f3f6ed310b603a5bca1a6ea2f7f0385ac8207587a958c62b63e03a6dfb";
const FINGERPRINT: &str = "caec05825c6b454bcf0cba33e036ec6230f1275124ae5d774e9a4793edcd1662";
const LINK_ENVELOPE_DIGEST: &str = "18de37cf90d4bfce1bbaff40efc03a873f56f551ff5153478be8b312cb8e24ba";
const RECIPIENT_ENVELOPE_DIGEST: &str = "1a4787e80c6d04444bb4576a84d9261d09d5197a4c615f5388229f3402ac0600";
