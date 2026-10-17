//! Known-answer tests that pin the wire format and key schedule. If one of
//! these changes, envelopes sealed by older clients stop opening: bump the
//! envelope version instead of updating the constants.

use sealing::{
    CHUNK_LEN, FileBytes, FileName, KdfCost, Passphrase, Plaintext, RecipientSeed, SealError, Sealer, SenderCode,
    SenderSeed,
    application::{CryptoSuite, HybridKem, HybridSigner, Randomness},
};
use sealing_adapters::{Argon2idStretcher, Ed25519MlDsa65, HkdfSha3, X25519MlKem768, XChaCha20Poly1305Aead};
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
        signer: &Ed25519MlDsa65,
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
    let recipient_envelope =
        sealer.seal_for_recipient(&plaintext, &public_key, &fingerprint, None, None, None).unwrap();
    assert_eq!(digest(&recipient_envelope.to_bytes()), RECIPIENT_ENVELOPE_DIGEST);
    assert_eq!(sealer.open_as_recipient(&recipient_envelope, &seed, None, None).unwrap().plaintext, plaintext);

    let sender = SenderSeed::from_array([9; 32]);
    let signed_envelope =
        sealer.seal_for_recipient(&plaintext, &public_key, &fingerprint, None, Some(&sender), None).unwrap();
    assert_eq!(digest(&signed_envelope.to_bytes()), SIGNED_ENVELOPE_DIGEST);
    let received = sealer.open_as_recipient(&signed_envelope, &seed, None, None).unwrap();
    assert_eq!((received.plaintext, received.sender), (plaintext, Some(sealer.sender_fingerprint(&sender))));
}

#[test]
fn sender_identity_from_a_fixed_seed() {
    let seed = SenderSeed::from_array([9; 32]);
    let public_key = Ed25519MlDsa65.public_key(&seed);
    assert_eq!(digest(public_key.as_bytes()), SENDER_PK_DIGEST);
    let fingerprint = Ed25519MlDsa65.fingerprint(&public_key);
    assert_eq!(hex(fingerprint.as_bytes()), SENDER_FINGERPRINT);
    assert_eq!(fingerprint.code(), SENDER_CODE);
    assert_eq!(digest(Ed25519MlDsa65.sign(&seed, b"sigylo").as_bytes()), SIGNATURE_DIGEST);
}

#[test]
fn expected_sender_pin_from_fixed_inputs() {
    let sealer = Sealer::new(sealing_adapters::rustcrypto_suite());
    let recipient = X25519MlKem768.fingerprint(&X25519MlKem768.public_key(&RecipientSeed::from_array([7; 32])));
    let code = SenderCode::parse(SENDER_CODE).unwrap();
    assert_eq!(hex(sealer.sender_pin(&recipient, &code).as_bytes()), SENDER_PIN);
}

#[test]
fn files_from_fixed_randomness() {
    let counter = Counter::default();
    let suite = CryptoSuite {
        randomness: &counter,
        aead: &XChaCha20Poly1305Aead,
        stretcher: &Argon2idStretcher,
        kdf: &HkdfSha3,
        kem: &X25519MlKem768,
        signer: &Ed25519MlDsa65,
    };
    let sealer = Sealer::new(suite);
    let contents = FileBytes::new((0..CHUNK_LEN + 1000).map(|i| (i % 251) as u8).collect()).unwrap();
    let name = FileName::new("sigillo.bin".to_owned()).unwrap();
    let (file, key) = sealer.seal_file_for_link(name, &contents, None).unwrap();
    // Files pin the manifest and chunk layout too: a change here means a new
    // manifest version, not new constants. The file key is drawn first, then
    // the link key, then the nonce.
    assert_eq!(hex(key.expose()), hex(&(33..=64).collect::<Vec<u8>>()));
    assert_eq!(digest(&file.manifest.to_bytes()), FILE_MANIFEST_DIGEST);
    assert_eq!(file.chunks.len(), 2);
    assert_eq!(digest(file.chunks[0].as_bytes()), FILE_CHUNK_0_DIGEST);
    assert_eq!(digest(file.chunks[1].as_bytes()), FILE_CHUNK_1_DIGEST);
}

const PK_DIGEST: &str = "bf9ea6f3f6ed310b603a5bca1a6ea2f7f0385ac8207587a958c62b63e03a6dfb";
const FINGERPRINT: &str = "caec05825c6b454bcf0cba33e036ec6230f1275124ae5d774e9a4793edcd1662";
const LINK_ENVELOPE_DIGEST: &str = "18de37cf90d4bfce1bbaff40efc03a873f56f551ff5153478be8b312cb8e24ba";
const RECIPIENT_ENVELOPE_DIGEST: &str = "1a4787e80c6d04444bb4576a84d9261d09d5197a4c615f5388229f3402ac0600";
const FILE_MANIFEST_DIGEST: &str = "3372b9edf943174a76dc00fb0a682c003663e681f09c39a46002a48fc6c8510b";
const FILE_CHUNK_0_DIGEST: &str = "257e5764a49afa6810cbcd815fbce61cb4737671caf23032d46d310df1fdebe8";
const FILE_CHUNK_1_DIGEST: &str = "aeae525f24bd69f4dbc07c60a6159b05491fee62c20213d18628d3ef76ffc284";
const SIGNED_ENVELOPE_DIGEST: &str = "2cbdc7b442fd30c00d277f0b1caa881353ef449e12387da9e14f2d73aeabf7c7";
const SENDER_PK_DIGEST: &str = "81e06145dac00291e19007c474a116468b6298bd0631eef76afdc13b1bea23a4";
const SENDER_FINGERPRINT: &str = "845bcc71dd61d3f90a50f4df5639124b41d1134f10276edf248032ef49e8f1aa";
const SENDER_CODE: &str = "GHDW-RWEX-C79Z-J2JG-YKFN";
const SIGNATURE_DIGEST: &str = "502f4257965cda0c58e0adbc77a3b5087163c824d13273c3c3167e43e61a6e71";
const SENDER_PIN: &str = "1baee2e9dc98312939a3e4a338442875c65351519a7b69243df338e8f8754c84";
