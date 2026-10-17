//! The Sealing use cases running on the real RustCrypto suite.

use sealing::{
    Envelope, KdfCost, LinkKey, Passphrase, Plaintext, RecipientSeed, SealError, Sealer, application::HybridKem,
};
use sealing_adapters::{X25519MlKem768, rustcrypto_suite};

/// Tests use the cheapest accepted Argon2id cost; production uses RECOMMENDED.
fn sealer() -> Sealer<'static> {
    Sealer::new(rustcrypto_suite()).with_kdf_cost(KdfCost::MINIMUM)
}

fn secret() -> Plaintext {
    Plaintext::new("password del DB: cavallo-corretto-batteria-graffetta 🔐".as_bytes().to_vec()).unwrap()
}

fn pass(s: &str) -> Passphrase {
    Passphrase::new(s.as_bytes().to_vec()).unwrap()
}

#[test]
fn link_mode_roundtrip_over_the_wire() {
    let (envelope, key) = sealer().seal_for_link(&secret(), None).unwrap();
    let wire = envelope.to_bytes();
    let key = LinkKey::from_slice(key.expose()).unwrap();
    assert_eq!(sealer().open_link(&Envelope::parse(&wire).unwrap(), &key, None).unwrap(), secret());
}

#[test]
fn recipient_mode_roundtrip_with_passphrase() {
    let recipient = sealer().new_recipient().unwrap();
    let envelope = sealer()
        .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, Some(&pass("seconda chiave")))
        .unwrap();
    let wire = envelope.to_bytes();
    let opened = sealer()
        .open_as_recipient(&Envelope::parse(&wire).unwrap(), &recipient.seed, Some(&pass("seconda chiave")))
        .unwrap();
    assert_eq!(opened, secret());
}

#[test]
fn recommended_cost_is_what_production_writes() {
    let (envelope, key) = Sealer::new(rustcrypto_suite()).seal_for_link(&secret(), Some(&pass("pw"))).unwrap();
    assert_eq!(envelope.header().passphrase.unwrap().cost, KdfCost::RECOMMENDED);
    assert_eq!(sealer().open_link(&envelope, &key, Some(&pass("pw"))).unwrap(), secret());
}

#[test]
fn public_key_is_a_pure_function_of_the_seed() {
    let recipient = sealer().new_recipient().unwrap();
    let again = RecipientSeed::from_slice(recipient.seed.expose()).unwrap();
    assert_eq!(X25519MlKem768.public_key(&again), recipient.public_key);
}

#[test]
fn every_envelope_is_fresh() {
    let (a, ka) = sealer().seal_for_link(&secret(), None).unwrap();
    let (b, kb) = sealer().seal_for_link(&secret(), None).unwrap();
    assert_ne!(a.to_bytes(), b.to_bytes());
    assert_ne!(ka, kb);
}

mod adversary {
    use super::*;

    #[test]
    fn every_single_bit_flip_is_detected() {
        let recipient = sealer().new_recipient().unwrap();
        let envelope = sealer()
            .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, Some(&pass("pw")))
            .unwrap()
            .to_bytes();
        for byte in 0..envelope.len() {
            // One bit per byte keeps the run short while touching every field.
            let mut bad = envelope.clone();
            bad[byte] ^= 1 << (byte % 8);
            let outcome = Envelope::parse(&bad)
                .and_then(|env| sealer().open_as_recipient(&env, &recipient.seed, Some(&pass("pw"))));
            assert!(outcome.is_err(), "flip in byte {byte} went undetected");
        }
    }

    #[test]
    fn swapping_ciphertexts_between_envelopes_fails() {
        let (a, key_a) = sealer().seal_for_link(&secret(), None).unwrap();
        let (b, _) = sealer().seal_for_link(&secret(), None).unwrap();
        let header_len = a.header().to_bytes().len();
        let mut spliced = a.to_bytes()[..header_len].to_vec();
        spliced.extend_from_slice(&b.to_bytes()[header_len..]);
        let spliced = Envelope::parse(&spliced).unwrap();
        assert_eq!(sealer().open_link(&spliced, &key_a, None), Err(SealError::NotAuthentic));
    }

    #[test]
    fn substituted_public_key_is_refused() {
        let alice = sealer().new_recipient().unwrap();
        let mallory = sealer().new_recipient().unwrap();
        let result = sealer().seal_for_recipient(&secret(), &mallory.public_key, &alice.fingerprint, None);
        assert_eq!(result.unwrap_err(), SealError::FingerprintMismatch);
    }

    #[test]
    fn other_recipient_and_wrong_passphrase_fail_identically() {
        let alice = sealer().new_recipient().unwrap();
        let mallory = sealer().new_recipient().unwrap();
        let envelope =
            sealer().seal_for_recipient(&secret(), &alice.public_key, &alice.fingerprint, Some(&pass("pw"))).unwrap();
        let wrong_seed = sealer().open_as_recipient(&envelope, &mallory.seed, Some(&pass("pw")));
        let wrong_pass = sealer().open_as_recipient(&envelope, &alice.seed, Some(&pass("pW")));
        assert_eq!(wrong_seed, Err(SealError::NotAuthentic));
        assert_eq!(wrong_pass, wrong_seed);
    }

    #[test]
    fn low_order_x25519_public_key_is_rejected() {
        let alice = sealer().new_recipient().unwrap();
        let mut bytes = alice.public_key.as_bytes().to_vec();
        bytes[..32].fill(0);
        let poisoned = sealing::RecipientPublicKey::from_slice(&bytes).unwrap();
        let fingerprint = X25519MlKem768.fingerprint(&poisoned);
        let result = sealer().seal_for_recipient(&secret(), &poisoned, &fingerprint, None);
        assert_eq!(result.unwrap_err(), SealError::InvalidKeyMaterial);
    }

    #[test]
    fn random_bytes_posing_as_envelopes_never_open() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let key = LinkKey::from_array([9; 32]);
        for _ in 0..200 {
            let mut bytes = b"SGY\x01\x01\x00".to_vec();
            for _ in 0..(24 + 272) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                bytes.push(state as u8);
            }
            let env = Envelope::parse(&bytes).unwrap();
            assert_eq!(sealer().open_link(&env, &key, None), Err(SealError::NotAuthentic));
        }
    }
}
