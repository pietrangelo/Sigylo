//! The Sealing use cases running on the real RustCrypto suite.

use sealing::{
    Encapsulation, Envelope, KdfCost, LinkKey, Passphrase, Plaintext, RecipientSeed, SealError, Sealer, SenderCode,
    SenderPublicKey, SenderSeed, SenderSignature,
    application::{HybridKem, HybridSigner},
};
use sealing_adapters::{Ed25519MlDsa65, X25519MlKem768, rustcrypto_suite};

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
        .seal_for_recipient(
            &secret(),
            &recipient.public_key,
            &recipient.fingerprint,
            Some(&pass("seconda chiave")),
            None,
            None,
        )
        .unwrap();
    let wire = envelope.to_bytes();
    let opened = sealer()
        .open_as_recipient(&Envelope::parse(&wire).unwrap(), &recipient.seed, Some(&pass("seconda chiave")), None)
        .unwrap();
    assert_eq!(opened.plaintext, secret());
    assert_eq!(opened.sender, None);
}

#[test]
fn signed_answer_roundtrip_over_the_wire() {
    let recipient = sealer().new_recipient().unwrap();
    let alice = sealer().new_sender().unwrap();
    let envelope = sealer()
        .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, None, Some(&alice.seed), None)
        .unwrap();
    let wire = envelope.to_bytes();
    // A short secret still lands in a single fixed bucket once signed.
    assert_eq!(wire.len(), 6 + Encapsulation::LEN + 24 + 8192 + 16);
    let received = sealer().open_as_recipient(&Envelope::parse(&wire).unwrap(), &recipient.seed, None, None).unwrap();
    assert_eq!(received.plaintext, secret());
    assert_eq!(received.sender, Some(alice.fingerprint));
    assert_eq!(sealer().sender_fingerprint(&alice.seed), alice.fingerprint);
}

#[test]
fn only_the_expected_sender_gets_through() {
    let recipient = sealer().new_recipient().unwrap();
    let alice = sealer().new_sender().unwrap();
    let mallory = sealer().new_sender().unwrap();
    let pin = sealer().sender_pin(&recipient.fingerprint, &SenderCode::parse(&alice.fingerprint.code()).unwrap());
    let seal = |seed: &SenderSeed| {
        sealer()
            .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, None, Some(seed), None)
            .unwrap()
    };
    let from_alice = sealer().open_as_recipient(&seal(&alice.seed), &recipient.seed, None, Some(&pin)).unwrap();
    assert_eq!(from_alice.sender, Some(alice.fingerprint));
    let from_mallory = sealer().open_as_recipient(&seal(&mallory.seed), &recipient.seed, None, Some(&pin));
    assert_eq!(from_mallory, Err(SealError::UnexpectedSender));
}

#[test]
fn sender_public_key_is_a_pure_function_of_the_seed() {
    let alice = sealer().new_sender().unwrap();
    let again = SenderSeed::from_slice(alice.seed.expose()).unwrap();
    assert_eq!(Ed25519MlDsa65.public_key(&again), alice.public_key);
}

#[test]
fn hybrid_signature_verifies_and_is_deterministic() {
    let seed = SenderSeed::from_array([3; 32]);
    let pk = Ed25519MlDsa65.public_key(&seed);
    let sig = Ed25519MlDsa65.sign(&seed, b"message");
    assert!(Ed25519MlDsa65.verify(&pk, b"message", &sig));
    assert_eq!(Ed25519MlDsa65.sign(&seed, b"message"), sig);
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
            .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, Some(&pass("pw")), None, None)
            .unwrap()
            .to_bytes();
        for byte in 0..envelope.len() {
            // One bit per byte keeps the run short while touching every field.
            let mut bad = envelope.clone();
            bad[byte] ^= 1 << (byte % 8);
            let outcome = Envelope::parse(&bad)
                .and_then(|env| sealer().open_as_recipient(&env, &recipient.seed, Some(&pass("pw")), None));
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
        let result = sealer().seal_for_recipient(&secret(), &mallory.public_key, &alice.fingerprint, None, None, None);
        assert_eq!(result.unwrap_err(), SealError::FingerprintMismatch);
    }

    #[test]
    fn other_recipient_and_wrong_passphrase_fail_identically() {
        let alice = sealer().new_recipient().unwrap();
        let mallory = sealer().new_recipient().unwrap();
        let envelope = sealer()
            .seal_for_recipient(&secret(), &alice.public_key, &alice.fingerprint, Some(&pass("pw")), None, None)
            .unwrap();
        let wrong_seed = sealer().open_as_recipient(&envelope, &mallory.seed, Some(&pass("pw")), None);
        let wrong_pass = sealer().open_as_recipient(&envelope, &alice.seed, Some(&pass("pW")), None);
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
        let result = sealer().seal_for_recipient(&secret(), &poisoned, &fingerprint, None, None, None);
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

    fn signed(seed: u8, message: &[u8]) -> (SenderPublicKey, SenderSignature) {
        let seed = SenderSeed::from_array([seed; 32]);
        (Ed25519MlDsa65.public_key(&seed), Ed25519MlDsa65.sign(&seed, message))
    }

    #[test]
    fn bit_flips_all_over_a_signed_answer_are_detected() {
        let recipient = sealer().new_recipient().unwrap();
        let alice = sealer().new_sender().unwrap();
        let envelope = sealer()
            .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, None, Some(&alice.seed), None)
            .unwrap()
            .to_bytes();
        for byte in (0..envelope.len()).step_by(11) {
            let mut bad = envelope.clone();
            bad[byte] ^= 1 << (byte % 8);
            let outcome =
                Envelope::parse(&bad).and_then(|env| sealer().open_as_recipient(&env, &recipient.seed, None, None));
            assert!(outcome.is_err(), "flip in byte {byte} went undetected");
        }
    }

    #[test]
    fn both_halves_must_verify() {
        let (pk, sig) = signed(1, b"m");
        for (start, end) in [(0, 64), (64, SenderSignature::LEN)] {
            for i in [start, (start + end) / 2, end - 1] {
                let mut bad = sig.as_bytes().to_vec();
                bad[i] ^= 0x01;
                let bad = SenderSignature::from_slice(&bad).unwrap();
                assert!(!Ed25519MlDsa65.verify(&pk, b"m", &bad), "flip at {i} accepted");
            }
        }
        // Splicing a valid half from another signature does not help either.
        let (_, other) = signed(1, b"n");
        for spliced in [
            [&sig.as_bytes()[..64], &other.as_bytes()[64..]].concat(),
            [&other.as_bytes()[..64], &sig.as_bytes()[64..]].concat(),
        ] {
            assert!(!Ed25519MlDsa65.verify(&pk, b"m", &SenderSignature::from_slice(&spliced).unwrap()));
        }
    }

    #[test]
    fn a_signature_does_not_verify_under_another_key_or_message() {
        let (pk, sig) = signed(1, b"pay alice");
        let (mallory, _) = signed(2, b"");
        assert!(!Ed25519MlDsa65.verify(&mallory, b"pay alice", &sig));
        assert!(!Ed25519MlDsa65.verify(&pk, b"pay mallory", &sig));
        // Mixing Alice's Ed25519 half with Mallory's ML-DSA half is another key.
        let mixed = [pk.ed25519_part(), mallory.mldsa_part()].concat();
        assert!(!Ed25519MlDsa65.verify(&SenderPublicKey::from_slice(&mixed).unwrap(), b"pay alice", &sig));
    }

    #[test]
    fn hostile_keys_and_signatures_never_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut noise = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect()
        };
        let (pk, sig) = signed(1, b"m");
        for round in 0..20 {
            let pk_bytes = if round % 2 == 0 { noise(SenderPublicKey::LEN) } else { pk.as_bytes().to_vec() };
            let sig_bytes = if round % 3 == 0 { vec![0xFF; SenderSignature::LEN] } else { noise(SenderSignature::LEN) };
            let hostile_pk = SenderPublicKey::from_slice(&pk_bytes).unwrap();
            let hostile_sig = SenderSignature::from_slice(&sig_bytes).unwrap();
            assert!(!Ed25519MlDsa65.verify(&hostile_pk, b"m", &hostile_sig));
            assert!(!Ed25519MlDsa65.verify(&hostile_pk, b"m", &sig) || hostile_pk == pk);
        }
        // The Ed25519 identity point is a small-order key: verify_strict refuses it.
        let mut weak = pk.as_bytes().to_vec();
        weak[..32].copy_from_slice(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let mut weak_sig = sig.as_bytes().to_vec();
        weak_sig[..64].copy_from_slice(&[[1u8].as_slice(), &[0; 63]].concat());
        assert!(!Ed25519MlDsa65.verify(
            &SenderPublicKey::from_slice(&weak).unwrap(),
            b"m",
            &SenderSignature::from_slice(&weak_sig).unwrap()
        ));
    }
}

mod files {
    use sealing::{CHUNK_LEN, FileBytes, FileManifest, FileName, MAX_FILE_LEN, SealedChunk};

    use super::*;

    fn contents(len: usize) -> FileBytes {
        FileBytes::new((0..len).map(|i| (i % 253) as u8).collect()).unwrap()
    }

    fn name() -> FileName {
        FileName::new("bilancio 2026.xlsx".to_owned()).unwrap()
    }

    #[test]
    fn largest_file_roundtrips_over_the_wire_with_a_passphrase() {
        let (file, key) = sealer().seal_file_for_link(name(), &contents(MAX_FILE_LEN), Some(&pass("pw"))).unwrap();
        let wire: Vec<Vec<u8>> = file.chunks.into_iter().map(SealedChunk::into_bytes).collect();
        assert!(wire.iter().all(|c| c.len() == CHUNK_LEN + 16));
        let manifest_envelope = Envelope::parse(&file.manifest.to_bytes()).unwrap();
        let plaintext = sealer().open_link(&manifest_envelope, &key, Some(&pass("pw"))).unwrap();
        let manifest = FileManifest::recognize(&plaintext).unwrap().unwrap();
        let chunks: Vec<SealedChunk> = wire.into_iter().map(|c| SealedChunk::new(c).unwrap()).collect();
        assert_eq!(sealer().open_file(&manifest, &chunks).unwrap(), contents(MAX_FILE_LEN));
        assert_eq!(manifest.name().as_str(), "bilancio 2026.xlsx");
    }

    #[test]
    fn recipient_mode_file_roundtrip() {
        let recipient = sealer().new_recipient().unwrap();
        let file = sealer()
            .seal_file_for_recipient(
                name(),
                &contents(CHUNK_LEN + 1),
                &recipient.public_key,
                &recipient.fingerprint,
                None,
                None,
                None,
            )
            .unwrap();
        let received = sealer().open_as_recipient(&file.manifest, &recipient.seed, None, None).unwrap();
        let manifest = FileManifest::recognize(&received.plaintext).unwrap().unwrap();
        assert_eq!(sealer().open_file(&manifest, &file.chunks).unwrap(), contents(CHUNK_LEN + 1));
    }

    mod adversary {
        use super::*;

        fn sealed(len: usize) -> (FileManifest, Vec<SealedChunk>) {
            let (file, key) = sealer().seal_file_for_link(name(), &contents(len), None).unwrap();
            let plaintext = sealer().open_link(&file.manifest, &key, None).unwrap();
            (FileManifest::recognize(&plaintext).unwrap().unwrap(), file.chunks)
        }

        #[test]
        fn swapped_dropped_and_foreign_chunks_fail_alike() {
            let (manifest, chunks) = sealed(3 * CHUNK_LEN);
            let (_, foreign) = sealed(3 * CHUNK_LEN);
            let swapped = [chunks[1].clone(), chunks[0].clone(), chunks[2].clone()];
            let dropped = [chunks[0].clone(), chunks[1].clone()];
            let mixed = [chunks[0].clone(), foreign[1].clone(), chunks[2].clone()];
            for attempt in [&swapped[..], &dropped[..], &mixed[..]] {
                assert_eq!(sealer().open_file(&manifest, attempt), Err(SealError::NotAuthentic));
            }
        }

        #[test]
        fn every_bit_flip_in_a_last_chunk_is_detected() {
            let (manifest, chunks) = sealed(300);
            let bytes = chunks[0].as_bytes();
            for byte in 0..bytes.len() {
                let mut bad = bytes.to_vec();
                bad[byte] ^= 1 << (byte % 8);
                let bad = [SealedChunk::new(bad).unwrap()];
                assert_eq!(sealer().open_file(&manifest, &bad), Err(SealError::NotAuthentic), "byte {byte}");
            }
        }
    }
}
