use super::fakes::{CountingRandomness, RecordingStretcher, ToyAead, ToyKdf, ToyKem, ToySigner};
use super::{CryptoSuite, HybridSigner, Sealer};
use crate::core::{
    Envelope, KdfCost, LinkKey, MAX_SIGNED_PLAINTEXT_LEN, Passphrase, Plaintext, SealError, SenderFingerprint,
    SenderPublicKey, SenderSeed, SenderSignature,
};

struct World {
    randomness: CountingRandomness,
    stretcher: RecordingStretcher,
    kem: ToyKem,
    signer: ToySigner,
}

impl World {
    fn new() -> Self {
        Self {
            randomness: CountingRandomness::default(),
            stretcher: RecordingStretcher::default(),
            kem: ToyKem::default(),
            signer: ToySigner::default(),
        }
    }

    fn sealer(&self) -> Sealer<'_> {
        self.sealer_signing_with(&self.signer)
    }

    /// The same world, but sealing with another (possibly dishonest) signer.
    fn sealer_signing_with<'a>(&'a self, signer: &'a dyn HybridSigner) -> Sealer<'a> {
        Sealer::new(CryptoSuite {
            randomness: &self.randomness,
            aead: &ToyAead,
            stretcher: &self.stretcher,
            kdf: &ToyKdf,
            kem: &self.kem,
            signer,
        })
    }
}

fn secret() -> Plaintext {
    Plaintext::new(b"db password: correct horse battery staple".to_vec()).unwrap()
}

fn pass(s: &str) -> Passphrase {
    Passphrase::new(s.as_bytes().to_vec()).unwrap()
}

#[test]
fn link_mode_roundtrip() {
    let world = World::new();
    let (envelope, key) = world.sealer().seal_for_link(&secret(), None).unwrap();
    assert_eq!(world.sealer().open_link(&envelope, &key, None).unwrap(), secret());
    assert_eq!(world.stretcher.calls.get(), 0);
}

#[test]
fn passphrase_is_stretched_with_the_cost_written_in_the_envelope() {
    let world = World::new();
    let cost = KdfCost::new(32 * 1024, 4, 2).unwrap();
    let sealer = world.sealer().with_kdf_cost(cost);
    let (envelope, key) = sealer.seal_for_link(&secret(), Some(&pass("tr0ub4dor"))).unwrap();
    assert_eq!(envelope.header().passphrase.unwrap().cost, cost);
    // A sealer with a different default still opens: the envelope's cost wins.
    assert_eq!(world.sealer().open_link(&envelope, &key, Some(&pass("tr0ub4dor"))).unwrap(), secret());
    assert_eq!(world.stretcher.last_cost.get(), Some(cost));
    assert_eq!(world.stretcher.calls.get(), 2);
}

#[test]
fn recipient_mode_roundtrip() {
    let world = World::new();
    let recipient = world.sealer().new_recipient().unwrap();
    let envelope = world
        .sealer()
        .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, Some(&pass("pw")), None)
        .unwrap();
    let received = world.sealer().open_as_recipient(&envelope, &recipient.seed, Some(&pass("pw"))).unwrap();
    assert_eq!(received.plaintext, secret());
    assert_eq!(received.sender, None, "an unsigned answer names no sender");
    assert!(!envelope.is_signed());
}

#[test]
fn new_sender_is_consistent_with_its_seed() {
    let world = World::new();
    let alice = world.sealer().new_sender().unwrap();
    assert_eq!(world.signer.public_key(&alice.seed), alice.public_key);
    assert_eq!(world.sealer().sender_fingerprint(&alice.seed), alice.fingerprint);
    assert_ne!(world.sealer().new_sender().unwrap().fingerprint, alice.fingerprint);
}

#[test]
fn signed_answer_names_its_sender() {
    let world = World::new();
    let recipient = world.sealer().new_recipient().unwrap();
    let alice = world.sealer().new_sender().unwrap();
    let envelope = world
        .sealer()
        .seal_for_recipient(
            &secret(),
            &recipient.public_key,
            &recipient.fingerprint,
            Some(&pass("pw")),
            Some(&alice.seed),
        )
        .unwrap();
    assert!(envelope.is_signed());
    let parsed = Envelope::parse(&envelope.to_bytes()).unwrap();
    let received = world.sealer().open_as_recipient(&parsed, &recipient.seed, Some(&pass("pw"))).unwrap();
    assert_eq!(received.plaintext, secret());
    assert_eq!(received.sender, Some(alice.fingerprint));
}

#[test]
fn signing_hides_the_sender_inside_the_ciphertext() {
    let world = World::new();
    let recipient = world.sealer().new_recipient().unwrap();
    let alice = world.sealer().new_sender().unwrap();
    let envelope = world
        .sealer()
        .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, None, Some(&alice.seed))
        .unwrap()
        .to_bytes();
    assert!(!envelope.windows(32).any(|w| w == &alice.public_key.as_bytes()[..32]));
    assert!(!envelope.windows(32).any(|w| w == alice.fingerprint.as_bytes()));
}

#[test]
fn signed_secrets_must_leave_room_for_the_signature() {
    let world = World::new();
    let recipient = world.sealer().new_recipient().unwrap();
    let alice = world.sealer().new_sender().unwrap();
    let seal = |len: usize| {
        world.sealer().seal_for_recipient(
            &Plaintext::new(vec![b'x'; len]).unwrap(),
            &recipient.public_key,
            &recipient.fingerprint,
            None,
            Some(&alice.seed),
        )
    };
    let largest = seal(MAX_SIGNED_PLAINTEXT_LEN).unwrap();
    assert_eq!(
        world.sealer().open_as_recipient(&largest, &recipient.seed, None).unwrap().plaintext.expose().len(),
        MAX_SIGNED_PLAINTEXT_LEN
    );
    let encapsulations = world.kem.encapsulations.get();
    assert_eq!(seal(MAX_SIGNED_PLAINTEXT_LEN + 1).unwrap_err(), SealError::PlaintextTooLarge);
    assert_eq!(world.kem.encapsulations.get(), encapsulations, "refused before any crypto work");
}

#[test]
fn envelopes_survive_the_wire() {
    let world = World::new();
    let (envelope, key) = world.sealer().seal_for_link(&secret(), Some(&pass("pw"))).unwrap();
    let parsed = Envelope::parse(&envelope.to_bytes()).unwrap();
    assert_eq!(world.sealer().open_link(&parsed, &key, Some(&pass("pw"))).unwrap(), secret());
}

mod adversary {
    use super::*;

    #[test]
    fn wrong_link_key_or_passphrase_is_not_authentic() {
        let world = World::new();
        let (envelope, _) = world.sealer().seal_for_link(&secret(), Some(&pass("right"))).unwrap();
        let (_, other_key) = world.sealer().seal_for_link(&secret(), None).unwrap();
        assert_eq!(world.sealer().open_link(&envelope, &other_key, Some(&pass("right"))), Err(SealError::NotAuthentic));
        let (envelope, key) = world.sealer().seal_for_link(&secret(), Some(&pass("right"))).unwrap();
        assert_eq!(world.sealer().open_link(&envelope, &key, Some(&pass("wrong"))), Err(SealError::NotAuthentic));
    }

    #[test]
    fn passphrase_expectations_must_match_the_envelope() {
        let world = World::new();
        let (locked, key) = world.sealer().seal_for_link(&secret(), Some(&pass("pw"))).unwrap();
        assert_eq!(world.sealer().open_link(&locked, &key, None), Err(SealError::PassphraseExpectationMismatch));
        let (open, key) = world.sealer().seal_for_link(&secret(), None).unwrap();
        assert_eq!(
            world.sealer().open_link(&open, &key, Some(&pass("pw"))),
            Err(SealError::PassphraseExpectationMismatch)
        );
    }

    #[test]
    fn stripping_the_passphrase_lock_from_the_header_fails_authentication() {
        let world = World::new();
        let (locked, key) = world.sealer().seal_for_link(&secret(), Some(&pass("pw"))).unwrap();
        let bytes = locked.to_bytes();
        // Remove the flag and the 28 KDF bytes, as a relay downgrading the envelope would.
        let mut stripped = bytes[..6].to_vec();
        stripped[5] = 0;
        stripped.extend_from_slice(&bytes[6 + 28..]);
        let stripped = Envelope::parse(&stripped).unwrap();
        assert_eq!(world.sealer().open_link(&stripped, &key, None), Err(SealError::NotAuthentic));
    }

    #[test]
    fn modes_cannot_be_confused() {
        let world = World::new();
        let recipient = world.sealer().new_recipient().unwrap();
        let (link_envelope, key) = world.sealer().seal_for_link(&secret(), None).unwrap();
        assert_eq!(world.sealer().open_as_recipient(&link_envelope, &recipient.seed, None), Err(SealError::WrongMode));
        let envelope = world
            .sealer()
            .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, None, None)
            .unwrap();
        assert_eq!(world.sealer().open_link(&envelope, &key, None), Err(SealError::WrongMode));
    }

    #[test]
    fn substituted_public_key_is_refused_before_encapsulating() {
        let world = World::new();
        let alice = world.sealer().new_recipient().unwrap();
        let mallory = world.sealer().new_recipient().unwrap();
        let result = world.sealer().seal_for_recipient(&secret(), &mallory.public_key, &alice.fingerprint, None, None);
        assert_eq!(result.unwrap_err(), SealError::FingerprintMismatch);
        assert_eq!(world.kem.encapsulations.get(), 0);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let world = World::new();
        let alice = world.sealer().new_recipient().unwrap();
        let mallory = world.sealer().new_recipient().unwrap();
        let envelope =
            world.sealer().seal_for_recipient(&secret(), &alice.public_key, &alice.fingerprint, None, None).unwrap();
        assert_eq!(world.sealer().open_as_recipient(&envelope, &mallory.seed, None), Err(SealError::NotAuthentic));
    }

    #[test]
    fn broken_randomness_never_produces_an_envelope() {
        let world = World::new();
        world.randomness.broken.set(true);
        assert_eq!(world.sealer().seal_for_link(&secret(), None).unwrap_err(), SealError::RandomnessUnavailable);
        assert_eq!(world.sealer().new_recipient().unwrap_err(), SealError::RandomnessUnavailable);
    }

    #[test]
    fn link_key_is_never_part_of_the_envelope() {
        let world = World::new();
        let (envelope, key) = world.sealer().seal_for_link(&secret(), None).unwrap();
        let bytes = envelope.to_bytes();
        assert!(!bytes.windows(32).any(|w| w == key.expose()));
        let _: &LinkKey = &key;
    }

    /// Claims someone else's public key but can only sign with its own seed.
    struct Impersonator(SenderPublicKey);

    impl HybridSigner for Impersonator {
        fn public_key(&self, _: &SenderSeed) -> SenderPublicKey {
            self.0.clone()
        }
        fn fingerprint(&self, public_key: &SenderPublicKey) -> SenderFingerprint {
            ToySigner::default().fingerprint(public_key)
        }
        fn sign(&self, seed: &SenderSeed, message: &[u8]) -> SenderSignature {
            ToySigner::default().sign(seed, message)
        }
        fn verify(&self, _: &SenderPublicKey, _: &[u8], _: &SenderSignature) -> bool {
            unreachable!("sealing never verifies")
        }
    }

    /// Replays a signature it saw once, whatever it is asked to sign.
    struct Replayer(SenderPublicKey, SenderSignature);

    impl HybridSigner for Replayer {
        fn public_key(&self, _: &SenderSeed) -> SenderPublicKey {
            self.0.clone()
        }
        fn fingerprint(&self, public_key: &SenderPublicKey) -> SenderFingerprint {
            ToySigner::default().fingerprint(public_key)
        }
        fn sign(&self, _: &SenderSeed, _: &[u8]) -> SenderSignature {
            self.1.clone()
        }
        fn verify(&self, _: &SenderPublicKey, _: &[u8], _: &SenderSignature) -> bool {
            unreachable!("sealing never verifies")
        }
    }

    #[test]
    fn an_impostor_cannot_sign_in_someone_elses_name() {
        let world = World::new();
        let recipient = world.sealer().new_recipient().unwrap();
        let alice = world.sealer().new_sender().unwrap();
        let mallory = world.sealer().new_sender().unwrap();
        let impostor = Impersonator(alice.public_key.clone());
        let envelope = world
            .sealer_signing_with(&impostor)
            .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, None, Some(&mallory.seed))
            .unwrap();
        assert_eq!(world.sealer().open_as_recipient(&envelope, &recipient.seed, None), Err(SealError::NotAuthentic));
    }

    #[test]
    fn a_signature_meant_for_one_recipient_does_not_verify_for_another() {
        let world = World::new();
        let bob = world.sealer().new_recipient().unwrap();
        let carol = world.sealer().new_recipient().unwrap();
        let alice = world.sealer().new_sender().unwrap();
        // Bob learns Alice's signature over the secret she sent him...
        let message = crate::core::signed_message(&bob.fingerprint, b"any header", &secret());
        let signature = world.signer.sign(&alice.seed, &message);
        // ...and re-seals it to Carol, as if Alice had sent it to her.
        let replayer = Replayer(alice.public_key.clone(), signature);
        let forged = world
            .sealer_signing_with(&replayer)
            .seal_for_recipient(&secret(), &carol.public_key, &carol.fingerprint, None, Some(&alice.seed))
            .unwrap();
        assert_eq!(world.sealer().open_as_recipient(&forged, &carol.seed, None), Err(SealError::NotAuthentic));
    }

    #[test]
    fn the_signed_flag_can_be_neither_stripped_nor_added() {
        let world = World::new();
        let recipient = world.sealer().new_recipient().unwrap();
        let alice = world.sealer().new_sender().unwrap();
        let seal = |sender: Option<&SenderSeed>| {
            world
                .sealer()
                .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, None, sender)
                .unwrap()
                .to_bytes()
        };
        for (mut bytes, flags) in [(seal(Some(&alice.seed)), 0), (seal(None), 0b10)] {
            bytes[5] = flags;
            let tampered = Envelope::parse(&bytes).unwrap();
            assert_eq!(
                world.sealer().open_as_recipient(&tampered, &recipient.seed, None),
                Err(SealError::NotAuthentic)
            );
        }
    }
}
