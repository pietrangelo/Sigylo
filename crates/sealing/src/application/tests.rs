use super::fakes::{CountingRandomness, RecordingStretcher, ToyAead, ToyKdf, ToyKem};
use super::{CryptoSuite, Sealer};
use crate::core::{Envelope, KdfCost, LinkKey, Passphrase, Plaintext, SealError};

struct World {
    randomness: CountingRandomness,
    stretcher: RecordingStretcher,
    kem: ToyKem,
}

impl World {
    fn new() -> Self {
        Self {
            randomness: CountingRandomness::default(),
            stretcher: RecordingStretcher::default(),
            kem: ToyKem::default(),
        }
    }

    fn sealer(&self) -> Sealer<'_> {
        Sealer::new(CryptoSuite {
            randomness: &self.randomness,
            aead: &ToyAead,
            stretcher: &self.stretcher,
            kdf: &ToyKdf,
            kem: &self.kem,
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
        .seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, Some(&pass("pw")))
        .unwrap();
    assert_eq!(world.sealer().open_as_recipient(&envelope, &recipient.seed, Some(&pass("pw"))).unwrap(), secret());
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
        let envelope =
            world.sealer().seal_for_recipient(&secret(), &recipient.public_key, &recipient.fingerprint, None).unwrap();
        assert_eq!(world.sealer().open_link(&envelope, &key, None), Err(SealError::WrongMode));
    }

    #[test]
    fn substituted_public_key_is_refused_before_encapsulating() {
        let world = World::new();
        let alice = world.sealer().new_recipient().unwrap();
        let mallory = world.sealer().new_recipient().unwrap();
        let result = world.sealer().seal_for_recipient(&secret(), &mallory.public_key, &alice.fingerprint, None);
        assert_eq!(result.unwrap_err(), SealError::FingerprintMismatch);
        assert_eq!(world.kem.encapsulations.get(), 0);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let world = World::new();
        let alice = world.sealer().new_recipient().unwrap();
        let mallory = world.sealer().new_recipient().unwrap();
        let envelope =
            world.sealer().seal_for_recipient(&secret(), &alice.public_key, &alice.fingerprint, None).unwrap();
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
}
