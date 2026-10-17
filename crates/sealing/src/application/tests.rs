use super::fakes::{CountingRandomness, RecordingStretcher, ToyAead, ToyKdf, ToyKem};
use super::{CryptoSuite, SealedFile, Sealer};
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

mod files {
    use super::*;
    use crate::core::{CHUNK_LEN, FileBytes, FileManifest, FileName, SealedChunk};

    fn contents(len: usize) -> FileBytes {
        FileBytes::new((0..len).map(|i| (i * 7 + 3) as u8).collect()).unwrap()
    }

    fn name() -> FileName {
        FileName::new("contratto.pdf".to_owned()).unwrap()
    }

    /// What the recipient does: open the manifest envelope, recognize it, open the chunks.
    fn open_by_link(world: &World, file: &SealedFile, key: &LinkKey, pass: Option<&Passphrase>) -> FileBytes {
        let plaintext = world.sealer().open_link(&file.manifest, key, pass).unwrap();
        let manifest = FileManifest::recognize(&plaintext).unwrap().expect("a file manifest");
        world.sealer().open_file(&manifest, &file.chunks).unwrap()
    }

    #[test]
    fn link_mode_file_roundtrip_across_chunk_edges() {
        let world = World::new();
        for len in [1, 255, 256, 257, CHUNK_LEN - 1, CHUNK_LEN, CHUNK_LEN + 1, 3 * CHUNK_LEN + 12_345] {
            let (file, key) = world.sealer().seal_file_for_link(name(), &contents(len), None).unwrap();
            assert_eq!(file.chunks.len(), len.div_ceil(CHUNK_LEN), "{len}");
            assert_eq!(open_by_link(&world, &file, &key, None), contents(len), "{len}");
        }
    }

    #[test]
    fn manifest_names_the_file_and_rides_a_v1_envelope() {
        let world = World::new();
        let (file, key) = world.sealer().seal_file_for_link(name(), &contents(10), Some(&pass("pw"))).unwrap();
        assert!(file.manifest.needs_passphrase());
        assert_eq!(Envelope::parse(&file.manifest.to_bytes()).unwrap(), file.manifest);
        let plaintext = world.sealer().open_link(&file.manifest, &key, Some(&pass("pw"))).unwrap();
        let manifest = FileManifest::recognize(&plaintext).unwrap().unwrap();
        assert_eq!((manifest.name().as_str(), manifest.size().bytes()), ("contratto.pdf", 10));
    }

    #[test]
    fn recipient_mode_file_roundtrip() {
        let world = World::new();
        let recipient = world.sealer().new_recipient().unwrap();
        let file = world
            .sealer()
            .seal_file_for_recipient(
                name(),
                &contents(CHUNK_LEN + 5),
                &recipient.public_key,
                &recipient.fingerprint,
                None,
            )
            .unwrap();
        let plaintext = world.sealer().open_as_recipient(&file.manifest, &recipient.seed, None).unwrap();
        let manifest = FileManifest::recognize(&plaintext).unwrap().unwrap();
        assert_eq!(world.sealer().open_file(&manifest, &file.chunks).unwrap(), contents(CHUNK_LEN + 5));
    }

    #[test]
    fn text_secrets_are_still_text() {
        let world = World::new();
        let (envelope, key) = world.sealer().seal_for_link(&secret(), None).unwrap();
        let plaintext = world.sealer().open_link(&envelope, &key, None).unwrap();
        assert_eq!(FileManifest::recognize(&plaintext), Ok(None));
    }

    mod adversary {
        use super::*;

        fn sealed(world: &World, len: usize) -> (FileManifest, Vec<SealedChunk>) {
            let (file, key) = world.sealer().seal_file_for_link(name(), &contents(len), None).unwrap();
            let plaintext = world.sealer().open_link(&file.manifest, &key, None).unwrap();
            (FileManifest::recognize(&plaintext).unwrap().unwrap(), file.chunks)
        }

        #[test]
        fn reordered_chunks_are_not_authentic() {
            let world = World::new();
            let (manifest, mut chunks) = sealed(&world, 3 * CHUNK_LEN);
            chunks.swap(0, 1);
            assert_eq!(world.sealer().open_file(&manifest, &chunks), Err(SealError::NotAuthentic));
        }

        #[test]
        fn dropped_duplicated_or_extra_chunks_are_not_authentic() {
            let world = World::new();
            let (manifest, chunks) = sealed(&world, 2 * CHUNK_LEN + 1);
            let truncated = &chunks[..2];
            assert_eq!(world.sealer().open_file(&manifest, truncated), Err(SealError::NotAuthentic));
            let duplicated = [chunks[0].clone(), chunks[0].clone(), chunks[2].clone()];
            assert_eq!(world.sealer().open_file(&manifest, &duplicated), Err(SealError::NotAuthentic));
            let mut extra = chunks.clone();
            extra.push(chunks[2].clone());
            assert_eq!(world.sealer().open_file(&manifest, &extra), Err(SealError::NotAuthentic));
        }

        #[test]
        fn a_file_cut_at_a_chunk_boundary_is_not_authentic() {
            // The relay keeps the first chunk of a two-chunk file and claims it
            // is a one-chunk file: the count in the associated data says otherwise.
            let world = World::new();
            let (long_manifest, long_chunks) = sealed(&world, 2 * CHUNK_LEN);
            let short = FileManifest::new(
                long_manifest.key().clone(),
                crate::core::FileSize::new(CHUNK_LEN as u64).unwrap(),
                name(),
            );
            assert_eq!(world.sealer().open_file(&short, &long_chunks[..1]), Err(SealError::NotAuthentic));
        }

        #[test]
        fn chunks_of_another_file_are_not_authentic() {
            let world = World::new();
            let (manifest, mut chunks) = sealed(&world, 2 * CHUNK_LEN);
            let (_, other) = sealed(&world, 2 * CHUNK_LEN);
            chunks[1] = other[1].clone();
            assert_eq!(world.sealer().open_file(&manifest, &chunks), Err(SealError::NotAuthentic));
        }

        #[test]
        fn a_flipped_bit_anywhere_in_a_chunk_is_not_authentic() {
            let world = World::new();
            let (manifest, chunks) = sealed(&world, 300);
            let len = chunks[0].as_bytes().len();
            for i in (0..len).step_by(37).chain([len - 1]) {
                let mut bytes = chunks[0].as_bytes().to_vec();
                bytes[i] ^= 0x01;
                let flipped = [SealedChunk::new(bytes).unwrap()];
                assert_eq!(world.sealer().open_file(&manifest, &flipped), Err(SealError::NotAuthentic), "byte {i}");
            }
        }

        #[test]
        fn a_truncated_chunk_is_not_authentic() {
            let world = World::new();
            let (manifest, chunks) = sealed(&world, 1000);
            let cut = SealedChunk::new(chunks[0].as_bytes()[..600].to_vec()).unwrap();
            assert_eq!(world.sealer().open_file(&manifest, &[cut]), Err(SealError::NotAuthentic));
        }

        #[test]
        fn every_file_gets_a_fresh_key() {
            let world = World::new();
            let (a, _) = sealed(&world, 10);
            let (b, _) = sealed(&world, 10);
            assert_ne!(a.key(), b.key());
        }

        #[test]
        fn substituted_public_key_is_refused_before_any_chunk_is_sealed() {
            let world = World::new();
            let alice = world.sealer().new_recipient().unwrap();
            let mallory = world.sealer().new_recipient().unwrap();
            let result = world.sealer().seal_file_for_recipient(
                name(),
                &contents(10),
                &mallory.public_key,
                &alice.fingerprint,
                None,
            );
            assert_eq!(result.unwrap_err(), SealError::FingerprintMismatch);
            assert_eq!(world.kem.encapsulations.get(), 0);
        }

        #[test]
        fn the_file_key_never_appears_outside_the_sealed_manifest() {
            let world = World::new();
            let (file, key) = world.sealer().seal_file_for_link(name(), &contents(2000), None).unwrap();
            let plaintext = world.sealer().open_link(&file.manifest, &key, None).unwrap();
            let manifest = FileManifest::recognize(&plaintext).unwrap().unwrap();
            let file_key = manifest.key().expose();
            assert!(!file.manifest.to_bytes().windows(32).any(|w| w == file_key));
            assert!(!file.chunks.iter().any(|c| c.as_bytes().windows(32).any(|w| w == file_key)));
        }
    }
}
