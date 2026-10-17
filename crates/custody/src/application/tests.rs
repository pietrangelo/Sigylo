use super::fakes::{BrokenIds, FakeStore, FakeVault, SequentialIds, StuckIds, ToyDigest, block_on};
use super::{Answer, Custodian, IdSource, TokenDigest};
use crate::core::{
    CustodyError, Lifetime, MIN_PAYLOAD_LEN, RecipientKeyBlob, Retention, RevocationToken, SealedPayload,
};

fn payload() -> SealedPayload {
    sealed(b"SGY\x01opaque-ciphertext")
}

/// An envelope-sized payload that starts with `head`.
fn sealed(head: &[u8]) -> SealedPayload {
    let mut bytes = head.to_vec();
    bytes.resize(MIN_PAYLOAD_LEN, 0xA0);
    SealedPayload::new(bytes).unwrap()
}

fn token(n: u8) -> RevocationToken {
    RevocationToken::from_slice(&[n; 32]).unwrap()
}

fn key() -> RecipientKeyBlob {
    RecipientKeyBlob::new(vec![4; RecipientKeyBlob::LEN]).unwrap()
}

type TestCustodian<'a> = Custodian<&'a FakeVault, &'a FakeStore, ToyDigest, SequentialIds>;

fn custodian(vault: &FakeVault) -> TestCustodian<'_> {
    Custodian::new(vault, &vault.store, ToyDigest, SequentialIds::default())
}

#[test]
fn burn_after_reading_gives_the_payload_exactly_once() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    let receipt = block_on(c.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
    let opened = block_on(c.open(&receipt.id)).unwrap();
    assert_eq!((opened.payload, opened.burned), (payload(), true));
    assert_eq!(block_on(c.open(&receipt.id)), Err(CustodyError::NotFound));
}

#[test]
fn until_expiry_can_be_read_repeatedly_then_vanishes() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    let receipt = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_HOUR, None)).unwrap();
    assert_eq!(receipt.expires_at.0, 3600);
    for _ in 0..3 {
        assert!(!block_on(c.open(&receipt.id)).unwrap().burned);
    }
    vault.advance(3600);
    assert_eq!(block_on(c.open(&receipt.id)), Err(CustodyError::NotFound));
}

#[test]
fn unread_burn_after_reading_still_expires() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    let receipt = block_on(c.deposit(payload(), Retention::BurnAfterReading, Lifetime::MIN, None)).unwrap();
    vault.advance(i64::from(Lifetime::MIN.seconds()));
    assert_eq!(block_on(c.open(&receipt.id)), Err(CustodyError::NotFound));
    assert_eq!(block_on(c.purge_expired()), Ok(1));
}

#[test]
fn revocation_destroys_an_unread_deposit() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    let receipt = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(7)))).unwrap();
    block_on(c.revoke(&receipt.id, &token(7))).unwrap();
    assert_eq!(block_on(c.open(&receipt.id)), Err(CustodyError::NotFound));
}

#[test]
fn request_lifecycle_answer_lands_in_the_private_inbox() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    let request = block_on(c.post_request(key(), Lifetime::ONE_DAY)).unwrap();
    assert_eq!(block_on(c.fetch_request(&request.id)).unwrap().recipient_key, key());

    let answer = Answer {
        payload: payload(),
        retention: Retention::BurnAfterReading,
        lifetime: Lifetime::ONE_HOUR,
        chunks: None,
    };
    block_on(c.answer_request(request.id, answer)).unwrap();
    assert_eq!(block_on(c.fetch_request(&request.id)), Err(CustodyError::NotFound));
    assert_eq!(block_on(c.open(&request.inbox)).unwrap().payload, payload());
}

#[test]
fn every_deposit_and_request_gets_its_own_id() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    let a = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None)).unwrap();
    let b = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None)).unwrap();
    let r = block_on(c.post_request(key(), Lifetime::ONE_DAY)).unwrap();
    let ids = [a.id, b.id, r.id, r.inbox];
    for (i, x) in ids.iter().enumerate() {
        assert!(ids[i + 1..].iter().all(|y| y != x), "{x:?} repeats");
    }
}

mod adversary {
    use super::*;

    #[test]
    fn vault_stores_only_the_digest_of_the_revocation_token() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let receipt =
            block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(7)))).unwrap();
        let stored = vault.stored_digest(&receipt.id).unwrap();
        assert_ne!(stored.as_bytes(), token(7).expose());
        assert_eq!(stored, ToyDigest.digest(&token(7)));
    }

    #[test]
    fn wrong_token_or_missing_token_cannot_revoke() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let with = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(7)))).unwrap();
        let without = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None)).unwrap();
        assert_eq!(block_on(c.revoke(&with.id, &token(8))), Err(CustodyError::NotFound));
        assert_eq!(block_on(c.revoke(&without.id, &token(7))), Err(CustodyError::NotFound));
        assert!(block_on(c.open(&with.id)).is_ok() && block_on(c.open(&without.id)).is_ok());
    }

    #[test]
    fn whoever_burns_a_secret_cannot_refill_its_link() {
        // An eavesdropper with the whole link reads first, then re-seals the
        // secret (or a forgery) under the same key. If it could land under the
        // same id, the real recipient would open it and never notice.
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let original = block_on(c.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
        block_on(c.open(&original.id)).unwrap();
        let forgery = sealed(b"SGY\x01forged");
        let refill = block_on(c.deposit(forgery, Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
        assert_ne!(refill.id, original.id);
        assert_eq!(block_on(c.open(&original.id)), Err(CustodyError::NotFound));
    }

    #[test]
    fn a_stuck_id_source_cannot_overwrite_a_live_secret() {
        let vault = FakeVault::default();
        let c = Custodian::new(&vault, &vault.store, ToyDigest, StuckIds);
        let first = block_on(c.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
        let evil = sealed(b"attacker");
        let again = block_on(c.deposit(evil, Retention::UntilExpiry, Lifetime::MAX, None));
        assert_eq!(again, Err(CustodyError::AlreadyExists));
        assert_eq!(block_on(c.open(&first.id)).unwrap().payload, payload());
    }

    #[test]
    fn a_failing_id_source_stores_nothing() {
        let vault = FakeVault::default();
        let c = Custodian::new(&vault, &vault.store, ToyDigest, BrokenIds);
        let deposit = block_on(c.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None));
        assert_eq!(deposit, Err(CustodyError::RandomnessUnavailable));
        assert_eq!(block_on(c.post_request(key(), Lifetime::ONE_DAY)), Err(CustodyError::RandomnessUnavailable));
        assert_eq!(block_on(c.purge_expired()), Ok(0));
        assert!(vault.is_empty());
    }

    #[test]
    fn a_request_is_answered_at_most_once() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let request = block_on(c.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        let answer = || Answer {
            payload: payload(),
            retention: Retention::UntilExpiry,
            lifetime: Lifetime::ONE_HOUR,
            chunks: None,
        };
        block_on(c.answer_request(request.id, answer())).unwrap();
        assert_eq!(block_on(c.answer_request(request.id, answer())), Err(CustodyError::NotFound));
    }

    #[test]
    fn the_request_link_can_neither_read_nor_burn_the_answer() {
        // The request link goes to the sender, often over a channel others can
        // read. Whoever holds it must not be able to burn the answer before the
        // recipient, nor fetch it: only the private inbox link reaches it.
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let request = block_on(c.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        let answer = Answer {
            payload: payload(),
            retention: Retention::BurnAfterReading,
            lifetime: Lifetime::ONE_HOUR,
            chunks: None,
        };
        block_on(c.answer_request(request.id, answer)).unwrap();
        assert_eq!(block_on(c.open(&request.id)), Err(CustodyError::NotFound));
        let opened = block_on(c.open(&request.inbox)).unwrap();
        assert_eq!((opened.payload, opened.burned), (payload(), true));
    }

    #[test]
    fn a_stuck_random_source_never_files_the_answer_under_the_request_id() {
        let vault = FakeVault::default();
        let c = Custodian::new(&vault, &vault.store, ToyDigest, StuckIds);
        assert_eq!(block_on(c.post_request(key(), Lifetime::ONE_DAY)), Err(CustodyError::RandomnessUnavailable));
        assert!(vault.is_empty());
    }

    #[test]
    fn a_secret_id_is_not_a_request_that_can_be_answered() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let secret = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None)).unwrap();
        let answer = Answer {
            payload: payload(),
            retention: Retention::UntilExpiry,
            lifetime: Lifetime::ONE_HOUR,
            chunks: None,
        };
        assert_eq!(block_on(c.answer_request(secret.id, answer)), Err(CustodyError::NotFound));
    }

    #[test]
    fn expired_requests_cannot_be_answered() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let request = block_on(c.post_request(key(), Lifetime::MIN)).unwrap();
        vault.advance(i64::from(Lifetime::MIN.seconds()));
        let answer = Answer {
            payload: payload(),
            retention: Retention::UntilExpiry,
            lifetime: Lifetime::ONE_HOUR,
            chunks: None,
        };
        assert_eq!(block_on(c.answer_request(request.id, answer)), Err(CustodyError::NotFound));
        assert_eq!(block_on(c.fetch_request(&request.id)), Err(CustodyError::NotFound));
    }

    #[test]
    fn missing_expired_burned_and_revoked_look_the_same() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let never = SequentialIds::starting_at(200).fresh().unwrap();
        let burned = block_on(c.deposit(payload(), Retention::BurnAfterReading, Lifetime::MIN, None)).unwrap();
        block_on(c.open(&burned.id)).unwrap();
        let revoked = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::MIN, Some(&token(1)))).unwrap();
        block_on(c.revoke(&revoked.id, &token(1))).unwrap();
        let expired = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::MIN, None)).unwrap();
        vault.advance(i64::from(Lifetime::MIN.seconds()));
        for id in [never, burned.id, revoked.id, expired.id] {
            assert_eq!(block_on(c.open(&id)), Err(CustodyError::NotFound), "{id:?}");
        }
    }
}

mod files {
    use super::*;
    use crate::core::{
        CLAIM_WINDOW_SECONDS, ChunkCount, ChunkIndex, ClaimToken, DropId, MAX_CHUNK_LEN, MIN_CHUNK_LEN, SealedChunk,
    };

    fn count(n: u16) -> ChunkCount {
        ChunkCount::new(n).unwrap()
    }

    fn at(i: u16) -> ChunkIndex {
        ChunkIndex::new(i).unwrap()
    }

    fn chunk(i: u16) -> SealedChunk {
        SealedChunk::new(vec![i as u8 + 1; MAX_CHUNK_LEN]).unwrap()
    }

    fn deposit_file(c: &TestCustodian<'_>, n: u16, retention: Retention) -> DropId {
        let receipt = block_on(c.deposit_file(payload(), count(n), retention, Lifetime::ONE_DAY, Some(&token(3))));
        receipt.unwrap().id
    }

    fn upload_all(c: &TestCustodian<'_>, id: &DropId, n: u16) {
        for i in 0..n {
            block_on(c.put_chunk(id, at(i), chunk(i))).unwrap();
        }
    }

    #[test]
    fn burn_after_reading_file_hands_each_chunk_once_to_whoever_opened_it() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let id = deposit_file(&c, 3, Retention::BurnAfterReading);
        upload_all(&c, &id, 3);
        let opened = block_on(c.open(&id)).unwrap();
        assert_eq!((opened.payload, opened.burned, opened.chunks), (payload(), true, Some(count(3))));
        let claim = opened.claim.expect("a burned file comes with its claim");
        for i in 0..3 {
            assert_eq!(block_on(c.open_chunk(&id, at(i), Some(&claim))), Ok(chunk(i)));
            assert_eq!(block_on(c.open_chunk(&id, at(i), Some(&claim))), Err(CustodyError::NotFound));
        }
        // The deposit went with its last chunk.
        assert!(vault.is_empty());
    }

    #[test]
    fn until_expiry_file_is_readable_by_anyone_with_the_link_until_it_expires() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let id = deposit_file(&c, 2, Retention::UntilExpiry);
        upload_all(&c, &id, 2);
        for _ in 0..2 {
            let opened = block_on(c.open(&id)).unwrap();
            assert_eq!((opened.burned, opened.chunks, opened.claim), (false, Some(count(2)), None));
            assert_eq!(block_on(c.open_chunk(&id, at(1), None)), Ok(chunk(1)));
        }
        vault.advance(i64::from(Lifetime::ONE_DAY.seconds()));
        assert_eq!(block_on(c.open_chunk(&id, at(0), None)), Err(CustodyError::NotFound));
        assert_eq!(block_on(c.purge_expired()), Ok(1));
        assert!(vault.is_empty());
    }

    #[test]
    fn a_text_secret_carries_no_chunks_and_no_claim() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let receipt = block_on(c.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
        let opened = block_on(c.open(&receipt.id)).unwrap();
        assert_eq!((opened.chunks, opened.claim), (None, None));
    }

    #[test]
    fn a_request_can_be_answered_with_a_file() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let request = block_on(c.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        let answer = Answer {
            payload: payload(),
            retention: Retention::BurnAfterReading,
            lifetime: Lifetime::ONE_HOUR,
            chunks: Some(count(2)),
        };
        // The sender learns where the answer went, so it can upload the chunks there.
        let receipt = block_on(c.answer_request(request.id, answer)).unwrap();
        assert_eq!(receipt.id, request.inbox);
        assert_eq!(block_on(c.open(&request.inbox)), Err(CustodyError::NotFound), "not before the chunks");
        upload_all(&c, &receipt.id, 2);
        let opened = block_on(c.open(&request.inbox)).unwrap();
        assert_eq!(block_on(c.open_chunk(&request.inbox, at(0), opened.claim.as_ref())), Ok(chunk(0)));
    }

    #[test]
    fn the_request_link_cannot_spoil_a_file_answer() {
        // adversary: whoever saw the request link races the sender to the chunks.
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let request = block_on(c.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        let answer = Answer {
            payload: payload(),
            retention: Retention::UntilExpiry,
            lifetime: Lifetime::ONE_HOUR,
            chunks: Some(count(1)),
        };
        let receipt = block_on(c.answer_request(request.id, answer)).unwrap();
        let junk = SealedChunk::new(vec![0xEE; MIN_CHUNK_LEN]).unwrap();
        assert_eq!(block_on(c.put_chunk(&request.id, at(0), junk)), Err(CustodyError::NotFound));
        block_on(c.put_chunk(&receipt.id, at(0), chunk(0))).unwrap();
        assert_eq!(block_on(c.open_chunk(&request.inbox, at(0), None)), Ok(chunk(0)));
    }

    #[test]
    fn revoking_a_file_takes_its_chunks_along() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let id = deposit_file(&c, 2, Retention::UntilExpiry);
        upload_all(&c, &id, 2);
        block_on(c.revoke(&id, &token(3))).unwrap();
        assert!(vault.is_empty());
        assert_eq!(block_on(c.collect_garbage()), Ok(2));
        assert_eq!((vault.store.objects(), vault.garbage()), (0, 0));
    }

    #[test]
    fn chunks_live_in_the_store_and_the_vault_keeps_only_their_names() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let id = deposit_file(&c, 2, Retention::UntilExpiry);
        upload_all(&c, &id, 2);
        assert_eq!((vault.stored_chunks(), vault.store.objects()), (2, 2));
        let mut kept = vault.store.contents();
        kept.sort_by_key(|c| c.as_bytes().to_vec());
        assert_eq!(kept, vec![chunk(0), chunk(1)]);
    }

    #[test]
    fn a_burned_chunk_leaves_the_store_as_it_is_handed_out() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let id = deposit_file(&c, 2, Retention::BurnAfterReading);
        upload_all(&c, &id, 2);
        let claim = block_on(c.open(&id)).unwrap().claim.unwrap();
        block_on(c.open_chunk(&id, at(0), Some(&claim))).unwrap();
        assert_eq!(vault.store.objects(), 1);
        block_on(c.open_chunk(&id, at(1), Some(&claim))).unwrap();
        assert_eq!(vault.store.objects(), 0);
        // What the store already dropped costs nothing more to collect.
        block_on(c.collect_garbage()).unwrap();
        assert_eq!(vault.garbage(), 0);
    }

    #[test]
    fn expired_files_leave_the_store_with_the_next_collection() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let id = deposit_file(&c, 3, Retention::BurnAfterReading);
        upload_all(&c, &id, 3);
        vault.advance(i64::from(Lifetime::ONE_DAY.seconds()));
        assert_eq!(block_on(c.purge_expired()), Ok(1));
        assert_eq!(vault.store.objects(), 3);
        assert_eq!(block_on(c.collect_garbage()), Ok(3));
        assert_eq!(vault.store.objects(), 0);
        assert_eq!(block_on(c.collect_garbage()), Ok(0));
    }

    mod adversary {
        use super::*;

        #[test]
        fn an_incomplete_file_cannot_be_opened() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 3, Retention::BurnAfterReading);
            block_on(c.put_chunk(&id, at(0), chunk(0))).unwrap();
            block_on(c.put_chunk(&id, at(2), chunk(2))).unwrap();
            assert_eq!(block_on(c.open(&id)), Err(CustodyError::NotFound));
            assert_eq!(block_on(c.open_chunk(&id, at(0), None)), Err(CustodyError::NotFound));
        }

        #[test]
        fn chunks_are_written_once_and_only_where_the_count_allows() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 2, Retention::UntilExpiry);
            block_on(c.put_chunk(&id, at(0), chunk(0))).unwrap();
            let forged = SealedChunk::new(vec![0xF0; MAX_CHUNK_LEN]).unwrap();
            assert_eq!(block_on(c.put_chunk(&id, at(0), forged.clone())), Err(CustodyError::AlreadyExists));
            assert_eq!(block_on(c.put_chunk(&id, at(2), forged)), Err(CustodyError::NotFound));
            assert_eq!(vault.stored_chunks(), 1);
        }

        #[test]
        fn a_short_chunk_fits_only_the_end_of_a_file() {
            // Only the last chunk is padded short: anything else is junk that
            // would cost a row and an object for a few bytes.
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 2, Retention::UntilExpiry);
            let short = SealedChunk::new(vec![3; MIN_CHUNK_LEN]).unwrap();
            assert_eq!(block_on(c.put_chunk(&id, at(0), short.clone())), Err(CustodyError::NotFound));
            assert_eq!((vault.stored_chunks(), vault.store.objects()), (0, 0));
            block_on(c.put_chunk(&id, at(1), short.clone())).unwrap();
            block_on(c.put_chunk(&id, at(0), chunk(0))).unwrap();
            assert_eq!(block_on(c.open_chunk(&id, at(1), None)), Ok(short));
        }

        #[test]
        fn no_chunk_can_be_added_after_the_file_was_opened() {
            // A reader who holds the link cannot slip a chunk into a file that
            // others will open after them, nor into a text secret.
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 1, Retention::BurnAfterReading);
            upload_all(&c, &id, 1);
            block_on(c.open(&id)).unwrap();
            assert_eq!(block_on(c.put_chunk(&id, at(0), chunk(9))), Err(CustodyError::NotFound));
            let text = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None)).unwrap();
            assert_eq!(block_on(c.put_chunk(&text.id, at(0), chunk(0))), Err(CustodyError::NotFound));
        }

        #[test]
        fn a_claimed_file_cannot_be_opened_again_nor_its_chunks_taken_without_the_claim() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 2, Retention::BurnAfterReading);
            upload_all(&c, &id, 2);
            let first = block_on(c.open(&id)).unwrap();
            assert_eq!(block_on(c.open(&id)), Err(CustodyError::NotFound));
            let guessed = ClaimToken::from_array([0x42; 32]);
            for claim in [None, Some(&guessed)] {
                assert_eq!(block_on(c.open_chunk(&id, at(0), claim)), Err(CustodyError::NotFound));
            }
            assert_eq!(block_on(c.open_chunk(&id, at(0), first.claim.as_ref())), Ok(chunk(0)));
        }

        #[test]
        fn the_vault_keeps_only_the_digest_of_the_claim() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 1, Retention::BurnAfterReading);
            upload_all(&c, &id, 1);
            let claim = block_on(c.open(&id)).unwrap().claim.unwrap();
            let stored = vault.stored_claim(&id).unwrap();
            assert_ne!(stored.as_bytes(), claim.expose());
            assert_eq!(stored, ToyDigest.digest_claim(&claim));
        }

        #[test]
        fn an_abandoned_claim_lapses_within_the_claim_window() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 2, Retention::BurnAfterReading);
            upload_all(&c, &id, 2);
            let claim = block_on(c.open(&id)).unwrap().claim.unwrap();
            assert_eq!(vault.expires_at(&id), Some(i64::from(CLAIM_WINDOW_SECONDS)));
            vault.advance(i64::from(CLAIM_WINDOW_SECONDS));
            assert_eq!(block_on(c.open_chunk(&id, at(0), Some(&claim))), Err(CustodyError::NotFound));
            assert_eq!(block_on(c.purge_expired()), Ok(1));
            assert!(vault.is_empty());
        }

        #[test]
        fn the_claim_window_never_extends_a_deposit() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let receipt =
                block_on(c.deposit_file(payload(), count(1), Retention::BurnAfterReading, Lifetime::MIN, None));
            let id = receipt.unwrap().id;
            upload_all(&c, &id, 1);
            block_on(c.open(&id)).unwrap();
            assert_eq!(vault.expires_at(&id), Some(i64::from(Lifetime::MIN.seconds())));
        }

        #[test]
        fn a_refused_chunk_leaves_nothing_in_the_store() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 1, Retention::BurnAfterReading);
            upload_all(&c, &id, 1);
            assert_eq!(block_on(c.put_chunk(&id, at(0), chunk(5))), Err(CustodyError::AlreadyExists));
            assert_eq!(block_on(c.put_chunk(&id, at(1), chunk(5))), Err(CustodyError::NotFound));
            let unknown = DropId::from_slice(&[0x77; 16]).unwrap();
            assert_eq!(block_on(c.put_chunk(&unknown, at(0), chunk(5))), Err(CustodyError::NotFound));
            assert_eq!(vault.store.objects(), 1);
        }

        #[test]
        fn a_chunk_over_the_quota_leaves_nothing_in_the_store() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 1, Retention::UntilExpiry);
            vault.full.set(true);
            assert_eq!(block_on(c.put_chunk(&id, at(0), chunk(0))), Err(CustodyError::StorageFull));
            assert_eq!((vault.stored_chunks(), vault.store.objects()), (0, 0));
        }

        #[test]
        fn a_chunk_the_store_could_not_keep_is_not_recorded() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 1, Retention::UntilExpiry);
            vault.store.fail.set(true);
            assert_eq!(block_on(c.put_chunk(&id, at(0), chunk(0))), Err(CustodyError::VaultUnavailable));
            vault.store.fail.set(false);
            assert_eq!(vault.stored_chunks(), 0);
            assert_eq!(block_on(c.open(&id)), Err(CustodyError::NotFound), "the file is still incomplete");
            upload_all(&c, &id, 1);
            assert!(block_on(c.open(&id)).is_ok());
        }

        #[test]
        fn a_claim_sent_for_a_file_kept_until_expiry_burns_nothing() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 1, Retention::UntilExpiry);
            upload_all(&c, &id, 1);
            let guessed = ClaimToken::from_array([0x42; 32]);
            for _ in 0..2 {
                assert_eq!(block_on(c.open_chunk(&id, at(0), Some(&guessed))), Ok(chunk(0)));
            }
            assert_eq!(vault.store.objects(), 1);
        }

        #[test]
        fn object_names_are_fresh_and_say_nothing_of_the_deposit() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 3, Retention::UntilExpiry);
            upload_all(&c, &id, 3);
            let names = vault.store.names();
            assert_eq!(names.len(), 3);
            for name in &names {
                assert_ne!(name.as_bytes(), id.as_bytes());
            }
            let mut unique = names.clone();
            unique.sort_by_key(|n| *n.as_bytes());
            unique.dedup();
            assert_eq!(unique.len(), 3);
        }

        #[test]
        fn garbage_survives_a_store_that_fails_to_delete() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 2, Retention::UntilExpiry);
            upload_all(&c, &id, 2);
            block_on(c.revoke(&id, &token(3))).unwrap();
            vault.store.fail.set(true);
            assert_eq!(block_on(c.collect_garbage()), Err(CustodyError::VaultUnavailable));
            vault.store.fail.set(false);
            assert_eq!(vault.store.objects(), 2, "nothing was lost track of");
            assert_eq!(block_on(c.collect_garbage()), Ok(2));
            assert_eq!(vault.store.objects(), 0);
        }

        #[test]
        fn chunks_of_one_file_are_not_reachable_through_another() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let a = deposit_file(&c, 1, Retention::UntilExpiry);
            let b = deposit_file(&c, 1, Retention::UntilExpiry);
            upload_all(&c, &a, 1);
            assert_eq!(block_on(c.open_chunk(&b, at(0), None)), Err(CustodyError::NotFound));
        }

        #[test]
        fn a_failing_random_source_opens_nothing() {
            let vault = FakeVault::default();
            let c = custodian(&vault);
            let id = deposit_file(&c, 1, Retention::BurnAfterReading);
            upload_all(&c, &id, 1);
            let broken = Custodian::new(&vault, &vault.store, ToyDigest, BrokenIds);
            assert_eq!(block_on(broken.open(&id)), Err(CustodyError::RandomnessUnavailable));
            assert!(block_on(c.open(&id)).unwrap().claim.is_some(), "the file is still there");
        }
    }
}
