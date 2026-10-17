use super::fakes::{BrokenIds, FakeVault, SequentialIds, StuckIds, ToyDigest, block_on};
use super::{Answer, Custodian, IdSource, TokenDigest};
use crate::core::{CustodyError, Lifetime, RecipientKeyBlob, Retention, RevocationToken, SealedPayload};

fn payload() -> SealedPayload {
    SealedPayload::new(b"SGY\x01opaque-ciphertext".to_vec()).unwrap()
}

fn token(n: u8) -> RevocationToken {
    RevocationToken::from_slice(&[n; 32]).unwrap()
}

fn key() -> RecipientKeyBlob {
    RecipientKeyBlob::new(vec![4; RecipientKeyBlob::LEN]).unwrap()
}

fn custodian(vault: &FakeVault) -> Custodian<&FakeVault, ToyDigest, SequentialIds> {
    Custodian::new(vault, ToyDigest, SequentialIds::default())
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

    let answer = Answer { payload: payload(), retention: Retention::BurnAfterReading, lifetime: Lifetime::ONE_HOUR };
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
        let forgery = SealedPayload::new(b"SGY\x01forged".to_vec()).unwrap();
        let refill = block_on(c.deposit(forgery, Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
        assert_ne!(refill.id, original.id);
        assert_eq!(block_on(c.open(&original.id)), Err(CustodyError::NotFound));
    }

    #[test]
    fn a_stuck_id_source_cannot_overwrite_a_live_secret() {
        let vault = FakeVault::default();
        let c = Custodian::new(&vault, ToyDigest, StuckIds);
        let first = block_on(c.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
        let evil = SealedPayload::new(b"attacker".to_vec()).unwrap();
        let again = block_on(c.deposit(evil, Retention::UntilExpiry, Lifetime::MAX, None));
        assert_eq!(again, Err(CustodyError::AlreadyExists));
        assert_eq!(block_on(c.open(&first.id)).unwrap().payload, payload());
    }

    #[test]
    fn a_failing_id_source_stores_nothing() {
        let vault = FakeVault::default();
        let c = Custodian::new(&vault, ToyDigest, BrokenIds);
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
        let answer = || Answer { payload: payload(), retention: Retention::UntilExpiry, lifetime: Lifetime::ONE_HOUR };
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
        let answer =
            Answer { payload: payload(), retention: Retention::BurnAfterReading, lifetime: Lifetime::ONE_HOUR };
        block_on(c.answer_request(request.id, answer)).unwrap();
        assert_eq!(block_on(c.open(&request.id)), Err(CustodyError::NotFound));
        let opened = block_on(c.open(&request.inbox)).unwrap();
        assert_eq!((opened.payload, opened.burned), (payload(), true));
    }

    #[test]
    fn a_stuck_random_source_never_files_the_answer_under_the_request_id() {
        let vault = FakeVault::default();
        let c = Custodian::new(&vault, ToyDigest, StuckIds);
        assert_eq!(block_on(c.post_request(key(), Lifetime::ONE_DAY)), Err(CustodyError::RandomnessUnavailable));
        assert!(vault.is_empty());
    }

    #[test]
    fn a_secret_id_is_not_a_request_that_can_be_answered() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let secret = block_on(c.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None)).unwrap();
        let answer = Answer { payload: payload(), retention: Retention::UntilExpiry, lifetime: Lifetime::ONE_HOUR };
        assert_eq!(block_on(c.answer_request(secret.id, answer)), Err(CustodyError::NotFound));
    }

    #[test]
    fn expired_requests_cannot_be_answered() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let request = block_on(c.post_request(key(), Lifetime::MIN)).unwrap();
        vault.advance(i64::from(Lifetime::MIN.seconds()));
        let answer = Answer { payload: payload(), retention: Retention::UntilExpiry, lifetime: Lifetime::ONE_HOUR };
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
