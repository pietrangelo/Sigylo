use super::fakes::{FakeVault, ToyDigest, block_on};
use super::{Answer, Custodian, TokenDigest};
use crate::core::{
    CustodyError, DropId, Lifetime, RecipientKeyBlob, Request, Retention, RevocationToken, SealedPayload,
};

fn id(n: u8) -> DropId {
    DropId::from_slice(&[n; 16]).unwrap()
}

fn payload() -> SealedPayload {
    SealedPayload::new(b"SGY\x01opaque-ciphertext".to_vec()).unwrap()
}

fn token(n: u8) -> RevocationToken {
    RevocationToken::from_slice(&[n; 32]).unwrap()
}

fn custodian(vault: &FakeVault) -> Custodian<&FakeVault, ToyDigest> {
    Custodian::new(vault, ToyDigest)
}

#[test]
fn burn_after_reading_gives_the_payload_exactly_once() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    block_on(c.deposit(id(1), payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
    let opened = block_on(c.open(&id(1))).unwrap();
    assert_eq!((opened.payload, opened.burned), (payload(), true));
    assert_eq!(block_on(c.open(&id(1))), Err(CustodyError::NotFound));
}

#[test]
fn until_expiry_can_be_read_repeatedly_then_vanishes() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    let expires = block_on(c.deposit(id(1), payload(), Retention::UntilExpiry, Lifetime::ONE_HOUR, None)).unwrap();
    assert_eq!(expires.0, 3600);
    for _ in 0..3 {
        assert!(!block_on(c.open(&id(1))).unwrap().burned);
    }
    vault.advance(3600);
    assert_eq!(block_on(c.open(&id(1))), Err(CustodyError::NotFound));
}

#[test]
fn unread_burn_after_reading_still_expires() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    block_on(c.deposit(id(1), payload(), Retention::BurnAfterReading, Lifetime::MIN, None)).unwrap();
    vault.advance(i64::from(Lifetime::MIN.seconds()));
    assert_eq!(block_on(c.open(&id(1))), Err(CustodyError::NotFound));
    assert_eq!(block_on(c.purge_expired()), Ok(1));
}

#[test]
fn revocation_destroys_an_unread_deposit() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    block_on(c.deposit(id(1), payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(7)))).unwrap();
    block_on(c.revoke(&id(1), &token(7))).unwrap();
    assert_eq!(block_on(c.open(&id(1))), Err(CustodyError::NotFound));
}

#[test]
fn request_lifecycle_answer_lands_under_the_request_id() {
    let vault = FakeVault::default();
    let c = custodian(&vault);
    let key = RecipientKeyBlob::new(vec![4; RecipientKeyBlob::LEN]).unwrap();
    block_on(c.post_request(Request { id: id(9), recipient_key: key.clone(), lifetime: Lifetime::ONE_DAY })).unwrap();
    assert_eq!(block_on(c.fetch_request(&id(9))).unwrap().recipient_key, key);

    let answer = Answer { payload: payload(), retention: Retention::BurnAfterReading, lifetime: Lifetime::ONE_HOUR };
    block_on(c.answer_request(id(9), answer)).unwrap();
    assert_eq!(block_on(c.fetch_request(&id(9))), Err(CustodyError::NotFound));
    assert_eq!(block_on(c.open(&id(9))).unwrap().payload, payload());
}

mod adversary {
    use super::*;

    #[test]
    fn vault_stores_only_the_digest_of_the_revocation_token() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        block_on(c.deposit(id(1), payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(7)))).unwrap();
        let stored = vault.stored_digest(&id(1)).unwrap();
        assert_ne!(stored.as_bytes(), token(7).expose());
        assert_eq!(stored, ToyDigest.digest(&token(7)));
    }

    #[test]
    fn wrong_token_or_missing_token_cannot_revoke() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        block_on(c.deposit(id(1), payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(7)))).unwrap();
        block_on(c.deposit(id(2), payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None)).unwrap();
        assert_eq!(block_on(c.revoke(&id(1), &token(8))), Err(CustodyError::NotFound));
        assert_eq!(block_on(c.revoke(&id(2), &token(7))), Err(CustodyError::NotFound));
        assert!(block_on(c.open(&id(1))).is_ok() && block_on(c.open(&id(2))).is_ok());
    }

    #[test]
    fn a_live_id_cannot_be_overwritten() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        block_on(c.deposit(id(1), payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None)).unwrap();
        let evil = SealedPayload::new(b"attacker".to_vec()).unwrap();
        let again = block_on(c.deposit(id(1), evil, Retention::UntilExpiry, Lifetime::MAX, None));
        assert_eq!(again, Err(CustodyError::AlreadyExists));
        assert_eq!(block_on(c.open(&id(1))).unwrap().payload, payload());
    }

    #[test]
    fn a_request_is_answered_at_most_once() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let key = RecipientKeyBlob::new(vec![4; RecipientKeyBlob::LEN]).unwrap();
        block_on(c.post_request(Request { id: id(9), recipient_key: key, lifetime: Lifetime::ONE_DAY })).unwrap();
        let answer = || Answer { payload: payload(), retention: Retention::UntilExpiry, lifetime: Lifetime::ONE_HOUR };
        block_on(c.answer_request(id(9), answer())).unwrap();
        assert_eq!(block_on(c.answer_request(id(9), answer())), Err(CustodyError::NotFound));
    }

    #[test]
    fn expired_requests_cannot_be_answered() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        let key = RecipientKeyBlob::new(vec![4; RecipientKeyBlob::LEN]).unwrap();
        block_on(c.post_request(Request { id: id(9), recipient_key: key, lifetime: Lifetime::MIN })).unwrap();
        vault.advance(i64::from(Lifetime::MIN.seconds()));
        let answer = Answer { payload: payload(), retention: Retention::UntilExpiry, lifetime: Lifetime::ONE_HOUR };
        assert_eq!(block_on(c.answer_request(id(9), answer)), Err(CustodyError::NotFound));
        assert_eq!(block_on(c.fetch_request(&id(9))), Err(CustodyError::NotFound));
    }

    #[test]
    fn missing_expired_burned_and_revoked_look_the_same() {
        let vault = FakeVault::default();
        let c = custodian(&vault);
        block_on(c.deposit(id(2), payload(), Retention::BurnAfterReading, Lifetime::MIN, None)).unwrap();
        block_on(c.open(&id(2))).unwrap();
        block_on(c.deposit(id(3), payload(), Retention::UntilExpiry, Lifetime::MIN, Some(&token(1)))).unwrap();
        block_on(c.revoke(&id(3), &token(1))).unwrap();
        block_on(c.deposit(id(4), payload(), Retention::UntilExpiry, Lifetime::MIN, None)).unwrap();
        vault.advance(i64::from(Lifetime::MIN.seconds()));
        for n in 1..=4 {
            assert_eq!(block_on(c.open(&id(n))), Err(CustodyError::NotFound), "id {n}");
        }
    }
}
