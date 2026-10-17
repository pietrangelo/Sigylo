//! Vault contract tests against a real PostgreSQL with the Sigylo migrations.
//!
//! Run through `bash supabase/tests/run.sh`, which starts a throwaway
//! database and sets the two URLs. The vault connects as `sigylo_relay`
//! (the Worker's role); time travel uses the owner connection.

use custody::{
    Answer, Custodian, CustodyError, Deposit, DropId, IdSource, Lifetime, RecipientKeyBlob, Request, Retention,
    RevocationToken, SealedPayload, Vault,
};
use custody_adapters::{PostgresVault, RandomIds, Sha256TokenDigest};
use futures_util::future::join_all;
use tokio_postgres::{Client, NoTls};

async fn connect(var: &str) -> Option<Client> {
    let Ok(url) = std::env::var(var) else {
        eprintln!("{var} not set: run `bash supabase/tests/run.sh`; skipping");
        return None;
    };
    let (client, connection) = tokio_postgres::connect(&url, NoTls).await.expect("database reachable");
    tokio::spawn(connection);
    Some(client)
}

macro_rules! databases {
    ($relay:ident, $admin:ident) => {
        let (Some($relay), Some($admin)) =
            (connect("SIGYLO_TEST_RELAY_URL").await, connect("SIGYLO_TEST_DATABASE_URL").await)
        else {
            return;
        };
    };
}

fn fresh_id() -> DropId {
    RandomIds.fresh().unwrap()
}

fn custodian(relay: &Client) -> Custodian<PostgresVault<'_>, Sha256TokenDigest, RandomIds> {
    Custodian::new(PostgresVault::new(relay), Sha256TokenDigest, RandomIds)
}

fn payload() -> SealedPayload {
    SealedPayload::new(b"SGY\x01 opaque".to_vec()).unwrap()
}

fn token(n: u8) -> RevocationToken {
    RevocationToken::from_slice(&[n; 32]).unwrap()
}

fn recipient_key() -> RecipientKeyBlob {
    RecipientKeyBlob::new(vec![7; RecipientKeyBlob::LEN]).unwrap()
}

async fn expire(admin: &Client, table: &str, id: &DropId) {
    let sql = format!("update custody.{table} set expires_at = now() - interval '1 second' where id = $1");
    admin.execute(&sql, &[&id.as_bytes().as_slice()]).await.unwrap();
}

#[tokio::test]
async fn burn_after_reading_is_returned_once() {
    databases!(relay, _admin);
    let custodian = custodian(&relay);
    let id = custodian.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None).await.unwrap().id;
    let opened = custodian.open(&id).await.unwrap();
    assert_eq!((opened.payload, opened.burned), (payload(), true));
    assert_eq!(custodian.open(&id).await, Err(CustodyError::NotFound));
}

#[tokio::test]
async fn until_expiry_is_readable_until_the_database_clock_says_otherwise() {
    databases!(relay, admin);
    let custodian = custodian(&relay);
    let receipt = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_HOUR, None).await.unwrap();
    let id = receipt.id;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!((receipt.expires_at.0 - now - 3600).abs() < 60, "expiry is now + lifetime");
    for _ in 0..3 {
        assert!(!custodian.open(&id).await.unwrap().burned);
    }
    expire(&admin, "deposits", &id).await;
    assert_eq!(custodian.open(&id).await, Err(CustodyError::NotFound));
    assert!(custodian.purge_expired().await.unwrap() >= 1);
}

#[tokio::test]
async fn revocation_needs_the_right_token() {
    databases!(relay, _admin);
    let custodian = custodian(&relay);
    let id = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(1))).await.unwrap().id;
    assert_eq!(custodian.revoke(&id, &token(2)).await, Err(CustodyError::NotFound));
    custodian.revoke(&id, &token(1)).await.unwrap();
    assert_eq!(custodian.open(&id).await, Err(CustodyError::NotFound));
}

#[tokio::test]
async fn request_is_answered_into_its_private_inbox() {
    databases!(relay, _admin);
    let custodian = custodian(&relay);
    let receipt = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap();
    assert_ne!(receipt.id, receipt.inbox);
    assert_eq!(custodian.fetch_request(&receipt.id).await.unwrap().recipient_key, recipient_key());
    let answer = Answer { payload: payload(), retention: Retention::BurnAfterReading, lifetime: Lifetime::ONE_HOUR };
    custodian.answer_request(receipt.id, answer).await.unwrap();
    assert_eq!(custodian.fetch_request(&receipt.id).await, Err(CustodyError::NotFound));
    assert!(custodian.open(&receipt.inbox).await.unwrap().burned);
}

#[tokio::test]
async fn a_request_posted_before_inboxes_is_still_answered_under_its_id() {
    // Requests already live when the inbox column arrived have none: their
    // recipients' links point at the request id, so the answer goes there.
    databases!(relay, admin);
    let id = fresh_id();
    admin
        .execute(
            "insert into custody.requests (id, recipient_key, expires_at) values ($1, $2, now() + interval '1 hour')",
            &[&id.as_bytes().as_slice(), &recipient_key().as_bytes()],
        )
        .await
        .unwrap();
    let custodian = custodian(&relay);
    let answer = Answer { payload: payload(), retention: Retention::UntilExpiry, lifetime: Lifetime::ONE_HOUR };
    custodian.answer_request(id, answer).await.unwrap();
    assert_eq!(custodian.open(&id).await.unwrap().payload, payload());
}

mod adversary {
    use super::*;

    #[tokio::test]
    async fn the_request_link_can_neither_read_nor_burn_the_answer() {
        databases!(relay, _admin);
        let custodian = custodian(&relay);
        let receipt = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap();
        let answer =
            Answer { payload: payload(), retention: Retention::BurnAfterReading, lifetime: Lifetime::ONE_HOUR };
        custodian.answer_request(receipt.id, answer).await.unwrap();
        assert_eq!(custodian.open(&receipt.id).await, Err(CustodyError::NotFound));
        assert_eq!(custodian.open(&receipt.inbox).await.unwrap().payload, payload());
    }

    #[tokio::test]
    async fn concurrent_reads_of_a_burn_after_reading_secret_get_it_once() {
        databases!(relay, _admin);
        let id = custodian(&relay)
            .deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None)
            .await
            .unwrap()
            .id;
        // 16 separate connections race to open the same link.
        let mut clients = Vec::new();
        for _ in 0..16 {
            clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
        }
        let outcomes = join_all(clients.iter().map(|c| async move { PostgresVault::new(c).open(&id).await })).await;
        let winners = outcomes.iter().filter(|o| matches!(o, Ok(Some(_)))).count();
        assert_eq!(winners, 1, "{outcomes:?}");
        assert!(outcomes.iter().all(|o| o.is_ok()));
    }

    #[tokio::test]
    async fn the_database_refuses_an_inbox_that_is_the_request_id() {
        databases!(relay, _admin);
        let id = fresh_id();
        let request = Request { id, inbox: id, recipient_key: recipient_key(), lifetime: Lifetime::ONE_DAY };
        assert!(PostgresVault::new(&relay).post_request(&request).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_answers_to_one_request_store_exactly_one() {
        databases!(relay, _admin);
        let id = fresh_id();
        PostgresVault::new(&relay)
            .post_request(&Request {
                id,
                inbox: fresh_id(),
                recipient_key: recipient_key(),
                lifetime: Lifetime::ONE_DAY,
            })
            .await
            .unwrap();
        let mut clients = Vec::new();
        for _ in 0..8 {
            clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
        }
        let outcomes = join_all(clients.iter().enumerate().map(|(n, c)| async move {
            let answer = Deposit {
                id,
                payload: SealedPayload::new(vec![n as u8 + 1; 64]).unwrap(),
                retention: Retention::UntilExpiry,
                lifetime: Lifetime::ONE_HOUR,
                revocation: None,
            };
            PostgresVault::new(c).answer_request(&answer).await
        }))
        .await;
        assert_eq!(outcomes.iter().filter(|o| matches!(o, Ok(Some(_)))).count(), 1, "{outcomes:?}");
    }

    #[tokio::test]
    async fn a_live_id_cannot_be_overwritten_but_an_expired_one_is_free() {
        // Ids come from the custodian's random source; this is the vault's own
        // guard should that source ever repeat itself.
        databases!(relay, admin);
        let vault = PostgresVault::new(&relay);
        let deposit = |payload, lifetime| Deposit {
            id: fresh_id(),
            payload,
            retention: Retention::UntilExpiry,
            lifetime,
            revocation: None,
        };
        let first = deposit(payload(), Lifetime::ONE_DAY);
        vault.deposit(&first).await.unwrap();
        let evil = SealedPayload::new(b"attacker".to_vec()).unwrap();
        let overwrite = Deposit { id: first.id, ..deposit(evil.clone(), Lifetime::MAX) };
        assert_eq!(vault.deposit(&overwrite).await, Err(CustodyError::AlreadyExists));
        expire(&admin, "deposits", &first.id).await;
        let reuse = Deposit { id: first.id, ..deposit(evil.clone(), Lifetime::MIN) };
        vault.deposit(&reuse).await.unwrap();
        assert_eq!(vault.open(&first.id).await.unwrap().unwrap().payload, evil);
    }

    #[tokio::test]
    async fn whoever_burns_a_secret_cannot_refill_its_link() {
        databases!(relay, _admin);
        let custodian = custodian(&relay);
        let original =
            custodian.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None).await.unwrap();
        custodian.open(&original.id).await.unwrap();
        let forgery = SealedPayload::new(b"SGY\x01 forged".to_vec()).unwrap();
        let refill = custodian.deposit(forgery, Retention::BurnAfterReading, Lifetime::ONE_DAY, None).await.unwrap();
        assert_ne!(refill.id, original.id);
        assert_eq!(custodian.open(&original.id).await, Err(CustodyError::NotFound));
    }

    #[tokio::test]
    async fn expired_requests_cannot_be_fetched_or_answered() {
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let id = custodian.post_request(recipient_key(), Lifetime::MIN).await.unwrap().id;
        expire(&admin, "requests", &id).await;
        assert_eq!(custodian.fetch_request(&id).await, Err(CustodyError::NotFound));
        let answer = Answer { payload: payload(), retention: Retention::UntilExpiry, lifetime: Lifetime::ONE_HOUR };
        assert_eq!(custodian.answer_request(id, answer).await, Err(CustodyError::NotFound));
    }

    #[tokio::test]
    async fn database_rejects_what_the_domain_would_reject() {
        // Defense in depth: a compromised Worker skipping the domain checks
        // still hits the database's own limits.
        databases!(relay, _admin);
        let id = fresh_id();
        let id = id.as_bytes().as_slice();
        let short_life =
            relay.query_one("select custody.deposit($1, $2, false, 10, null)", &[&id, &b"x".as_slice()]).await;
        assert!(short_life.is_err(), "10-second lifetime accepted");
        let huge = vec![0u8; 73_729];
        let oversized =
            relay.query_one("select custody.deposit($1, $2, false, 300, null)", &[&id, &huge.as_slice()]).await;
        assert!(oversized.is_err(), "oversized payload accepted");
        let bad_id = relay
            .query_one("select custody.deposit($1, $2, false, 300, null)", &[&b"short".as_slice(), &b"x".as_slice()])
            .await;
        assert!(bad_id.is_err(), "5-byte id accepted");
    }

    #[tokio::test]
    async fn the_relay_role_cannot_read_tables() {
        databases!(relay, _admin);
        let error = relay.query("select id from custody.deposits", &[]).await.unwrap_err();
        assert_eq!(error.code(), Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE));
    }
}
