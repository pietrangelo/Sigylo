//! Vault contract tests against a real PostgreSQL with the Sigylo migrations.
//!
//! Run through `bash supabase/tests/run.sh`, which starts a throwaway
//! database and sets the two URLs. The vault connects as `sigylo_relay`
//! (the Worker's role); time travel uses the owner connection.

use std::collections::HashMap;
use std::sync::Mutex;

use custody::{
    Answer, ChunkCount, ChunkIndex, ChunkStore, ClaimDigest, Custodian, CustodyError, Deposit, DropId, IdSource,
    Lifetime, MAX_CHUNK_LEN, ObjectName, RecipientKeyBlob, Request, Retention, RevocationToken, SealedChunk,
    SealedPayload, Vault,
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

/// Stands in for R2: the contract under test is the vault's.
#[derive(Debug, Default)]
struct MemoryStore(Mutex<HashMap<ObjectName, SealedChunk>>);

impl MemoryStore {
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

impl ChunkStore for &MemoryStore {
    async fn put(&self, object: &ObjectName, chunk: &SealedChunk) -> Result<(), CustodyError> {
        self.0.lock().unwrap().insert(*object, chunk.clone());
        Ok(())
    }

    async fn get(&self, object: &ObjectName) -> Result<Option<SealedChunk>, CustodyError> {
        Ok(self.0.lock().unwrap().get(object).cloned())
    }

    async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        let mut stored = self.0.lock().unwrap();
        for object in objects {
            stored.remove(object);
        }
        Ok(())
    }
}

/// One store for the whole test binary, as R2 is one bucket for every relay.
fn store() -> &'static MemoryStore {
    static STORE: std::sync::OnceLock<MemoryStore> = std::sync::OnceLock::new();
    STORE.get_or_init(MemoryStore::default)
}

fn custodian(relay: &Client) -> Custodian<PostgresVault<'_>, &'static MemoryStore, Sha256TokenDigest, RandomIds> {
    Custodian::new(PostgresVault::new(relay), store(), Sha256TokenDigest, RandomIds)
}

fn payload() -> SealedPayload {
    sealed(b"SGY\x01 opaque")
}

/// An envelope-sized payload that starts with `head`.
fn sealed(head: &[u8]) -> SealedPayload {
    let mut bytes = head.to_vec();
    bytes.resize(custody::MIN_PAYLOAD_LEN, 0xA0);
    SealedPayload::new(bytes).unwrap()
}

fn token(n: u8) -> RevocationToken {
    RevocationToken::from_slice(&[n; 32]).unwrap()
}

fn recipient_key() -> RecipientKeyBlob {
    RecipientKeyBlob::new(vec![7; RecipientKeyBlob::LEN]).unwrap()
}

/// What the ceiling charges a deposit row on top of its payload.
const DEPOSIT_ROW: i64 = 192;

/// The one-step `custody.put_chunk` the relay deployed before this one calls.
async fn legacy_put_chunk(client: &Client, id: &DropId, object: &ObjectName, size: i32) -> Result<bool, CustodyError> {
    let put = "select custody.put_chunk($1, 0::smallint, $2, $3)";
    let (id, object) = (id.as_bytes().as_slice(), object.as_bytes().as_slice());
    match client.query_one(put, &[&id, &object, &size]).await {
        Ok(row) => Ok(row.get(0)),
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::DISK_FULL) => Err(CustodyError::StorageFull),
        Err(_) => Err(CustodyError::VaultUnavailable),
    }
}

fn claim(n: usize) -> ClaimDigest {
    ClaimDigest::from_array([n as u8 + 1; 32])
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
    let answer = Answer {
        payload: payload(),
        retention: Retention::BurnAfterReading,
        lifetime: Lifetime::ONE_HOUR,
        chunks: None,
    };
    let answered = custodian.answer_request(receipt.id, answer).await.unwrap();
    assert_eq!(answered.id, receipt.inbox, "the sender learns the inbox, for a file's chunks");
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
    let answer =
        Answer { payload: payload(), retention: Retention::UntilExpiry, lifetime: Lifetime::ONE_HOUR, chunks: None };
    assert_eq!(custodian.answer_request(id, answer).await.unwrap().id, id);
    assert_eq!(custodian.open(&id).await.unwrap().payload, payload());
}

mod adversary {
    use super::*;

    #[tokio::test]
    async fn the_request_link_can_neither_read_nor_burn_the_answer() {
        databases!(relay, _admin);
        let custodian = custodian(&relay);
        let receipt = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap();
        let answer = Answer {
            payload: payload(),
            retention: Retention::BurnAfterReading,
            lifetime: Lifetime::ONE_HOUR,
            chunks: None,
        };
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
        let outcomes = join_all(
            clients.iter().enumerate().map(|(n, c)| async move { PostgresVault::new(c).open(&id, &claim(n)).await }),
        )
        .await;
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
                payload: sealed(&[n as u8 + 1]),
                retention: Retention::UntilExpiry,
                lifetime: Lifetime::ONE_HOUR,
                revocation: None,
                chunks: None,
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
            chunks: None,
        };
        let first = deposit(payload(), Lifetime::ONE_DAY);
        vault.deposit(&first).await.unwrap();
        let evil = sealed(b"attacker");
        let overwrite = Deposit { id: first.id, ..deposit(evil.clone(), Lifetime::MAX) };
        assert_eq!(vault.deposit(&overwrite).await, Err(CustodyError::AlreadyExists));
        expire(&admin, "deposits", &first.id).await;
        let reuse = Deposit { id: first.id, ..deposit(evil.clone(), Lifetime::MIN) };
        vault.deposit(&reuse).await.unwrap();
        assert_eq!(vault.open(&first.id, &claim(0)).await.unwrap().unwrap().payload, evil);
    }

    #[tokio::test]
    async fn whoever_burns_a_secret_cannot_refill_its_link() {
        databases!(relay, _admin);
        let custodian = custodian(&relay);
        let original =
            custodian.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None).await.unwrap();
        custodian.open(&original.id).await.unwrap();
        let forgery = sealed(b"SGY\x01 forged");
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
        let answer = Answer {
            payload: payload(),
            retention: Retention::UntilExpiry,
            lifetime: Lifetime::ONE_HOUR,
            chunks: None,
        };
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
    async fn the_database_refuses_payloads_smaller_than_any_envelope() {
        // Every row costs far more than one byte: a flood of tiny deposits
        // would fill the database while the ceiling saw nothing.
        databases!(relay, _admin);
        let tiny = vec![1u8; custody::MIN_PAYLOAD_LEN - 1];
        let tiny = tiny.as_slice();
        for statement in [
            "select custody.deposit($1, $2, false, 300, null)",
            "select custody.deposit($1, $2, false, 300, null, 0::smallint)",
            "select custody.deposit($1, $2, false, 300, null, 1::smallint)",
        ] {
            let id = fresh_id();
            let refused = relay.query_one(statement, &[&id.as_bytes().as_slice(), &tiny]).await;
            assert!(refused.is_err(), "{statement}");
        }
        let custodian = custodian(&relay);
        let request = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap();
        let answer = "select * from custody.answer_into_inbox($1, $2, false, 300, 0::smallint)";
        assert!(relay.query(answer, &[&request.id.as_bytes().as_slice(), &tiny]).await.is_err());
        assert!(custodian.fetch_request(&request.id).await.is_ok(), "the refused answer used nothing up");
    }

    #[tokio::test]
    async fn many_small_rows_reach_the_ceiling_long_before_their_bytes_would() {
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let row = custody::MIN_PAYLOAD_LEN as i64 + DEPOSIT_ROW;
        with_capacity(&admin, 10 * row, async {
            for _ in 0..10 {
                custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::MIN, None).await.unwrap();
            }
            // Counting bytes alone, six more would have fit.
            let next = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::MIN, None).await;
            assert_eq!(next, Err(CustodyError::StorageFull));
        })
        .await;
    }

    #[tokio::test]
    async fn the_running_count_matches_what_the_tables_hold() {
        // The ceiling reads a counter instead of summing tables under a lock:
        // every way rows come and go must keep it exact.
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let text = custodian.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None).await.unwrap();
        custodian.open(&text.id).await.unwrap();
        let request = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap();
        let answer = Answer {
            payload: payload(),
            retention: Retention::BurnAfterReading,
            lifetime: Lifetime::ONE_HOUR,
            chunks: Some(ChunkCount::new(2).unwrap()),
        };
        let inbox = custodian.answer_request(request.id, answer).await.unwrap().id;
        let full = SealedChunk::new(vec![1; MAX_CHUNK_LEN]).unwrap();
        let last = SealedChunk::new(vec![2; custody::MIN_CHUNK_LEN]).unwrap();
        custodian.put_chunk(&inbox, ChunkIndex::new(0).unwrap(), full).await.unwrap();
        custodian.put_chunk(&inbox, ChunkIndex::new(1).unwrap(), last).await.unwrap();
        let claim = custodian.open(&inbox).await.unwrap().claim;
        custodian.open_chunk(&inbox, ChunkIndex::new(0).unwrap(), claim.as_ref()).await.unwrap();
        let revoked = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(9))).await;
        custodian.revoke(&revoked.unwrap().id, &token(9)).await.unwrap();
        let expired = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::MIN, None).await.unwrap();
        expire(&admin, "deposits", &expired.id).await;
        custodian.purge_expired().await.unwrap();
        let counted = admin
            .query_one(
                "select (select used_bytes from custody.usage) = (
                            coalesce((select sum(octet_length(payload) + 192) from custody.deposits), 0)
                          + coalesce((select sum(octet_length(recipient_key) + 128) from custody.requests), 0)
                          + 192 * (select count(*) from custody.chunks) + 128 * (select count(*) from custody.garbage)),
                        (select chunk_bytes from custody.usage) = (
                            coalesce((select sum(size) from custody.chunks), 0)
                          + coalesce((select sum(size) from custody.garbage), 0)),
                        (select count(*) from custody.usage)",
                &[],
            )
            .await
            .unwrap();
        assert!(counted.get::<_, bool>(0), "used_bytes drifted");
        assert!(counted.get::<_, bool>(1), "chunk_bytes drifted");
        assert_eq!(counted.get::<_, i64>(2), 1, "one counter row");
    }

    /// Runs `body` with the custody capacity set to what is stored now plus
    /// `headroom` bytes, then puts the real capacity back.
    pub(crate) async fn with_capacity<F: std::future::Future<Output = ()>>(admin: &Client, headroom: i64, body: F) {
        let original: String = admin
            .query_one("select pg_get_functiondef('custody.capacity_bytes()'::regprocedure)", &[])
            .await
            .unwrap()
            .get(0);
        // Expired rows left by other tests would otherwise be purged mid-test and free room.
        admin.execute("select custody.purge_expired()", &[]).await.unwrap();
        let used: i64 = admin.query_one("select custody.used_bytes()", &[]).await.unwrap().get(0);
        let tight = format!(
            "create or replace function custody.capacity_bytes() returns bigint language plpgsql stable \
             set search_path = '' as $$ begin return {}; end $$",
            used + headroom
        );
        admin.batch_execute(&tight).await.unwrap();
        body.await;
        admin.batch_execute(&original).await.unwrap();
    }

    #[tokio::test]
    async fn a_full_custody_refuses_new_seals_but_still_opens_old_ones() {
        // The free database is 500 MB: past that it turns read-only and nothing
        // works. A flood of deposits must hit our own ceiling first.
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let old = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None).await.unwrap().id;
        let request = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap();
        with_capacity(&admin, 0, async {
            let full = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None).await;
            assert_eq!(full, Err(CustodyError::StorageFull));
            assert_eq!(
                custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await,
                Err(CustodyError::StorageFull)
            );
            // Answering frees the request's key, so the answer must be larger than it to overflow.
            let large = SealedPayload::new(vec![1; 4096]).unwrap();
            let answer = Answer {
                payload: large,
                retention: Retention::UntilExpiry,
                lifetime: Lifetime::ONE_HOUR,
                chunks: None,
            };
            assert_eq!(custodian.answer_request(request.id, answer).await, Err(CustodyError::StorageFull));
            // A file's manifest is a deposit like any other.
            let two = ChunkCount::new(2).unwrap();
            let file = custodian.deposit_file(payload(), two, Retention::UntilExpiry, Lifetime::ONE_DAY, None).await;
            assert_eq!(file, Err(CustodyError::StorageFull));
            assert_eq!(custodian.open(&old).await.unwrap().payload, payload());
        })
        .await;
        // The refused answer left the request untouched.
        assert!(custodian.fetch_request(&request.id).await.is_ok());
    }

    #[tokio::test]
    async fn room_comes_back_when_a_secret_is_burned_or_expires() {
        databases!(relay, admin);
        let custodian = custodian(&relay);
        // A deposit costs its payload and the fixed cost of its row.
        let size = payload().as_bytes().len() as i64 + DEPOSIT_ROW;
        with_capacity(&admin, size, async {
            let first = custodian.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None).await;
            let first = first.unwrap().id;
            let second = custodian.deposit(payload(), Retention::BurnAfterReading, Lifetime::ONE_DAY, None).await;
            assert_eq!(second, Err(CustodyError::StorageFull));
            custodian.open(&first).await.unwrap();
            let third = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None).await.unwrap();
            // An expired row still on disk is cleared on the spot, not after the next purge.
            expire(&admin, "deposits", &third.id).await;
            assert!(custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None).await.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn the_relay_role_cannot_read_tables() {
        databases!(relay, _admin);
        let error = relay.query("select id from custody.deposits", &[]).await.unwrap_err();
        assert_eq!(error.code(), Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE));
    }
}

mod files {
    use super::*;

    fn count(n: u16) -> ChunkCount {
        ChunkCount::new(n).unwrap()
    }

    fn at(i: u16) -> ChunkIndex {
        ChunkIndex::new(i).unwrap()
    }

    fn chunk(i: u16) -> SealedChunk {
        // Every chunk but a file's last is full; a full one fits the end too.
        SealedChunk::new(vec![i as u8 + 1; MAX_CHUNK_LEN]).unwrap()
    }

    async fn file(relay: &Client, n: u16, retention: Retention) -> DropId {
        let custodian = custodian(relay);
        let id = custodian.deposit_file(payload(), count(n), retention, Lifetime::ONE_DAY, Some(&token(5))).await;
        let id = id.unwrap().id;
        for i in 0..n {
            custodian.put_chunk(&id, at(i), chunk(i)).await.unwrap();
        }
        id
    }

    fn object(n: u8) -> ObjectName {
        RandomIds
            .fresh_object()
            .map(|o| {
                let mut bytes = *o.as_bytes();
                bytes[0] = n;
                ObjectName::from_array(bytes)
            })
            .unwrap()
    }

    async fn objects_of(admin: &Client, id: &DropId) -> Vec<ObjectName> {
        let rows = admin
            .query("select object from custody.chunks where deposit_id = $1", &[&id.as_bytes().as_slice()])
            .await
            .unwrap();
        rows.iter().map(|r| ObjectName::from_slice(r.get::<_, &[u8]>(0)).unwrap()).collect()
    }

    async fn in_garbage(admin: &Client, objects: &[ObjectName]) -> usize {
        let names: Vec<&[u8]> = objects.iter().map(|o| o.as_bytes().as_slice()).collect();
        let row = admin.query_one("select count(*) from custody.garbage where object = any($1)", &[&names]).await;
        row.unwrap().get::<_, i64>(0) as usize
    }

    async fn rows(admin: &Client, table: &str, id: &DropId) -> i64 {
        let column = if table == "chunks" { "deposit_id" } else { "id" };
        let sql = format!("select count(*) from custody.{table} where {column} = $1");
        admin.query_one(&sql, &[&id.as_bytes().as_slice()]).await.unwrap().get(0)
    }

    #[tokio::test]
    async fn burn_after_reading_file_goes_chunk_by_chunk_to_whoever_opened_it() {
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let id = file(&relay, 3, Retention::BurnAfterReading).await;
        let opened = custodian.open(&id).await.unwrap();
        assert_eq!((opened.payload, opened.burned, opened.chunks), (payload(), true, Some(count(3))));
        let claim = opened.claim.unwrap();
        let objects = objects_of(&admin, &id).await;
        for i in 0..3 {
            assert_eq!(custodian.open_chunk(&id, at(i), Some(&claim)).await, Ok(chunk(i)));
            assert_eq!(custodian.open_chunk(&id, at(i), Some(&claim)).await, Err(CustodyError::NotFound));
        }
        assert_eq!((rows(&admin, "deposits", &id).await, rows(&admin, "chunks", &id).await), (0, 0));
        // Each burned chunk left the store as it went, and was then forgotten.
        assert_eq!(in_garbage(&admin, &objects).await, 0);
        for object in &objects {
            assert_eq!(store().get(object).await, Ok(None));
        }
    }

    #[tokio::test]
    async fn until_expiry_file_is_readable_until_it_expires() {
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let id = file(&relay, 2, Retention::UntilExpiry).await;
        for _ in 0..2 {
            let opened = custodian.open(&id).await.unwrap();
            assert_eq!((opened.burned, opened.chunks, opened.claim), (false, Some(count(2)), None));
            assert_eq!(custodian.open_chunk(&id, at(1), None).await, Ok(chunk(1)));
        }
        expire(&admin, "deposits", &id).await;
        assert_eq!(custodian.open_chunk(&id, at(0), None).await, Err(CustodyError::NotFound));
        custodian.purge_expired().await.unwrap();
        assert_eq!(rows(&admin, "chunks", &id).await, 0, "purge takes the chunks along");
    }

    #[tokio::test]
    async fn largest_chunk_and_file_answers_fit() {
        databases!(relay, _admin);
        let custodian = custodian(&relay);
        let request = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap();
        let answer = Answer {
            payload: payload(),
            retention: Retention::UntilExpiry,
            lifetime: Lifetime::ONE_HOUR,
            chunks: Some(count(custody::MAX_CHUNKS)),
        };
        let inbox = custodian.answer_request(request.id, answer).await.unwrap().id;
        assert_eq!(inbox, request.inbox);
        let big = SealedChunk::new(vec![0xAB; MAX_CHUNK_LEN]).unwrap();
        for i in 0..custody::MAX_CHUNKS {
            custodian.put_chunk(&inbox, at(i), big.clone()).await.unwrap();
        }
        assert_eq!(custodian.open(&inbox).await.unwrap().chunks, Some(count(custody::MAX_CHUNKS)));
        assert_eq!(custodian.open_chunk(&inbox, at(9), None).await, Ok(big));
    }

    #[tokio::test]
    async fn the_request_link_cannot_push_chunks_into_a_file_answer() {
        // adversary: whoever saw the request link races the sender to chunk 0.
        databases!(relay, _admin);
        let custodian = custodian(&relay);
        let request = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap();
        let answer = Answer {
            payload: payload(),
            retention: Retention::BurnAfterReading,
            lifetime: Lifetime::ONE_HOUR,
            chunks: Some(count(1)),
        };
        let inbox = custodian.answer_request(request.id, answer).await.unwrap().id;
        let junk = SealedChunk::new(vec![0xEE; custody::MIN_CHUNK_LEN]).unwrap();
        assert_eq!(custodian.put_chunk(&request.id, at(0), junk).await, Err(CustodyError::NotFound));
        custodian.put_chunk(&inbox, at(0), chunk(0)).await.unwrap();
        let opened = custodian.open(&request.inbox).await.unwrap();
        assert_eq!(custodian.open_chunk(&request.inbox, at(0), opened.claim.as_ref()).await, Ok(chunk(0)));
    }

    #[tokio::test]
    async fn revoking_a_file_deletes_its_chunks() {
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let id = file(&relay, 2, Retention::UntilExpiry).await;
        let objects = objects_of(&admin, &id).await;
        custodian.revoke(&id, &token(5)).await.unwrap();
        assert_eq!(rows(&admin, "chunks", &id).await, 0);
        // Out of the store at once, not with the next collection.
        assert_eq!(in_garbage(&admin, &objects).await, 0);
        for object in &objects {
            assert_eq!(store().get(object).await, Ok(None));
        }
    }

    #[tokio::test]
    async fn revocation_names_the_objects_of_the_chunks_it_took() {
        databases!(relay, admin);
        let id = file(&relay, 2, Retention::UntilExpiry).await;
        let mut objects = objects_of(&admin, &id).await;
        let digest = custody::TokenDigest::digest(&Sha256TokenDigest, &token(5));
        let vault = PostgresVault::new(&relay);
        let mut named = vault.revoke(&id, &digest).await.unwrap().unwrap();
        objects.sort_by_key(|o| *o.as_bytes());
        named.sort_by_key(|o| *o.as_bytes());
        assert_eq!(named, objects);
        assert_eq!(in_garbage(&admin, &objects).await, 2, "on record until the store deleted them");
        assert_eq!(vault.revoke(&id, &digest).await, Ok(None));
        let custodian = custodian(&relay);
        let text = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, Some(&token(6))).await;
        let text = text.unwrap().id;
        let digest = custody::TokenDigest::digest(&Sha256TokenDigest, &token(6));
        assert_eq!(vault.revoke(&text, &digest).await, Ok(Some(vec![])));
        vault.forget_garbage(&objects).await.unwrap();
    }

    #[tokio::test]
    async fn the_database_keeps_object_names_and_sizes_never_chunk_bytes() {
        databases!(relay, admin);
        let id = file(&relay, 2, Retention::UntilExpiry).await;
        let rows = admin
            .query("select object, size from custody.chunks where deposit_id = $1", &[&id.as_bytes().as_slice()])
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(row.get::<_, &[u8]>(0).len(), ObjectName::LEN);
            assert_eq!(row.get::<_, i32>(1), MAX_CHUNK_LEN as i32);
        }
    }

    #[tokio::test]
    async fn garbage_is_collected_from_the_store_and_then_forgotten() {
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let id = file(&relay, 3, Retention::UntilExpiry).await;
        let objects = objects_of(&admin, &id).await;
        expire(&admin, "deposits", &id).await;
        custodian.purge_expired().await.unwrap();
        assert_eq!(in_garbage(&admin, &objects).await, 3, "expiry hands the objects over too");
        custodian.collect_garbage(|| true).await.unwrap();
        assert_eq!(in_garbage(&admin, &objects).await, 3, "not before their grace time");
        make_due(&admin, &objects).await;
        custodian.collect_garbage(|| true).await.unwrap();
        assert_eq!(in_garbage(&admin, &objects).await, 0);
        for object in &objects {
            assert_eq!(store().get(object).await, Ok(None));
        }
    }

    /// Time travel: the grace time of these garbage objects is over.
    async fn make_due(admin: &Client, objects: &[ObjectName]) {
        let names: Vec<&[u8]> = objects.iter().map(|o| o.as_bytes().as_slice()).collect();
        let sql = "update custody.garbage set not_before = now() where object = any($1)";
        admin.execute(sql, &[&names]).await.unwrap();
    }

    #[tokio::test]
    async fn garbage_is_handed_out_in_bounded_batches() {
        databases!(relay, admin);
        admin
            .batch_execute(
                "insert into custody.garbage (object, size, not_before)
                 select decode('ee' || lpad(to_hex(n), 30, '0'), 'hex'), 272, now() from generate_series(1, 1200) n",
            )
            .await
            .unwrap();
        let vault = PostgresVault::new(&relay);
        let batch = vault.garbage(5000).await.unwrap();
        assert_eq!(batch.len(), 1000);
        vault.forget_garbage(&batch).await.unwrap();
        assert_eq!(vault.garbage(0).await.unwrap().len(), 0);
        admin.batch_execute("delete from custody.garbage where substring(object for 1) = '\\xee'").await.unwrap();
    }

    #[tokio::test]
    async fn collection_goes_on_batch_after_batch() {
        databases!(relay, admin);
        admin
            .batch_execute(
                "insert into custody.garbage (object, size, not_before)
                 select decode('ef' || lpad(to_hex(n), 30, '0'), 'hex'), 272, now() from generate_series(1, 2500) n",
            )
            .await
            .unwrap();
        let collected = custodian(&relay).collect_garbage(|| true).await.unwrap();
        let left: i64 = admin
            .query_one("select count(*) from custody.garbage where substring(object for 1) = '\\xef'", &[])
            .await
            .unwrap()
            .get(0);
        assert!(collected >= 2500 && left == 0, "{collected} collected, {left} left");
    }

    mod adversary {
        use super::*;

        #[tokio::test]
        async fn an_incomplete_file_cannot_be_opened() {
            databases!(relay, _admin);
            let custodian = custodian(&relay);
            let id = custodian.deposit_file(payload(), count(2), Retention::UntilExpiry, Lifetime::ONE_DAY, None).await;
            let id = id.unwrap().id;
            custodian.put_chunk(&id, at(1), chunk(1)).await.unwrap();
            assert_eq!(custodian.open(&id).await, Err(CustodyError::NotFound));
            assert_eq!(custodian.open_chunk(&id, at(1), None).await, Err(CustodyError::NotFound));
        }

        #[tokio::test]
        async fn chunks_are_written_once_inside_the_count_and_never_after_opening() {
            databases!(relay, _admin);
            let custodian = custodian(&relay);
            let id = custodian.deposit_file(payload(), count(2), Retention::BurnAfterReading, Lifetime::ONE_DAY, None);
            let id = id.await.unwrap().id;
            custodian.put_chunk(&id, at(0), chunk(0)).await.unwrap();
            assert_eq!(custodian.put_chunk(&id, at(0), chunk(7)).await, Err(CustodyError::NotFound));
            assert_eq!(custodian.put_chunk(&id, at(2), chunk(7)).await, Err(CustodyError::NotFound));
            custodian.put_chunk(&id, at(1), chunk(1)).await.unwrap();
            custodian.open(&id).await.unwrap();
            assert_eq!(custodian.put_chunk(&id, at(1), chunk(7)).await, Err(CustodyError::NotFound));
            let text = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None).await.unwrap();
            assert_eq!(custodian.put_chunk(&text.id, at(0), chunk(0)).await, Err(CustodyError::NotFound));
        }

        #[tokio::test]
        async fn concurrent_opens_of_a_burn_after_reading_file_claim_it_once() {
            databases!(relay, _admin);
            let id = file(&relay, 1, Retention::BurnAfterReading).await;
            let mut clients = Vec::new();
            for _ in 0..16 {
                clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
            }
            let outcomes = join_all(
                clients
                    .iter()
                    .enumerate()
                    .map(|(n, c)| async move { PostgresVault::new(c).open(&id, &claim(n)).await }),
            )
            .await;
            let winners: Vec<usize> = (0..16).filter(|&n| matches!(outcomes[n], Ok(Some(_)))).collect();
            assert_eq!(winners.len(), 1, "{outcomes:?}");
            // Only the winner's claim releases the chunk.
            let vault = PostgresVault::new(&relay);
            let loser = (winners[0] + 1) % 16;
            assert_eq!(vault.open_chunk(&id, at(0), Some(&claim(loser))).await, Ok(None));
            let found = vault.open_chunk(&id, at(0), Some(&claim(winners[0]))).await.unwrap().unwrap();
            assert!(found.burns);
            assert!(!vault.burn_chunk(&id, at(0), &claim(loser)).await.unwrap(), "only the claim burns");
        }

        #[tokio::test]
        async fn concurrent_burns_of_one_chunk_count_once() {
            // Only the caller whose burn counted hands the chunk out.
            databases!(relay, admin);
            let id = file(&relay, 2, Retention::BurnAfterReading).await;
            PostgresVault::new(&relay).open(&id, &claim(0)).await.unwrap().unwrap();
            let mut clients = Vec::new();
            for _ in 0..16 {
                clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
            }
            let outcomes = join_all(clients.iter().enumerate().map(|(n, c)| async move {
                PostgresVault::new(c).burn_chunk(&id, at((n % 2) as u16), &claim(0)).await
            }))
            .await;
            assert_eq!(outcomes.iter().filter(|o| matches!(o, Ok(true))).count(), 2, "{outcomes:?}");
            assert!(outcomes.iter().all(|o| o.is_ok()));
            assert_eq!(rows(&admin, "deposits", &id).await, 0, "the last chunk takes the deposit along");
        }

        #[tokio::test]
        async fn finding_a_chunk_burns_nothing_and_its_object_waits_after_the_burn() {
            // An R2 error between the burn and the read would lose the chunk,
            // and a collector running in between would delete it unread.
            databases!(relay, admin);
            let id = file(&relay, 1, Retention::BurnAfterReading).await;
            let vault = PostgresVault::new(&relay);
            vault.open(&id, &claim(0)).await.unwrap().unwrap();
            let first = vault.open_chunk(&id, at(0), Some(&claim(0))).await.unwrap().unwrap();
            let again = vault.open_chunk(&id, at(0), Some(&claim(0))).await.unwrap().unwrap();
            assert_eq!((first, rows(&admin, "chunks", &id).await), (again, 1));
            assert!(vault.burn_chunk(&id, at(0), &claim(0)).await.unwrap());
            assert_eq!(in_garbage(&admin, &[first.object]).await, 1);
            assert!(!vault.garbage(1000).await.unwrap().contains(&first.object), "due only after its grace time");
            let due: bool = admin
                .query_one(
                    "select not_before > now() + interval '4 minutes' from custody.garbage where object = $1",
                    &[&first.object.as_bytes().as_slice()],
                )
                .await
                .unwrap()
                .get(0);
            assert!(due);
            vault.forget_garbage(&[first.object]).await.unwrap();
        }

        #[tokio::test]
        async fn the_old_one_step_chunk_read_still_works_and_waits_too() {
            // The relay live while the migration runs burns in open_chunk.
            databases!(relay, _admin);
            let id = file(&relay, 1, Retention::BurnAfterReading).await;
            PostgresVault::new(&relay).open(&id, &claim(0)).await.unwrap().unwrap();
            let old = "select object, burned from custody.open_chunk($1, 0::smallint, $2)";
            let claimed = claim(0);
            let args: [&(dyn tokio_postgres::types::ToSql + Sync); 2] =
                [&id.as_bytes().as_slice(), &claimed.as_bytes().as_slice()];
            let row = relay.query_one(old, &args).await.unwrap();
            assert!(row.get::<_, bool>(1));
            assert!(relay.query(old, &args).await.unwrap().is_empty());
            let object = ObjectName::from_slice(row.get(0)).unwrap();
            assert!(!PostgresVault::new(&relay).garbage(1000).await.unwrap().contains(&object));
            PostgresVault::new(&relay).forget_garbage(&[object]).await.unwrap();
        }

        #[tokio::test]
        async fn a_claim_lapses_within_an_hour() {
            databases!(relay, admin);
            let id = file(&relay, 1, Retention::BurnAfterReading).await;
            custodian(&relay).open(&id).await.unwrap();
            let within: bool = admin
                .query_one(
                    "select expires_at <= now() + interval '1 hour' from custody.deposits where id = $1",
                    &[&id.as_bytes().as_slice()],
                )
                .await
                .unwrap()
                .get(0);
            assert!(within);
        }

        #[tokio::test]
        async fn an_unfinished_upload_holds_its_room_for_ten_minutes_only() {
            // Otherwise anyone could fill the chunk budget with files they never
            // finish, and keep it full for the longest lifetime.
            databases!(relay, admin);
            let custodian = custodian(&relay);
            let receipt = custodian.deposit_file(payload(), count(2), Retention::UntilExpiry, Lifetime::ONE_DAY, None);
            let receipt = receipt.await.unwrap();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            assert!((receipt.expires_at.0 - now - 86_400).abs() < 60, "the receipt promises the chosen lifetime");
            let minutes_left = async |id: &DropId| -> f64 {
                admin
                    .query_one(
                        "select extract(epoch from expires_at - now())::float8 / 60 from custody.deposits where id = $1",
                        &[&id.as_bytes().as_slice()],
                    )
                    .await
                    .unwrap()
                    .get(0)
            };
            assert!(minutes_left(&receipt.id).await <= 10.0);
            custodian.put_chunk(&receipt.id, at(0), chunk(0)).await.unwrap();
            assert!(minutes_left(&receipt.id).await <= 10.0);
            custodian.put_chunk(&receipt.id, at(1), chunk(1)).await.unwrap();
            assert!(minutes_left(&receipt.id).await > 23.0 * 60.0, "the last chunk restores the chosen lifetime");
            assert_eq!(custodian.open(&receipt.id).await.unwrap().chunks, Some(count(2)));
        }

        /// Fills the 5 GiB chunk budget, whatever other tests left, up to
        /// `room` bytes short of it, with objects waiting in the garbage (not
        /// due for a day): what is still in R2 counts until it is deleted.
        async fn fill_chunk_budget(admin: &Client, room: i64) {
            let sql = format!(
                "with need as (
                     select 5::bigint * 1024 * 1024 * 1024 - {room} - (select chunk_bytes from custody.usage) as bytes
                 )
                 insert into custody.garbage (object, size, not_before)
                 select decode('dd' || lpad(to_hex(n), 30, '0'), 'hex'),
                        least(1048592, need.bytes - (n - 1) * 1048592::bigint), now() + interval '1 day'
                 from need, generate_series(1, (select ceil(bytes / 1048592.0)::int from need)) n"
            );
            admin.batch_execute(&sql).await.unwrap();
        }

        async fn drain_chunk_budget(admin: &Client) {
            let sql = "delete from custody.garbage where substring(object for 1) in ('\\xdd', '\\xcc')";
            admin.batch_execute(sql).await.unwrap();
        }

        #[tokio::test]
        async fn concurrent_chunks_never_overshoot_the_ceiling() {
            databases!(relay, admin);
            fill_chunk_budget(&admin, MAX_CHUNK_LEN as i64).await;
            let custodian = custodian(&relay);
            let mut ids = Vec::new();
            for _ in 0..16 {
                let receipt =
                    custodian.deposit_file(payload(), count(1), Retention::UntilExpiry, Lifetime::ONE_DAY, None);
                ids.push(receipt.await.unwrap().id);
            }
            let mut clients = Vec::new();
            for _ in 0..16 {
                clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
            }
            let outcomes = join_all(clients.iter().zip(&ids).enumerate().map(|(n, (c, id))| async move {
                let vault = PostgresVault::new(c);
                // Half through the new reservation, half through the deployed relay's one step.
                if n % 2 == 0 {
                    vault.reserve_chunk(id, at(0), &object(0xCC), MAX_CHUNK_LEN as u32).await
                } else {
                    legacy_put_chunk(c, id, &object(0xCC), MAX_CHUNK_LEN as i32).await
                }
            }))
            .await;
            drain_chunk_budget(&admin).await;
            admin.batch_execute("delete from custody.chunks where substring(object for 1) = '\\xcc'").await.unwrap();
            drain_chunk_budget(&admin).await;
            assert_eq!(outcomes.iter().filter(|o| matches!(o, Ok(true))).count(), 1, "{outcomes:?}");
            assert!(outcomes.iter().all(|o| matches!(o, Ok(true) | Err(CustodyError::StorageFull))), "{outcomes:?}");
        }

        #[tokio::test]
        async fn objects_waiting_in_the_garbage_count_against_the_chunk_budget() {
            // Otherwise uploading and revoking in a loop grows R2 past the
            // budget faster than the collector empties it.
            databases!(relay, admin);
            let custodian = custodian(&relay);
            let id = file(&relay, 2, Retention::UntilExpiry).await;
            fill_chunk_budget(&admin, 0).await;
            let other = custodian.deposit_file(payload(), count(1), Retention::UntilExpiry, Lifetime::ONE_DAY, None);
            let other = other.await.unwrap().id;
            let small = SealedChunk::new(vec![1; custody::MIN_CHUNK_LEN]).unwrap();
            assert_eq!(custodian.put_chunk(&other, at(0), small.clone()).await, Err(CustodyError::StorageFull));
            // Revoking moves the chunks to the garbage: the room is not free yet...
            let objects = objects_of(&admin, &id).await;
            let digest = custody::TokenDigest::digest(&Sha256TokenDigest, &token(5));
            PostgresVault::new(&relay).revoke(&id, &digest).await.unwrap().unwrap();
            assert_eq!(custodian.put_chunk(&other, at(0), small.clone()).await, Err(CustodyError::StorageFull));
            // ...until the store has deleted them.
            store().delete(&objects).await.unwrap();
            PostgresVault::new(&relay).forget_garbage(&objects).await.unwrap();
            custodian.put_chunk(&other, at(0), small).await.unwrap();
            drain_chunk_budget(&admin).await;
        }

        #[tokio::test]
        async fn a_chunk_already_in_is_a_refusal_whether_or_not_the_file_was_opened() {
            // A unique violation (409) before opening and a 404 after would let
            // anyone with the link watch for the recipient without burning anything.
            databases!(relay, admin);
            let custodian = custodian(&relay);
            let id = file(&relay, 1, Retention::BurnAfterReading).await;
            let probe = async || {
                let old = legacy_put_chunk(&relay, &id, &object(0xCB), MAX_CHUNK_LEN as i32).await;
                (custodian.put_chunk(&id, at(0), chunk(9)).await, old)
            };
            let before = store().len();
            assert_eq!(probe().await, (Err(CustodyError::NotFound), Ok(false)));
            custodian.open(&id).await.unwrap();
            assert_eq!(probe().await, (Err(CustodyError::NotFound), Ok(false)));
            assert_eq!(store().len(), before, "no probe wrote to the store");
            assert_eq!(rows(&admin, "chunks", &id).await, 1);
        }

        #[tokio::test]
        async fn a_chunk_nobody_takes_is_refused_before_anything_is_written() {
            databases!(relay, admin);
            let custodian = custodian(&relay);
            let unknown = fresh_id();
            let text = custodian.deposit(payload(), Retention::UntilExpiry, Lifetime::ONE_DAY, None).await.unwrap().id;
            let two = custodian.deposit_file(payload(), count(2), Retention::UntilExpiry, Lifetime::ONE_DAY, None);
            let two = two.await.unwrap().id;
            let short = SealedChunk::new(vec![1; custody::MIN_CHUNK_LEN]).unwrap();
            let garbage_before: i64 =
                admin.query_one("select count(*) from custody.garbage", &[]).await.unwrap().get(0);
            let before = store().len();
            for (id, index, chunk) in [(unknown, 0, chunk(0)), (text, 0, chunk(0)), (two, 2, chunk(0)), (two, 0, short)]
            {
                assert_eq!(custodian.put_chunk(&id, at(index), chunk).await, Err(CustodyError::NotFound));
            }
            let garbage_after: i64 = admin.query_one("select count(*) from custody.garbage", &[]).await.unwrap().get(0);
            assert_eq!((store().len(), garbage_after), (before, garbage_before));
        }

        #[tokio::test]
        async fn a_reserved_object_is_on_record_before_the_store_has_it() {
            // Whatever happens after the reservation (store error, cancelled
            // Worker, lost connection), the object is collected in the end.
            databases!(relay, admin);
            let custodian = custodian(&relay);
            let id = custodian.deposit_file(payload(), count(1), Retention::UntilExpiry, Lifetime::ONE_DAY, None).await;
            let id = id.unwrap().id;
            let vault = PostgresVault::new(&relay);
            let name = object(0xCA);
            let len = custody::MIN_CHUNK_LEN as u32;
            assert!(vault.reserve_chunk(&id, at(0), &name, len).await.unwrap());
            assert_eq!(in_garbage(&admin, &[name]).await, 1);
            assert!(!vault.garbage(1000).await.unwrap().contains(&name), "the upload may still be on its way");
            // Late: by now its object could be on its way out of the store.
            let sql = "update custody.garbage set not_before = now() + interval '9 minutes' where object = $1";
            admin.execute(sql, &[&name.as_bytes().as_slice()]).await.unwrap();
            assert!(!vault.put_chunk(&id, at(0), &name, len).await.unwrap());
            assert_eq!(rows(&admin, "chunks", &id).await, 0);
            // A name that was never reserved is not recorded either.
            assert!(!vault.put_chunk(&id, at(0), &object(0xC9), len).await.unwrap());
            // A fresh reservation is recorded, and leaves the garbage.
            let fresh = object(0xCA);
            assert!(vault.reserve_chunk(&id, at(0), &fresh, len).await.unwrap());
            assert!(vault.put_chunk(&id, at(0), &fresh, len).await.unwrap());
            assert_eq!(in_garbage(&admin, &[fresh]).await, 0);
            vault.forget_garbage(&[name]).await.unwrap();
        }

        #[tokio::test]
        async fn the_old_open_function_never_burns_a_file() {
            // The relay live while the migration runs only knows open(bytea).
            databases!(relay, admin);
            let id = file(&relay, 1, Retention::BurnAfterReading).await;
            let old = relay.query("select * from custody.open($1)", &[&id.as_bytes().as_slice()]).await.unwrap();
            assert!(old.is_empty());
            assert_eq!(rows(&admin, "chunks", &id).await, 1);
            assert!(custodian(&relay).open(&id).await.unwrap().claim.is_some());
        }

        #[tokio::test]
        async fn chunk_storage_has_a_ceiling() {
            databases!(relay, admin);
            fill_chunk_budget(&admin, 0).await;
            let custodian = custodian(&relay);
            let id = custodian.deposit_file(payload(), count(1), Retention::UntilExpiry, Lifetime::ONE_DAY, None);
            let id = id.await.unwrap().id;
            let big = SealedChunk::new(vec![1; MAX_CHUNK_LEN]).unwrap();
            let before = store().len();
            let outcome = custodian.put_chunk(&id, at(0), big).await;
            let after = store().len();
            drain_chunk_budget(&admin).await;
            assert_eq!(outcome, Err(CustodyError::StorageFull));
            assert_eq!(after, before, "a refused chunk never reaches the store");
        }

        #[tokio::test]
        async fn many_small_chunk_rows_reach_the_ceiling() {
            // A chunk row costs the database the same whatever its object
            // holds: the ceiling counts it.
            databases!(relay, admin);
            let custodian = custodian(&relay);
            let mut ids = Vec::new();
            for _ in 0..3 {
                let id = custodian.deposit_file(payload(), count(1), Retention::UntilExpiry, Lifetime::ONE_DAY, None);
                ids.push(id.await.unwrap().id);
            }
            let small = SealedChunk::new(vec![1; custody::MIN_CHUNK_LEN]).unwrap();
            // Room for two chunk rows (192 B each, their objects in R2), not three.
            crate::adversary::with_capacity(&admin, 2 * 192 + 100, async {
                custodian.put_chunk(&ids[0], at(0), small.clone()).await.unwrap();
                custodian.put_chunk(&ids[1], at(0), small.clone()).await.unwrap();
                assert_eq!(custodian.put_chunk(&ids[2], at(0), small.clone()).await, Err(CustodyError::StorageFull));
            })
            .await;
        }

        #[tokio::test]
        async fn database_rejects_chunks_the_domain_would_reject() {
            databases!(relay, _admin);
            let id = fresh_id();
            let id = id.as_bytes().as_slice();
            let manifest = payload();
            let manifest = manifest.as_bytes();
            let too_many = relay
                .query_one("select custody.deposit($1, $2, false, 300, null, 11::smallint)", &[&id, &manifest])
                .await;
            assert!(too_many.is_err(), "11 chunks accepted");
            relay
                .query_one("select custody.deposit($1, $2, false, 300, null, 10::smallint)", &[&id, &manifest])
                .await
                .unwrap();
            let name = object(1);
            let name = name.as_bytes().as_slice();
            let full = MAX_CHUNK_LEN as i32;
            for put in [
                "select custody.put_chunk($1, $2::smallint, $3, $4)",
                "select custody.reserve_chunk($1, $2::smallint, $3, $4)",
            ] {
                let oversized = relay.query_one(put, &[&id, &0i16, &name, &(full + 1)]).await;
                assert!(!oversized.unwrap().get::<_, bool>(0), "oversized chunk accepted: {put}");
                let past = relay.query_one(put, &[&id, &10i16, &name, &full]).await;
                assert!(!past.unwrap().get::<_, bool>(0), "index 10 accepted: {put}");
                // Only what a sealer makes, and short only at the end.
                for (index, size) in [(0i16, 1i32), (9, 1), (9, 271), (9, 300), (9, 4096), (0, 272), (8, 4112)] {
                    let odd = relay.query_one(put, &[&id, &index, &name, &size]).await;
                    assert!(!odd.unwrap().get::<_, bool>(0), "chunk {index} of {size} B accepted: {put}");
                }
            }
            let put = "select custody.put_chunk($1, $2::smallint, $3, $4)";
            let short_name = relay.query_one(put, &[&id, &0i16, &&name[..15], &full]).await;
            assert!(short_name.is_err(), "malformed object name accepted");
            assert!(relay.query_one(put, &[&id, &0i16, &name, &full]).await.unwrap().get::<_, bool>(0));
            let reused = relay.query_one(put, &[&id, &1i16, &name, &full]).await;
            assert!(reused.is_err(), "one object recorded for two chunks");
            let last = object(2);
            let last = relay.query_one(put, &[&id, &9i16, &last.as_bytes().as_slice(), &272i32]).await;
            assert!(last.unwrap().get::<_, bool>(0), "a short last chunk is what a sealer makes");
        }
    }
}
