//! Vault contract tests against a real PostgreSQL with the Sigylo migrations.
//!
//! Run through `bash supabase/tests/run.sh`, which starts a throwaway
//! database and sets the two URLs. The vault connects as `sigylo_relay`
//! (the Worker's role); time travel uses the owner connection.

use custody::{
    Answer, ChunkCount, ChunkIndex, ClaimDigest, Custodian, CustodyError, Deposit, DropId, IdSource, Lifetime,
    MAX_CHUNK_LEN, RecipientKeyBlob, Request, Retention, RevocationToken, SealedChunk, SealedPayload, Vault,
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
async fn request_is_answered_under_its_own_id() {
    databases!(relay, _admin);
    let custodian = custodian(&relay);
    let id = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap().id;
    assert_eq!(custodian.fetch_request(&id).await.unwrap().recipient_key, recipient_key());
    let answer = Answer {
        payload: payload(),
        retention: Retention::BurnAfterReading,
        lifetime: Lifetime::ONE_HOUR,
        chunks: None,
    };
    custodian.answer_request(id, answer).await.unwrap();
    assert_eq!(custodian.fetch_request(&id).await, Err(CustodyError::NotFound));
    assert!(custodian.open(&id).await.unwrap().burned);
}

mod adversary {
    use super::*;

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
    async fn concurrent_answers_to_one_request_store_exactly_one() {
        databases!(relay, _admin);
        let id = fresh_id();
        PostgresVault::new(&relay)
            .post_request(&Request { id, recipient_key: recipient_key(), lifetime: Lifetime::ONE_DAY })
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
        let evil = SealedPayload::new(b"attacker".to_vec()).unwrap();
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
        SealedChunk::new(vec![i as u8 + 1; 4096]).unwrap()
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
        for i in 0..3 {
            assert_eq!(custodian.open_chunk(&id, at(i), Some(&claim)).await, Ok(chunk(i)));
            assert_eq!(custodian.open_chunk(&id, at(i), Some(&claim)).await, Err(CustodyError::NotFound));
        }
        assert_eq!((rows(&admin, "deposits", &id).await, rows(&admin, "chunks", &id).await), (0, 0));
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
        let request = custodian.post_request(recipient_key(), Lifetime::ONE_DAY).await.unwrap().id;
        let answer = Answer {
            payload: payload(),
            retention: Retention::UntilExpiry,
            lifetime: Lifetime::ONE_HOUR,
            chunks: Some(count(custody::MAX_CHUNKS)),
        };
        custodian.answer_request(request, answer).await.unwrap();
        let big = SealedChunk::new(vec![0xAB; MAX_CHUNK_LEN]).unwrap();
        for i in 0..custody::MAX_CHUNKS {
            custodian.put_chunk(&request, at(i), big.clone()).await.unwrap();
        }
        assert_eq!(custodian.open(&request).await.unwrap().chunks, Some(count(custody::MAX_CHUNKS)));
        assert_eq!(custodian.open_chunk(&request, at(9), None).await, Ok(big));
    }

    #[tokio::test]
    async fn revoking_a_file_deletes_its_chunks() {
        databases!(relay, admin);
        let custodian = custodian(&relay);
        let id = file(&relay, 2, Retention::UntilExpiry).await;
        custodian.revoke(&id, &token(5)).await.unwrap();
        assert_eq!(rows(&admin, "chunks", &id).await, 0);
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
            assert_eq!(custodian.put_chunk(&id, at(0), chunk(7)).await, Err(CustodyError::AlreadyExists));
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
            assert_eq!(vault.open_chunk(&id, at(0), Some(&claim(winners[0]))).await, Ok(Some(chunk(0))));
        }

        #[tokio::test]
        async fn concurrent_reads_of_one_burning_chunk_get_it_once() {
            databases!(relay, admin);
            let id = file(&relay, 2, Retention::BurnAfterReading).await;
            PostgresVault::new(&relay).open(&id, &claim(0)).await.unwrap().unwrap();
            let mut clients = Vec::new();
            for _ in 0..16 {
                clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
            }
            let outcomes = join_all(clients.iter().enumerate().map(|(n, c)| async move {
                PostgresVault::new(c).open_chunk(&id, at((n % 2) as u16), Some(&claim(0))).await
            }))
            .await;
            assert_eq!(outcomes.iter().filter(|o| matches!(o, Ok(Some(_)))).count(), 2, "{outcomes:?}");
            assert!(outcomes.iter().all(|o| o.is_ok()));
            assert_eq!(rows(&admin, "deposits", &id).await, 0, "the last chunk takes the deposit along");
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
            // Fill custody.chunks up to its 256 MiB budget (zeros compress, so this is cheap).
            admin
                .batch_execute(
                    "insert into custody.deposits (id, payload, burn_after_reading, expires_at, chunk_count)
                     select decode(lpad(to_hex(n), 32, 'f'), 'hex'), '\\x00', false, now() + interval '1 hour', 10
                     from generate_series(1, 26) n;
                     insert into custody.chunks (deposit_id, idx, ciphertext)
                     select decode(lpad(to_hex(n), 32, 'f'), 'hex'), i, decode(repeat('00', 1048592), 'hex')
                     from generate_series(1, 26) n, generate_series(0, 9) i
                     where (n - 1) * 10 + i < 255;",
                )
                .await
                .unwrap();
            let custodian = custodian(&relay);
            let id = custodian.deposit_file(payload(), count(1), Retention::UntilExpiry, Lifetime::ONE_DAY, None);
            let id = id.await.unwrap().id;
            let big = SealedChunk::new(vec![1; MAX_CHUNK_LEN]).unwrap();
            let outcome = custodian.put_chunk(&id, at(0), big).await;
            admin
                .batch_execute("delete from custody.deposits where chunk_count = 10 and payload = '\\x00'")
                .await
                .unwrap();
            assert_eq!(outcome, Err(CustodyError::StorageFull));
        }

        #[tokio::test]
        async fn database_rejects_chunks_the_domain_would_reject() {
            databases!(relay, _admin);
            let id = fresh_id();
            let id = id.as_bytes().as_slice();
            let too_many = relay
                .query_one("select custody.deposit($1, $2, false, 300, null, 11::smallint)", &[&id, &b"x".as_slice()])
                .await;
            assert!(too_many.is_err(), "11 chunks accepted");
            relay
                .query_one("select custody.deposit($1, $2, false, 300, null, 10::smallint)", &[&id, &b"x".as_slice()])
                .await
                .unwrap();
            let huge = vec![0u8; MAX_CHUNK_LEN + 1];
            let oversized =
                relay.query_one("select custody.put_chunk($1, 0::smallint, $2)", &[&id, &huge.as_slice()]).await;
            assert!(oversized.is_err(), "oversized chunk accepted");
            let past =
                relay.query_one("select custody.put_chunk($1, 10::smallint, $2)", &[&id, &b"x".as_slice()]).await;
            assert!(!past.unwrap().get::<_, bool>(0), "index 10 accepted");
        }
    }
}
