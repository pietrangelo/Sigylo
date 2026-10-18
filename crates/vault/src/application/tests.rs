//! The vault against the Custody contract, through the same path the relay
//! takes: a custodian, a remote vault, the wire, and the vault in its
//! Durable Object.

use custody::{
    Answer, ChunkCount, ChunkIndex, Custodian, CustodyError, DropId, GARBAGE_GRACE_SECONDS, Lifetime, MAX_CHUNK_LEN,
    MIN_CHUNK_LEN, MIN_PAYLOAD_LEN, ObjectName, RESERVATION_SECONDS, RecipientKeyBlob, Request, Retention,
    RevocationToken, SealedChunk, SealedPayload, UnixTime, Vault,
};

use super::Clock;
use super::fakes::{Loopback, ManualClock, MemoryBucket, MemoryKv, SequentialIds, ToyDigest, block_on};
use super::{Draining, LedgerVault, RemoteVault};
use crate::core::{
    INCOMPLETE_FILE_SECONDS, OBJECT_BYTES_CEILING, PURGE_BATCH, RECORD_CEILING, STORING_WRITES_PER_DAY, Usage, keys,
};

#[derive(Debug, Default)]
struct World {
    kv: MemoryKv,
    bucket: MemoryBucket,
    clock: ManualClock,
    ids: SequentialIds,
}

type Inner<'a> = LedgerVault<&'a MemoryKv, &'a MemoryBucket, &'a SequentialIds, &'a ManualClock>;
type Relay<'a> = Custodian<RemoteVault<Loopback<Inner<'a>>>, &'a MemoryBucket, ToyDigest, &'a SequentialIds>;

impl World {
    fn vault(&self) -> Inner<'_> {
        LedgerVault::new(&self.kv, &self.bucket, &self.ids, &self.clock)
    }

    fn relay(&self) -> Relay<'_> {
        Custodian::new(RemoteVault::new(Loopback::new(self.vault())), &self.bucket, ToyDigest, &self.ids)
    }

    fn usage(&self) -> Usage {
        self.vault().ledger().usage_now(self.clock.now()).unwrap()
    }

    fn advance(&self, seconds: u32) {
        self.clock.advance(i64::from(seconds));
    }

    /// Everything that went has left the bucket and the records, and the
    /// counters are back to zero: nothing leaks.
    fn assert_empty(&self) {
        let relay = self.relay();
        self.advance(Lifetime::MAX.seconds() + RESERVATION_SECONDS);
        block_on(relay.purge_expired()).unwrap();
        self.advance(GARBAGE_GRACE_SECONDS);
        block_on(relay.collect_garbage(|| true)).unwrap();
        assert_eq!(self.bucket.len(), 0, "objects left in the bucket");
        let records: Vec<String> = self.kv.keys().into_iter().filter(|k| k != keys::USAGE).collect();
        assert_eq!(records, Vec::<String>::new(), "records left");
        let usage = self.usage();
        assert_eq!((usage.object_bytes, usage.records), (0, 0));
    }
}

fn sealed(tag: u8) -> SealedPayload {
    let mut bytes = vec![0xA0; MIN_PAYLOAD_LEN + 10];
    bytes[0] = tag;
    SealedPayload::new(bytes).unwrap()
}

fn chunk(tag: u8, len: usize) -> SealedChunk {
    let mut bytes = vec![0xC0; len];
    bytes[0] = tag;
    SealedChunk::new(bytes).unwrap()
}

fn token(n: u8) -> RevocationToken {
    RevocationToken::from_slice(&[n; 32]).unwrap()
}

fn at(index: u16) -> ChunkIndex {
    ChunkIndex::new(index).unwrap()
}

fn key() -> RecipientKeyBlob {
    RecipientKeyBlob::new(vec![7; RecipientKeyBlob::LEN]).unwrap()
}

const BURN: Retention = Retention::BurnAfterReading;
const KEEP: Retention = Retention::UntilExpiry;

/// A file of three chunks, the last one short, all uploaded.
fn deposit_file(relay: &Relay<'_>, retention: Retention) -> DropId {
    let count = ChunkCount::new(3).unwrap();
    let id = block_on(relay.deposit_file(sealed(1), count, retention, Lifetime::ONE_DAY, Some(&token(1)))).unwrap().id;
    for (i, c) in [chunk(10, MAX_CHUNK_LEN), chunk(11, MAX_CHUNK_LEN), chunk(12, MIN_CHUNK_LEN)].into_iter().enumerate()
    {
        block_on(relay.put_chunk(&id, at(i as u16), c)).unwrap();
    }
    id
}

mod secrets {
    use super::*;

    #[test]
    fn burn_after_reading_opens_once_and_leaves_no_trace() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), BURN, Lifetime::ONE_HOUR, None)).unwrap().id;
        assert!(w.bucket.holds(sealed(1).as_bytes()));
        let opened = block_on(relay.open(&id)).unwrap();
        assert_eq!((opened.payload, opened.burned, opened.chunks, opened.claim), (sealed(1), true, None, None));
        assert_eq!(block_on(relay.open(&id)), Err(CustodyError::NotFound));
        // The payload left the bucket with the burn, not at the next collection.
        assert!(!w.bucket.holds(sealed(1).as_bytes()));
        w.assert_empty();
    }

    #[test]
    fn until_expiry_opens_until_the_vault_clock_says_otherwise() {
        let w = World::default();
        let relay = w.relay();
        let receipt = block_on(relay.deposit(sealed(1), KEEP, Lifetime::ONE_HOUR, None)).unwrap();
        assert_eq!(receipt.expires_at, UnixTime(w.clock.0.get() + 3600));
        for _ in 0..3 {
            assert!(!block_on(relay.open(&receipt.id)).unwrap().burned);
        }
        w.advance(3599);
        assert!(block_on(relay.open(&receipt.id)).is_ok());
        w.advance(1);
        assert_eq!(block_on(relay.open(&receipt.id)), Err(CustodyError::NotFound));
        w.assert_empty();
    }

    #[test]
    fn revocation_needs_the_right_token_and_deletes_at_once() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), KEEP, Lifetime::ONE_DAY, Some(&token(1)))).unwrap().id;
        assert_eq!(block_on(relay.revoke(&id, &token(2))), Err(CustodyError::NotFound));
        assert!(block_on(relay.open(&id)).is_ok());
        block_on(relay.revoke(&id, &token(1))).unwrap();
        assert_eq!(block_on(relay.open(&id)), Err(CustodyError::NotFound));
        assert_eq!(block_on(relay.revoke(&id, &token(1))), Err(CustodyError::NotFound));
        assert_eq!(w.bucket.len(), 0);
        w.assert_empty();
    }

    #[test]
    fn the_vault_keeps_only_a_digest_of_the_revocation_token() {
        let w = World::default();
        block_on(w.relay().deposit(sealed(1), KEEP, Lifetime::ONE_DAY, Some(&token(0x77)))).unwrap();
        assert!(w.kv.snapshot().values().all(|v| !v.windows(32).any(|win| win == [0x77; 32])));
    }

    #[test]
    fn requests_are_answered_into_their_private_inbox_once() {
        let w = World::default();
        let relay = w.relay();
        let posted = block_on(relay.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        assert_ne!(posted.id, posted.inbox);
        assert_eq!(block_on(relay.fetch_request(&posted.id)).unwrap().recipient_key, key());
        let answer = Answer { payload: sealed(2), retention: BURN, lifetime: Lifetime::ONE_HOUR, chunks: None };
        let receipt = block_on(relay.answer_request(posted.id, answer.clone())).unwrap();
        assert_eq!(receipt.id, posted.inbox);
        // The request is used up, and its public id opens nothing.
        assert_eq!(block_on(relay.fetch_request(&posted.id)), Err(CustodyError::NotFound));
        assert_eq!(block_on(relay.answer_request(posted.id, answer)), Err(CustodyError::NotFound));
        assert_eq!(block_on(relay.open(&posted.id)), Err(CustodyError::NotFound));
        assert_eq!(block_on(relay.open(&posted.inbox)).unwrap().payload, sealed(2));
        // A refused answer leaves nothing in the bucket.
        assert_eq!(w.bucket.len(), 0);
        w.assert_empty();
    }

    #[test]
    fn an_expired_request_cannot_be_answered() {
        let w = World::default();
        let relay = w.relay();
        let posted = block_on(relay.post_request(key(), Lifetime::MIN)).unwrap();
        w.advance(Lifetime::MIN.seconds());
        let answer = Answer { payload: sealed(2), retention: BURN, lifetime: Lifetime::ONE_HOUR, chunks: None };
        assert_eq!(block_on(relay.answer_request(posted.id, answer)), Err(CustodyError::NotFound));
        assert_eq!(w.bucket.len(), 0);
        w.assert_empty();
    }

    #[test]
    fn purge_removes_what_expired_and_its_objects() {
        let w = World::default();
        let relay = w.relay();
        block_on(relay.deposit(sealed(1), KEEP, Lifetime::MIN, None)).unwrap();
        block_on(relay.post_request(key(), Lifetime::MIN)).unwrap();
        deposit_file(&relay, KEEP);
        assert_eq!(w.usage().records, 3);
        w.advance(Lifetime::MIN.seconds());
        assert_eq!(block_on(relay.purge_expired()).unwrap(), 2);
        w.advance(Lifetime::ONE_DAY.seconds());
        assert_eq!(block_on(relay.purge_expired()).unwrap(), 1);
        w.assert_empty();
    }
}

mod files {
    use super::*;

    #[test]
    fn a_burn_after_reading_file_goes_to_whoever_claims_it_one_chunk_at_a_time() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit_file(&relay, BURN);
        let opened = block_on(relay.open(&id)).unwrap();
        assert_eq!((opened.burned, opened.chunks.map(|c| c.get())), (true, Some(3)));
        let claim = opened.claim.expect("the opener holds the claim");
        // Claimed: nobody opens it again, and its chunks need the claim.
        assert_eq!(block_on(relay.open(&id)), Err(CustodyError::NotFound));
        assert_eq!(block_on(relay.open_chunk(&id, at(0), None)), Err(CustodyError::NotFound));
        for (i, tag) in [10, 11, 12].into_iter().enumerate() {
            assert_eq!(block_on(relay.open_chunk(&id, at(i as u16), Some(&claim))).unwrap().as_bytes()[0], tag);
            assert_eq!(block_on(relay.open_chunk(&id, at(i as u16), Some(&claim))), Err(CustodyError::NotFound));
        }
        // The last chunk took the deposit, manifest included, with it.
        assert_eq!(w.usage().records, 1, "only the manifest waits in the garbage");
        w.assert_empty();
    }

    #[test]
    fn a_file_kept_until_expiry_opens_again_and_again() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit_file(&relay, KEEP);
        for _ in 0..2 {
            let opened = block_on(relay.open(&id)).unwrap();
            assert_eq!((opened.burned, opened.claim), (false, None));
            assert_eq!(block_on(relay.open_chunk(&id, at(2), None)).unwrap(), chunk(12, MIN_CHUNK_LEN));
        }
        block_on(relay.revoke(&id, &token(1))).unwrap();
        assert_eq!(w.bucket.len(), 0, "revoking empties the bucket at once");
        w.assert_empty();
    }

    #[test]
    fn an_incomplete_file_cannot_be_opened_and_expires_soon() {
        let w = World::default();
        let relay = w.relay();
        let count = ChunkCount::new(2).unwrap();
        let receipt = block_on(relay.deposit_file(sealed(1), count, KEEP, Lifetime::ONE_DAY, None)).unwrap();
        // The receipt names the lifetime chosen; the last chunk restores it.
        assert_eq!(receipt.expires_at, UnixTime(w.clock.0.get() + i64::from(Lifetime::ONE_DAY.seconds())));
        block_on(relay.put_chunk(&receipt.id, at(0), chunk(1, MAX_CHUNK_LEN))).unwrap();
        assert_eq!(block_on(relay.open(&receipt.id)), Err(CustodyError::NotFound));
        assert_eq!(block_on(relay.open_chunk(&receipt.id, at(0), None)), Err(CustodyError::NotFound));
        w.advance(INCOMPLETE_FILE_SECONDS);
        assert_eq!(block_on(relay.put_chunk(&receipt.id, at(1), chunk(2, MIN_CHUNK_LEN))), Err(CustodyError::NotFound));
        w.assert_empty();
    }

    #[test]
    fn the_last_chunk_gives_the_file_its_lifetime() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit_file(&relay, KEEP);
        w.advance(INCOMPLETE_FILE_SECONDS + 1);
        assert!(block_on(relay.open(&id)).is_ok());
        w.advance(Lifetime::ONE_DAY.seconds() - INCOMPLETE_FILE_SECONDS - 1);
        assert_eq!(block_on(relay.open(&id)), Err(CustodyError::NotFound));
        w.assert_empty();
    }

    #[test]
    fn chunks_go_in_once_where_they_fit_and_never_after_opening() {
        let w = World::default();
        let relay = w.relay();
        let count = ChunkCount::new(2).unwrap();
        let id = block_on(relay.deposit_file(sealed(1), count, BURN, Lifetime::ONE_DAY, None)).unwrap().id;
        let refused =
            |index: u16, c: SealedChunk| block_on(relay.put_chunk(&id, at(index), c)) == Err(CustodyError::NotFound);
        assert!(refused(0, chunk(1, MIN_CHUNK_LEN)), "short, and not the last");
        assert!(refused(2, chunk(1, MIN_CHUNK_LEN)), "past the count");
        block_on(relay.put_chunk(&id, at(0), chunk(1, MAX_CHUNK_LEN))).unwrap();
        assert!(refused(0, chunk(2, MAX_CHUNK_LEN)), "already in");
        block_on(relay.put_chunk(&id, at(1), chunk(3, MIN_CHUNK_LEN))).unwrap();
        block_on(relay.open(&id)).unwrap();
        assert!(refused(1, chunk(4, MIN_CHUNK_LEN)), "after opening");
        // Every refused chunk left the bucket: only the manifest and two chunks remain.
        assert_eq!(w.bucket.len(), 3);
        assert!(refused(0, chunk(1, MIN_CHUNK_LEN)));
        assert_eq!(
            block_on(relay.put_chunk(&DropId::from_slice(&[9; 16]).unwrap(), at(0), chunk(1, MAX_CHUNK_LEN))),
            Err(CustodyError::NotFound)
        );
    }

    #[test]
    fn a_file_answer_takes_its_chunks_in_the_inbox_only() {
        let w = World::default();
        let relay = w.relay();
        let posted = block_on(relay.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        let answer = Answer {
            payload: sealed(2),
            retention: BURN,
            lifetime: Lifetime::ONE_HOUR,
            chunks: ChunkCount::new(1).ok(),
        };
        let receipt = block_on(relay.answer_request(posted.id, answer)).unwrap();
        assert_eq!(block_on(relay.put_chunk(&posted.id, at(0), chunk(5, MIN_CHUNK_LEN))), Err(CustodyError::NotFound));
        block_on(relay.put_chunk(&receipt.id, at(0), chunk(5, MIN_CHUNK_LEN))).unwrap();
        let opened = block_on(relay.open(&posted.inbox)).unwrap();
        let claim = opened.claim.unwrap();
        assert_eq!(block_on(relay.open_chunk(&posted.inbox, at(0), Some(&claim))).unwrap(), chunk(5, MIN_CHUNK_LEN));
        w.assert_empty();
    }

    #[test]
    fn an_abandoned_claim_lapses_within_the_hour() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit_file(&relay, BURN);
        let claim = block_on(relay.open(&id)).unwrap().claim.unwrap();
        block_on(relay.open_chunk(&id, at(0), Some(&claim))).unwrap();
        w.advance(custody::CLAIM_WINDOW_SECONDS);
        assert_eq!(block_on(relay.open_chunk(&id, at(1), Some(&claim))), Err(CustodyError::NotFound));
        w.assert_empty();
    }
}

mod garbage {
    use super::*;

    #[test]
    fn a_reservation_never_recorded_is_collected_and_a_stale_one_cannot_be_recorded() {
        let w = World::default();
        let vault = w.vault();
        let count = ChunkCount::new(1).unwrap();
        let id = block_on(w.relay().deposit_file(sealed(1), count, KEEP, Lifetime::ONE_DAY, None)).unwrap().id;
        let object = ObjectName::from_array([0x0B; 16]);
        let len = MIN_CHUNK_LEN as u32;
        assert!(block_on(vault.reserve_chunk(&id, at(0), &object, len)).unwrap());
        w.advance(custody::RESERVATION_FRESH_SECONDS);
        assert!(!block_on(vault.put_chunk(&id, at(0), &object, len)).unwrap(), "stale");
        assert!(block_on(vault.garbage(10)).unwrap().is_empty(), "not due yet");
        w.advance(RESERVATION_SECONDS - custody::RESERVATION_FRESH_SECONDS);
        assert_eq!(block_on(vault.garbage(10)).unwrap(), vec![object]);
        block_on(vault.forget_garbage(&[object])).unwrap();
        assert!(block_on(vault.garbage(10)).unwrap().is_empty());
    }

    #[test]
    fn a_recorded_chunk_must_match_its_reservation() {
        let w = World::default();
        let vault = w.vault();
        let count = ChunkCount::new(2).unwrap();
        let id = block_on(w.relay().deposit_file(sealed(1), count, KEEP, Lifetime::ONE_DAY, None)).unwrap().id;
        let object = ObjectName::from_array([0x0B; 16]);
        let len = MAX_CHUNK_LEN as u32;
        assert!(block_on(vault.reserve_chunk(&id, at(0), &object, len)).unwrap());
        assert!(!block_on(vault.put_chunk(&id, at(0), &object, len - 1)).unwrap(), "another size");
        let odd = ObjectName::from_array([0x0C; 16]);
        assert!(!block_on(vault.reserve_chunk(&id, at(1), &odd, 300)).unwrap(), "no sealer makes 300 bytes");
        assert!(!block_on(vault.put_chunk(&id, at(0), &ObjectName::from_array([1; 16]), len)).unwrap(), "unreserved");
        assert!(block_on(vault.put_chunk(&id, at(1), &object, len)).unwrap(), "any free slot of its size");
        assert!(!block_on(vault.put_chunk(&id, at(0), &object, len)).unwrap(), "a reservation records once");
    }

    #[test]
    fn a_failing_bucket_loses_track_of_nothing() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), BURN, Lifetime::ONE_HOUR, None)).unwrap().id;
        w.bucket.fail_deletes.set(true);
        assert_eq!(block_on(relay.open(&id)).unwrap().payload, sealed(1));
        assert_eq!(w.bucket.len(), 1, "the delete failed");
        w.advance(GARBAGE_GRACE_SECONDS);
        assert!(block_on(relay.collect_garbage(|| true)).is_err());
        w.bucket.fail_deletes.set(false);
        assert_eq!(block_on(relay.collect_garbage(|| true)).unwrap(), 1);
        w.assert_empty();
    }

    #[test]
    fn a_failing_bucket_burns_nothing() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), BURN, Lifetime::ONE_HOUR, None)).unwrap().id;
        w.bucket.fail_reads.set(true);
        assert!(block_on(relay.open(&id)).is_err());
        w.bucket.fail_reads.set(false);
        assert_eq!(block_on(relay.open(&id)).unwrap().payload, sealed(1));
    }

    #[test]
    fn a_payload_the_bucket_refused_is_never_recorded() {
        let w = World::default();
        let relay = w.relay();
        w.bucket.fail.set(true);
        assert_eq!(
            block_on(relay.deposit(sealed(1), BURN, Lifetime::ONE_HOUR, None)),
            Err(CustodyError::VaultUnavailable)
        );
        w.bucket.fail.set(false);
        w.assert_empty();
    }
}

mod ceilings {
    use super::*;

    /// Fills the counters as if the vault held that much.
    fn pretend(w: &World, usage: Usage) {
        w.kv.tamper(keys::USAGE, Usage { day: w.usage().day, ..usage }.encode());
    }

    #[test]
    fn a_full_object_store_refuses_new_things_and_still_opens_old_ones() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), KEEP, Lifetime::ONE_DAY, Some(&token(1)))).unwrap().id;
        let posted = block_on(relay.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        let file = {
            let count = ChunkCount::new(1).unwrap();
            block_on(relay.deposit_file(sealed(3), count, KEEP, Lifetime::ONE_DAY, None)).unwrap().id
        };
        let held = w.usage();
        pretend(&w, Usage { object_bytes: OBJECT_BYTES_CEILING - 10, ..held });
        let before = w.kv.snapshot();
        let objects = w.bucket.len();
        assert_eq!(block_on(relay.deposit(sealed(2), KEEP, Lifetime::ONE_DAY, None)), Err(CustodyError::StorageFull));
        let answer = Answer { payload: sealed(2), retention: BURN, lifetime: Lifetime::ONE_HOUR, chunks: None };
        assert_eq!(block_on(relay.answer_request(posted.id, answer)), Err(CustodyError::StorageFull));
        assert_eq!(block_on(relay.put_chunk(&file, at(0), chunk(1, MIN_CHUNK_LEN))), Err(CustodyError::StorageFull));
        // Nothing changed, and nothing was written to the bucket first.
        assert_eq!(w.kv.snapshot(), before);
        assert_eq!(w.bucket.len(), objects);
        // Opening, fetching and revoking still work.
        assert!(block_on(relay.open(&id)).is_ok());
        assert!(block_on(relay.fetch_request(&posted.id)).is_ok());
        block_on(relay.revoke(&id, &token(1))).unwrap();
    }

    #[test]
    fn requests_count_against_the_record_ceiling() {
        let w = World::default();
        let relay = w.relay();
        pretend(&w, Usage { records: RECORD_CEILING, ..w.usage() });
        assert_eq!(block_on(relay.post_request(key(), Lifetime::ONE_DAY)), Err(CustodyError::StorageFull));
    }

    #[test]
    fn what_expired_makes_room_before_anything_is_refused() {
        let w = World::default();
        let relay = w.relay();
        let old = block_on(relay.deposit(sealed(1), KEEP, Lifetime::MIN, None)).unwrap().id;
        let held = w.usage();
        // Room for the new payload only once the old one is gone.
        let len = sealed(2).as_bytes().len() as u64;
        pretend(&w, Usage { object_bytes: OBJECT_BYTES_CEILING - len + held.object_bytes, ..held });
        w.advance(Lifetime::MIN.seconds());
        // The expired deposit goes (to the garbage, still counted) but is no room yet...
        assert_eq!(block_on(relay.deposit(sealed(2), KEEP, Lifetime::ONE_DAY, None)), Err(CustodyError::StorageFull));
        assert_eq!(block_on(relay.open(&old)), Err(CustodyError::NotFound));
        assert!(w.kv.get_record(&keys::deposit(&old)).is_none(), "purged, and the purge stays");
        // ...until the collector deletes its object.
        w.advance(GARBAGE_GRACE_SECONDS);
        block_on(relay.collect_garbage(|| true)).unwrap();
        assert!(block_on(relay.deposit(sealed(2), KEEP, Lifetime::ONE_DAY, None)).is_ok());
    }

    #[test]
    fn a_day_of_writes_stops_storing_but_not_opening_until_the_next_day() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), BURN, Lifetime::ONE_DAY, None)).unwrap().id;
        pretend(&w, Usage { writes: STORING_WRITES_PER_DAY, ..w.usage() });
        assert_eq!(block_on(relay.deposit(sealed(2), KEEP, Lifetime::ONE_DAY, None)), Err(CustodyError::StorageFull));
        assert_eq!(block_on(relay.post_request(key(), Lifetime::ONE_DAY)), Err(CustodyError::StorageFull));
        assert_eq!(block_on(relay.open(&id)).unwrap().payload, sealed(1));
        let midnight = 86_400 - w.clock.0.get().rem_euclid(86_400);
        w.clock.advance(midnight);
        assert!(block_on(relay.deposit(sealed(2), KEEP, Lifetime::ONE_DAY, None)).is_ok());
    }

    #[test]
    fn writes_are_counted_as_they_happen() {
        let w = World::default();
        let relay = w.relay();
        let start = w.kv.writes.get();
        block_on(relay.deposit(sealed(1), BURN, Lifetime::ONE_DAY, None)).unwrap();
        let id = block_on(relay.deposit(sealed(2), BURN, Lifetime::ONE_DAY, None)).unwrap().id;
        block_on(relay.open(&id)).unwrap();
        assert_eq!(u64::from(w.usage().writes), w.kv.writes.get() - start);
    }
}

mod adversary {
    use super::*;

    #[test]
    fn two_opens_that_both_found_the_secret_burn_it_once() {
        let w = World::default();
        let vault = w.vault();
        let id = block_on(w.relay().deposit(sealed(1), BURN, Lifetime::ONE_HOUR, None)).unwrap().id;
        let ledger = vault.ledger();
        let now = w.clock.now();
        let first = ledger.find(now, &id).unwrap().unwrap();
        let second = ledger.find(now, &id).unwrap().unwrap();
        let claim = custody::ClaimDigest::from_array([1; 32]);
        assert!(ledger.commit_open(now, &id, &first.payload.object, &claim).unwrap().is_some());
        assert!(ledger.commit_open(now, &id, &second.payload.object, &claim).unwrap().is_none());
    }

    #[test]
    fn two_claims_of_one_file_leave_it_to_the_first() {
        let w = World::default();
        let vault = w.vault();
        let id = deposit_file(&w.relay(), BURN);
        let (ledger, now) = (vault.ledger(), w.clock.now());
        let found = ledger.find(now, &id).unwrap().unwrap();
        let (a, b) = (custody::ClaimDigest::from_array([1; 32]), custody::ClaimDigest::from_array([2; 32]));
        assert!(ledger.commit_open(now, &id, &found.payload.object, &a).unwrap().is_some());
        assert!(ledger.commit_open(now, &id, &found.payload.object, &b).unwrap().is_none());
        assert!(ledger.open_chunk(now, &id, at(0), Some(&b)).unwrap().is_none());
        assert!(!ledger.burn_chunk(now, &id, at(0), &b).unwrap());
        assert!(ledger.burn_chunk(now, &id, at(0), &a).unwrap());
        assert!(!ledger.burn_chunk(now, &id, at(0), &a).unwrap(), "each chunk burns once");
    }

    #[test]
    fn a_write_that_fails_halfway_leaves_no_half_step() {
        for nth in 1..12 {
            let w = World::default();
            let relay = w.relay();
            let id = deposit_file(&relay, BURN);
            let before = w.kv.snapshot();
            w.kv.fail_write.set(nth);
            let outcome = block_on(relay.open(&id));
            w.kv.fail_write.set(0);
            if outcome.is_err() {
                assert_eq!(w.kv.snapshot(), before, "failing write {nth}");
                assert!(block_on(relay.open(&id)).is_ok(), "still opens after failing write {nth}");
            }
        }
    }

    #[test]
    fn a_damaged_record_reads_as_a_fault_never_as_other_data() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), KEEP, Lifetime::ONE_DAY, Some(&token(1)))).unwrap().id;
        let key = keys::deposit(&id);
        let good = w.kv.get_record(&key).unwrap();
        for damage in [vec![], good[..good.len() - 1].to_vec(), [good.clone(), vec![0]].concat(), {
            let mut flipped = good.clone();
            flipped[1] = 7;
            flipped
        }] {
            w.kv.tamper(&key, damage);
            assert_eq!(block_on(relay.open(&id)), Err(CustodyError::VaultUnavailable));
            assert_eq!(block_on(relay.revoke(&id, &token(1))), Err(CustodyError::VaultUnavailable));
        }
        w.kv.tamper(keys::USAGE, vec![1, 2, 3]);
        assert_eq!(
            block_on(relay.deposit(sealed(2), KEEP, Lifetime::ONE_DAY, None)),
            Err(CustodyError::VaultUnavailable)
        );
    }

    #[test]
    fn a_vault_that_cannot_be_reached_fails_closed() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), BURN, Lifetime::ONE_HOUR, None)).unwrap().id;
        w.kv.down.set(true);
        assert_eq!(block_on(relay.open(&id)), Err(CustodyError::VaultUnavailable));
        w.kv.down.set(false);
        assert_eq!(block_on(relay.open(&id)).unwrap().payload, sealed(1));
    }

    #[test]
    fn a_garbled_reply_is_a_fault_and_never_a_payload() {
        let w = World::default();
        let link = Loopback::new(w.vault());
        let remote = RemoteVault::new(&link);
        let deposit = custody::Deposit {
            id: DropId::from_slice(&[1; 16]).unwrap(),
            payload: sealed(1),
            retention: BURN,
            lifetime: Lifetime::ONE_HOUR,
            revocation: None,
            chunks: None,
        };
        for garble in
            [vec![], vec![0xFF], crate::core::Reply::Flag(true).encode(), crate::core::Reply::Opened(None).encode()]
        {
            *link.garble.borrow_mut() = Some(garble);
            assert_eq!(block_on(remote.deposit(&deposit)), Err(CustodyError::VaultUnavailable));
        }
        *link.garble.borrow_mut() = Some(crate::core::Reply::Failed(CustodyError::StorageFull).encode());
        assert_eq!(block_on(remote.deposit(&deposit)), Err(CustodyError::StorageFull));
    }

    #[test]
    fn a_call_that_does_not_decode_is_refused() {
        let w = World::default();
        let vault = w.vault();
        for junk in [vec![], vec![0], vec![2, 1, 2, 3], vec![13, 0]] {
            assert_eq!(
                block_on(super::super::serve(&vault, &junk)),
                crate::core::Reply::Failed(CustodyError::VaultUnavailable).encode()
            );
        }
        assert_eq!(w.kv.keys(), Vec::<String>::new());
    }

    #[test]
    fn stale_expiry_entries_are_swept_without_touching_live_records() {
        let w = World::default();
        let relay = w.relay();
        let id = block_on(relay.deposit(sealed(1), KEEP, Lifetime::ONE_DAY, None)).unwrap().id;
        // An index entry pointing at a time the record no longer has.
        let stale = keys::expiry(UnixTime(w.clock.0.get() - 10), keys::Kind::Deposit, &id);
        w.kv.tamper(&stale, vec![]);
        assert_eq!(block_on(relay.purge_expired()).unwrap(), 0);
        assert!(w.kv.get_record(&stale).is_none());
        assert!(block_on(relay.open(&id)).is_ok());
    }

    #[test]
    fn the_object_store_never_learns_which_deposit_an_object_belongs_to() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit_file(&relay, KEEP);
        // Names are drawn fresh for each object, never made from the id.
        let names = w.bucket.names();
        assert_eq!(names.len(), 4);
        assert!(names.iter().all(|n| n.as_bytes() != id.as_bytes()));
    }

    #[test]
    fn a_purge_that_finds_a_flood_takes_it_in_batches() {
        let w = World::default();
        let relay = w.relay();
        for _ in 0..(PURGE_BATCH + 7) {
            block_on(relay.post_request(key(), Lifetime::MIN)).unwrap();
        }
        w.advance(Lifetime::MIN.seconds());
        let (first, more) = w.vault().ledger().purge_batch(w.clock.now()).unwrap();
        assert_eq!((first, more), (PURGE_BATCH as u64, true));
        assert_eq!(block_on(relay.purge_expired()).unwrap(), 7);
        w.assert_empty();
    }

    #[test]
    fn one_relay_call_is_one_durable_object_request() {
        let w = World::default();
        let link = Loopback::new(w.vault());
        let relay = Custodian::new(RemoteVault::new(&link), &w.bucket, ToyDigest, &w.ids);
        let id = block_on(relay.deposit(sealed(1), BURN, Lifetime::ONE_HOUR, None)).unwrap().id;
        block_on(relay.open(&id)).unwrap();
        assert_eq!(link.calls.get(), 2);
    }
}

mod draining {
    use super::*;

    /// A new vault and an old one with its own records and the same bucket.
    struct Two {
        new: World,
        old_kv: MemoryKv,
    }

    impl Two {
        fn new() -> Self {
            Self { new: World::default(), old_kv: MemoryKv::default() }
        }

        fn old(&self) -> Inner<'_> {
            LedgerVault::new(&self.old_kv, &self.new.bucket, &self.new.ids, &self.new.clock)
        }

        fn old_relay(&self) -> Custodian<Inner<'_>, &MemoryBucket, ToyDigest, &SequentialIds> {
            Custodian::new(self.old(), &self.new.bucket, ToyDigest, &self.new.ids)
        }

        fn relay(&self) -> Custodian<Draining<Inner<'_>, Inner<'_>>, &MemoryBucket, ToyDigest, &SequentialIds> {
            Custodian::new(Draining::new(self.new.vault(), self.old()), &self.new.bucket, ToyDigest, &self.new.ids)
        }
    }

    #[test]
    fn what_the_old_vault_holds_is_still_opened_revoked_and_answered() {
        let two = Two::new();
        let old = two.old_relay();
        let burn = block_on(old.deposit(sealed(1), BURN, Lifetime::ONE_DAY, None)).unwrap().id;
        let revocable = block_on(old.deposit(sealed(2), KEEP, Lifetime::ONE_DAY, Some(&token(2)))).unwrap().id;
        let posted = block_on(old.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        let file = {
            let count = ChunkCount::new(1).unwrap();
            block_on(old.deposit_file(sealed(3), count, BURN, Lifetime::ONE_DAY, None)).unwrap().id
        };

        let relay = two.relay();
        block_on(relay.put_chunk(&file, at(0), chunk(9, MIN_CHUNK_LEN))).unwrap();
        assert_eq!(block_on(relay.open(&burn)).unwrap().payload, sealed(1));
        assert_eq!(block_on(relay.open(&burn)), Err(CustodyError::NotFound));
        block_on(relay.revoke(&revocable, &token(2))).unwrap();
        assert_eq!(block_on(relay.fetch_request(&posted.id)).unwrap().recipient_key, key());
        let answer = Answer { payload: sealed(4), retention: BURN, lifetime: Lifetime::ONE_HOUR, chunks: None };
        assert_eq!(block_on(relay.answer_request(posted.id, answer)).unwrap().id, posted.inbox);
        assert_eq!(block_on(relay.open(&posted.inbox)).unwrap().payload, sealed(4));
        let claim = block_on(relay.open(&file)).unwrap().claim.unwrap();
        assert_eq!(block_on(relay.open_chunk(&file, at(0), Some(&claim))).unwrap(), chunk(9, MIN_CHUNK_LEN));

        // Nothing of it ever moved into the new vault.
        assert_eq!(two.new.kv.keys(), Vec::<String>::new());
        two.new.advance(GARBAGE_GRACE_SECONDS);
        block_on(relay.collect_garbage(|| true)).unwrap();
        assert_eq!(two.new.bucket.len(), 0);
    }

    #[test]
    fn everything_new_goes_to_the_new_vault() {
        let two = Two::new();
        let relay = two.relay();
        let id = block_on(relay.deposit(sealed(1), KEEP, Lifetime::ONE_DAY, None)).unwrap().id;
        let posted = block_on(relay.post_request(key(), Lifetime::ONE_DAY)).unwrap();
        assert!(two.old_kv.keys().is_empty());
        assert!(block_on(two.new.vault().open(&id, &custody::ClaimDigest::from_array([0; 32]))).unwrap().is_some());
        assert!(block_on(two.new.vault().fetch_request(&posted.id)).unwrap().is_some());
    }

    #[test]
    fn expiry_is_purged_in_both() {
        let two = Two::new();
        block_on(two.old_relay().deposit(sealed(1), KEEP, Lifetime::MIN, None)).unwrap();
        let relay = two.relay();
        block_on(relay.deposit(sealed(2), KEEP, Lifetime::MIN, None)).unwrap();
        two.new.advance(Lifetime::MIN.seconds());
        assert_eq!(block_on(relay.purge_expired()).unwrap(), 2);
    }
}

#[test]
fn unused_request_type_is_the_custody_one() {
    // Keeps the import honest: requests travel as Custody's own type.
    let _: Option<Request> = None;
}
