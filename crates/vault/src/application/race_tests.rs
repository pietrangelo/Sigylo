//! Races on the real async path: the relay's custodian, the wire and the
//! vault, with the bucket's reads or writes held in flight (as an R2 call
//! is while the Durable Object serves other requests) and other calls, the
//! cron's included, run in the middle. The ledger-only adversary tests
//! show each step decides alone; these show the steps around an `await`
//! still deliver at most once and never lose an object.

use core::future::Future;
use core::pin::{Pin, pin};
use core::task::Poll;

use custody::{
    Answer, CLAIM_WINDOW_SECONDS, ChunkCount, ChunkIndex, Custodian, CustodyError, DropId, GARBAGE_GRACE_SECONDS,
    Lifetime, MAX_CHUNK_LEN, MIN_CHUNK_LEN, MIN_PAYLOAD_LEN, RESERVATION_SECONDS, RecipientKeyBlob, Retention,
    RevocationToken, SealedChunk, SealedPayload,
};

use super::Clock;
use super::fakes::{GatedBucket, Loopback, ManualClock, MemoryKv, SequentialIds, ToyDigest, block_on, poll_once};
use super::{LedgerVault, RemoteVault};
use crate::core::keys;

#[derive(Debug, Default)]
struct World {
    kv: MemoryKv,
    bucket: GatedBucket,
    clock: ManualClock,
    ids: SequentialIds,
}

type Inner<'a> = LedgerVault<&'a MemoryKv, &'a GatedBucket, &'a SequentialIds, &'a ManualClock>;
type Relay<'a> = Custodian<RemoteVault<Loopback<Inner<'a>>>, &'a GatedBucket, ToyDigest, &'a SequentialIds>;

impl World {
    fn vault(&self) -> Inner<'_> {
        LedgerVault::new(&self.kv, &self.bucket, &self.ids, &self.clock)
    }

    fn relay(&self) -> Relay<'_> {
        Custodian::new(RemoteVault::new(Loopback::new(self.vault())), &self.bucket, ToyDigest, &self.ids)
    }

    fn advance(&self, seconds: u32) {
        self.clock.advance(i64::from(seconds));
    }

    /// One run of the cron, as `chores` in the Worker does it.
    fn cron(&self, relay: &Relay<'_>) {
        block_on(relay.purge_expired()).unwrap();
        block_on(relay.collect_garbage(|| true)).unwrap();
    }

    fn holds(&self, bytes: &[u8]) -> bool {
        self.bucket.bucket.holds(bytes)
    }

    /// Nothing leaks: once everything has expired and been collected, the
    /// bucket and the records are empty and the counters back to zero.
    fn assert_empty(&self) {
        let relay = self.relay();
        self.advance(Lifetime::MAX.seconds() + RESERVATION_SECONDS);
        block_on(relay.purge_expired()).unwrap();
        self.advance(GARBAGE_GRACE_SECONDS);
        block_on(relay.collect_garbage(|| true)).unwrap();
        assert_eq!(self.bucket.bucket.len(), 0, "objects left in the bucket");
        let records: Vec<String> = self.kv.keys().into_iter().filter(|k| k != keys::USAGE).collect();
        assert_eq!(records, Vec::<String>::new(), "records left");
        let usage = self.vault().ledger().usage_now(self.clock.now()).unwrap();
        assert_eq!((usage.object_bytes, usage.records, usage.requests), (0, 0, 0));
    }
}

/// The output of a future whose gates are open by now.
fn finish<F: Future>(future: Pin<&mut F>) -> F::Output {
    match poll_once(future) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("still waiting at a gate"),
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

fn token() -> RevocationToken {
    RevocationToken::from_slice(&[1; 32]).unwrap()
}

fn at(index: u16) -> ChunkIndex {
    ChunkIndex::new(index).unwrap()
}

const BURN: Retention = Retention::BurnAfterReading;
const KEEP: Retention = Retention::UntilExpiry;

fn deposit(relay: &Relay<'_>, retention: Retention, lifetime: Lifetime) -> DropId {
    block_on(relay.deposit(sealed(1), retention, lifetime, Some(&token()))).unwrap().id
}

/// A file of two chunks, tagged 10 and 11, both uploaded.
fn deposit_file(relay: &Relay<'_>, retention: Retention) -> DropId {
    let count = ChunkCount::new(2).unwrap();
    let id = block_on(relay.deposit_file(sealed(1), count, retention, Lifetime::ONE_DAY, Some(&token()))).unwrap().id;
    block_on(relay.put_chunk(&id, at(0), chunk(10, MAX_CHUNK_LEN))).unwrap();
    block_on(relay.put_chunk(&id, at(1), chunk(11, MIN_CHUNK_LEN))).unwrap();
    id
}

mod opening {
    use super::*;

    #[test]
    fn two_opens_reading_the_bucket_at_once_hand_the_secret_out_once() {
        for (b_first, land_first) in [(false, false), (true, false), (false, true), (true, true)] {
            let w = World::default();
            let relay = w.relay();
            let id = deposit(&relay, BURN, Lifetime::ONE_HOUR);
            w.bucket.reads_land_first.set(land_first);
            w.bucket.hold_reads.set(true);
            let mut a = pin!(relay.open(&id));
            let mut b = pin!(relay.open(&id));
            // Both found the secret and both are reading it from the bucket.
            assert!(poll_once(a.as_mut()).is_pending());
            assert!(poll_once(b.as_mut()).is_pending());
            w.bucket.hold_reads.set(false);
            let (first, second) = if b_first {
                (finish(b.as_mut()), finish(a.as_mut()))
            } else {
                (finish(a.as_mut()), finish(b.as_mut()))
            };
            assert_eq!(first.unwrap().payload, sealed(1), "the first commit delivers");
            assert_eq!(second, Err(CustodyError::NotFound), "the other read is thrown away");
            assert!(!w.holds(sealed(1).as_bytes()), "burned and gone from the bucket");
            w.assert_empty();
        }
    }

    #[test]
    fn two_opens_of_a_file_at_once_leave_the_claim_to_one() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit_file(&relay, BURN);
        w.bucket.hold_reads.set(true);
        let mut a = pin!(relay.open(&id));
        let mut b = pin!(relay.open(&id));
        assert!(poll_once(a.as_mut()).is_pending());
        assert!(poll_once(b.as_mut()).is_pending());
        w.bucket.hold_reads.set(false);
        let claim = finish(a.as_mut()).unwrap().claim.expect("the first open claims the file");
        assert_eq!(finish(b.as_mut()), Err(CustodyError::NotFound));
        assert_eq!(block_on(relay.open_chunk(&id, at(0), Some(&claim))).unwrap().as_bytes()[0], 10);
        w.assert_empty();
    }

    #[test]
    fn a_revocation_while_an_open_reads_the_bucket_wins() {
        for retention in [BURN, KEEP] {
            let w = World::default();
            let relay = w.relay();
            let id = deposit(&relay, retention, Lifetime::ONE_HOUR);
            w.bucket.hold_reads.set(true);
            let mut open = pin!(relay.open(&id));
            assert!(poll_once(open.as_mut()).is_pending());
            block_on(relay.revoke(&id, &token())).unwrap();
            w.bucket.hold_reads.set(false);
            assert_eq!(finish(open.as_mut()), Err(CustodyError::NotFound), "{retention:?}");
            assert!(!w.holds(sealed(1).as_bytes()));
            w.assert_empty();
        }
    }

    #[test]
    fn a_secret_that_expires_while_it_is_read_is_not_handed_out() {
        for (retention, cron) in [(BURN, false), (BURN, true), (KEEP, false), (KEEP, true)] {
            let w = World::default();
            let relay = w.relay();
            let id = deposit(&relay, retention, Lifetime::MIN);
            w.bucket.hold_reads.set(true);
            let mut open = pin!(relay.open(&id));
            assert!(poll_once(open.as_mut()).is_pending());
            w.advance(Lifetime::MIN.seconds());
            if cron {
                w.cron(&relay);
            }
            // Purged or only expired, the grace keeps the object for the read in flight.
            assert!(w.holds(sealed(1).as_bytes()));
            w.bucket.hold_reads.set(false);
            assert_eq!(finish(open.as_mut()), Err(CustodyError::NotFound), "{retention:?}, cron {cron}");
            w.assert_empty();
        }
    }

    #[test]
    fn the_cron_never_deletes_a_live_payload_while_it_is_read() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit(&relay, BURN, Lifetime::ONE_HOUR);
        w.bucket.hold_reads.set(true);
        let mut open = pin!(relay.open(&id));
        assert!(poll_once(open.as_mut()).is_pending());
        // Every reservation and grace this deposit ever had is long due.
        w.advance(RESERVATION_SECONDS + GARBAGE_GRACE_SECONDS);
        w.cron(&relay);
        assert!(w.holds(sealed(1).as_bytes()));
        w.bucket.hold_reads.set(false);
        assert_eq!(finish(open.as_mut()).unwrap().payload, sealed(1));
        w.assert_empty();
    }
}

mod chunks {
    use super::*;

    #[test]
    fn two_downloads_of_a_claimed_chunk_at_once_hand_it_out_once() {
        for (b_first, land_first) in [(false, false), (true, false), (false, true), (true, true)] {
            let w = World::default();
            let relay = w.relay();
            let id = deposit_file(&relay, BURN);
            let claim = block_on(relay.open(&id)).unwrap().claim.unwrap();
            w.bucket.reads_land_first.set(land_first);
            w.bucket.hold_reads.set(true);
            let mut a = pin!(relay.open_chunk(&id, at(0), Some(&claim)));
            let mut b = pin!(relay.open_chunk(&id, at(0), Some(&claim)));
            assert!(poll_once(a.as_mut()).is_pending());
            assert!(poll_once(b.as_mut()).is_pending());
            w.bucket.hold_reads.set(false);
            let (first, second) = if b_first {
                (finish(b.as_mut()), finish(a.as_mut()))
            } else {
                (finish(a.as_mut()), finish(b.as_mut()))
            };
            assert_eq!(first.unwrap().as_bytes()[0], 10, "the burn that counted hands it out");
            assert_eq!(second, Err(CustodyError::NotFound), "the other copy is thrown away");
            assert!(!w.holds(chunk(10, MAX_CHUNK_LEN).as_bytes()));
            assert_eq!(block_on(relay.open_chunk(&id, at(1), Some(&claim))).unwrap().as_bytes()[0], 11);
            w.assert_empty();
        }
    }

    #[test]
    fn a_claim_that_lapses_while_a_chunk_is_read_hands_nothing_out() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit_file(&relay, BURN);
        let claim = block_on(relay.open(&id)).unwrap().claim.unwrap();
        w.bucket.hold_reads.set(true);
        let mut download = pin!(relay.open_chunk(&id, at(0), Some(&claim)));
        assert!(poll_once(download.as_mut()).is_pending());
        w.advance(CLAIM_WINDOW_SECONDS);
        w.cron(&relay);
        assert!(w.holds(chunk(10, MAX_CHUNK_LEN).as_bytes()), "the grace keeps it for the read in flight");
        w.bucket.hold_reads.set(false);
        assert_eq!(finish(download.as_mut()), Err(CustodyError::NotFound));
        w.assert_empty();
    }

    #[test]
    fn a_revocation_while_a_claimed_chunk_is_read_wins() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit_file(&relay, BURN);
        let claim = block_on(relay.open(&id)).unwrap().claim.unwrap();
        // The chunk is already out of the bucket when the revocation comes.
        w.bucket.reads_land_first.set(true);
        w.bucket.hold_reads.set(true);
        let mut download = pin!(relay.open_chunk(&id, at(0), Some(&claim)));
        assert!(poll_once(download.as_mut()).is_pending());
        block_on(relay.revoke(&id, &token())).unwrap();
        w.bucket.hold_reads.set(false);
        assert_eq!(finish(download.as_mut()), Err(CustodyError::NotFound));
        assert_eq!(w.bucket.bucket.len(), 0, "revoked objects leave at once");
        w.assert_empty();
    }
}

mod uploads {
    use super::*;

    #[test]
    fn a_payload_that_lands_after_the_cron_collected_its_reservation_is_never_filed() {
        let w = World::default();
        let relay = w.relay();
        w.bucket.hold_writes.set(true);
        let mut upload = pin!(relay.deposit(sealed(1), BURN, Lifetime::ONE_HOUR, None));
        assert!(poll_once(upload.as_mut()).is_pending(), "reserved, the write in flight");
        w.advance(RESERVATION_SECONDS);
        w.cron(&relay);
        // The write lands after the collector forgot the name.
        w.bucket.hold_writes.set(false);
        assert_eq!(finish(upload.as_mut()), Err(CustodyError::VaultUnavailable));
        assert_eq!(w.bucket.bucket.len(), 0, "refused, so deleted at once");
        w.assert_empty();
    }

    #[test]
    fn a_chunk_that_lands_after_the_cron_collected_its_reservation_is_never_filed() {
        let w = World::default();
        let relay = w.relay();
        let count = ChunkCount::new(1).unwrap();
        let id = block_on(relay.deposit_file(sealed(1), count, KEEP, Lifetime::ONE_DAY, None)).unwrap().id;
        w.bucket.hold_writes.set(true);
        let mut upload = pin!(relay.put_chunk(&id, at(0), chunk(10, MIN_CHUNK_LEN)));
        assert!(poll_once(upload.as_mut()).is_pending());
        w.advance(RESERVATION_SECONDS);
        w.cron(&relay);
        w.bucket.hold_writes.set(false);
        assert_eq!(finish(upload.as_mut()), Err(CustodyError::NotFound));
        assert!(!w.holds(chunk(10, MIN_CHUNK_LEN).as_bytes()));
        w.assert_empty();
    }

    #[test]
    fn two_answers_uploading_at_once_consume_the_request_once() {
        let w = World::default();
        let relay = w.relay();
        let key = RecipientKeyBlob::new(vec![7; RecipientKeyBlob::LEN]).unwrap();
        let request = block_on(relay.post_request(key, Lifetime::ONE_HOUR)).unwrap();
        let answer = |tag| Answer { payload: sealed(tag), retention: BURN, lifetime: Lifetime::ONE_HOUR, chunks: None };
        w.bucket.hold_writes.set(true);
        let mut a = pin!(relay.answer_request(request.id, answer(2)));
        let mut b = pin!(relay.answer_request(request.id, answer(3)));
        assert!(poll_once(a.as_mut()).is_pending());
        assert!(poll_once(b.as_mut()).is_pending());
        w.bucket.hold_writes.set(false);
        assert_eq!(finish(a.as_mut()).unwrap().id, request.inbox);
        assert_eq!(finish(b.as_mut()), Err(CustodyError::NotFound));
        assert!(!w.holds(sealed(3).as_bytes()), "the losing answer left the bucket");
        assert_eq!(block_on(relay.open(&request.inbox)).unwrap().payload, sealed(2));
        w.assert_empty();
    }
}

mod settling {
    use super::*;
    use custody::{ClaimDigest, Vault};

    fn claim() -> ClaimDigest {
        ClaimDigest::from_array([9; 32])
    }

    #[test]
    fn a_burned_secret_is_handed_out_before_the_bucket_deletes_it() {
        let w = World::default();
        let id = deposit(&w.relay(), BURN, Lifetime::ONE_HOUR);
        let vault = w.vault();
        w.bucket.hold_deletes.set(true);
        let claim = claim();
        let mut open = pin!(vault.open(&id, &claim));
        // The reply does not wait for the deletion, which is still to come.
        let Poll::Ready(Ok(Some(opened))) = poll_once(open.as_mut()) else { panic!("the open waited for the bucket") };
        assert_eq!(opened.payload, sealed(1));
        assert!(w.holds(sealed(1).as_bytes()), "not deleted yet");
        assert_eq!(block_on(vault.open(&id, &claim)), Ok(None), "but burned already");
        let mut settle = pin!(vault.settle());
        assert!(poll_once(settle.as_mut()).is_pending(), "settling deletes it");
        w.bucket.hold_deletes.set(false);
        finish(settle.as_mut());
        assert!(!w.holds(sealed(1).as_bytes()));
        assert_eq!(w.vault().ledger().usage_now(w.clock.now()).unwrap().object_bytes, 0, "and forgets it");
        w.assert_empty();
    }

    #[test]
    fn a_vault_that_stops_before_settling_leaves_the_burn_to_the_cron() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit(&relay, BURN, Lifetime::ONE_HOUR);
        // The object restarts right after its reply: nothing settles.
        assert!(block_on(w.vault().open(&id, &claim())).unwrap().is_some());
        assert!(w.holds(sealed(1).as_bytes()));
        assert_eq!(block_on(relay.open(&id)), Err(CustodyError::NotFound));
        w.advance(GARBAGE_GRACE_SECONDS);
        w.cron(&relay);
        assert!(!w.holds(sealed(1).as_bytes()), "the collector took it");
        w.assert_empty();
    }

    #[test]
    fn settling_twice_or_with_nothing_burned_does_nothing() {
        let w = World::default();
        let relay = w.relay();
        let id = deposit(&relay, KEEP, Lifetime::ONE_HOUR);
        let vault = w.vault();
        block_on(vault.settle());
        assert!(block_on(vault.open(&id, &claim())).unwrap().is_some());
        block_on(vault.settle());
        assert!(w.holds(sealed(1).as_bytes()), "kept until expiry");
        w.assert_empty();
    }
}
