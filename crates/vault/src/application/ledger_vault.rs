//! The vault inside the Durable Object: the [`Ledger`] keeps the records,
//! the [`PayloadStore`] the sealed payloads. Every read of a payload happens
//! between two steps of the ledger (find, read, commit), so a failing object
//! store loses nothing and two concurrent reads never both burn.

use core::slice;

use custody::{
    ChunkIndex, ChunkRef, ClaimDigest, CustodyError, Deposit, DropId, IdSource, ObjectName, Opened, PostedRequest,
    Receipt, Request, RevocationDigest, UnixTime, Vault,
};

use super::ledger::{Entry, Ledger, NewRequest};
use super::ports::{Clock, KeyValue, PayloadStore};
use crate::core::Stored;

/// Purge batches one call runs at most.
const PURGE_BATCHES: usize = 10;

#[derive(Debug)]
pub struct LedgerVault<K, P, I, C> {
    ledger: Ledger<K>,
    payloads: P,
    ids: I,
    clock: C,
}

impl<K: KeyValue, P: PayloadStore, I: IdSource, C: Clock> LedgerVault<K, P, I, C> {
    pub fn new(kv: K, payloads: P, ids: I, clock: C) -> Self {
        Self { ledger: Ledger::new(kv), payloads, ids, clock }
    }

    pub fn ledger(&self) -> &Ledger<K> {
        &self.ledger
    }

    fn now(&self) -> UnixTime {
        self.clock.now()
    }

    /// Stores the payload under a fresh name, then has `record` file it.
    /// Unless it is filed (`Ok(Some(_))`), the payload leaves the store again.
    async fn store_then<T>(
        &self,
        deposit: &Deposit,
        record: impl FnOnce(&Entry) -> Result<Option<T>, CustodyError>,
    ) -> Result<Option<T>, CustodyError> {
        let len = deposit.payload.as_bytes().len() as u32;
        // Refuse before a byte is written when there is no room.
        self.ledger.check_room(self.now(), u64::from(len), 1)?;
        let object = self.ids.fresh_object()?;
        self.payloads.put(&object, &deposit.payload).await?;
        let entry = Entry {
            id: deposit.id,
            payload: Stored { object, len },
            retention: deposit.retention,
            lifetime: deposit.lifetime,
            revocation: deposit.revocation,
            chunks: deposit.chunks,
        };
        let recorded = record(&entry);
        if !matches!(recorded, Ok(Some(_))) {
            // Never filed: nothing will ever look for it. A failed delete
            // leaves it to the bucket's lifecycle rule.
            let _ = self.payloads.delete(slice::from_ref(&object)).await;
        }
        recorded
    }

    /// Deletes objects whose records are gone, and forgets them once the
    /// store did; if it fails they wait in the garbage for the collector.
    async fn discard(&self, objects: &[ObjectName]) {
        if self.payloads.delete(objects).await.is_ok() {
            let _ = self.ledger.forget_garbage(self.now(), objects);
        }
    }
}

impl<K: KeyValue, P: PayloadStore, I: IdSource, C: Clock> Vault for LedgerVault<K, P, I, C> {
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError> {
        let filed = self.store_then(deposit, |entry| self.ledger.deposit(self.now(), entry).map(Some)).await?;
        filed.ok_or(CustodyError::VaultUnavailable)
    }

    async fn open(&self, id: &DropId, claim: &ClaimDigest) -> Result<Option<Opened>, CustodyError> {
        let Some(found) = self.ledger.find(self.now(), id)? else { return Ok(None) };
        // Read first, burn after: if the store fails, the deposit is still there.
        let Some(payload) = self.payloads.get(&found.payload.object).await? else { return Ok(None) };
        let Some(committed) = self.ledger.commit_open(self.now(), id, &found.payload.object, claim)? else {
            // Another read burned or claimed it meanwhile; only that one counts.
            return Ok(None);
        };
        if let Some(object) = committed.discard {
            self.discard(slice::from_ref(&object)).await;
        }
        Ok(Some(Opened { payload, burned: committed.burned, chunks: committed.chunks, claim: None }))
    }

    async fn reserve_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        self.ledger.reserve_chunk(self.now(), id, index, object, len)
    }

    async fn put_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        self.ledger.put_chunk(self.now(), id, index, object, len)
    }

    async fn open_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimDigest>,
    ) -> Result<Option<ChunkRef>, CustodyError> {
        self.ledger.open_chunk(self.now(), id, index, claim)
    }

    async fn burn_chunk(&self, id: &DropId, index: ChunkIndex, claim: &ClaimDigest) -> Result<bool, CustodyError> {
        self.ledger.burn_chunk(self.now(), id, index, claim)
    }

    async fn garbage(&self, limit: u16) -> Result<Vec<ObjectName>, CustodyError> {
        self.ledger.garbage(self.now(), limit)
    }

    async fn forget_garbage(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        self.ledger.forget_garbage(self.now(), objects)
    }

    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<Option<Vec<ObjectName>>, CustodyError> {
        self.ledger.revoke(self.now(), id, digest)
    }

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError> {
        let request = NewRequest {
            id: request.id,
            inbox: request.inbox,
            recipient_key: request.recipient_key.clone(),
            lifetime: request.lifetime,
        };
        self.ledger.post_request(self.now(), &request)
    }

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError> {
        self.ledger.fetch_request(self.now(), id)
    }

    async fn answer_request(&self, answer: &Deposit) -> Result<Option<Receipt>, CustodyError> {
        // No request, nothing to store (the ledger checks again, atomically).
        if self.ledger.fetch_request(self.now(), &answer.id)?.is_none() {
            return Ok(None);
        }
        self.store_then(answer, |entry| self.ledger.answer_request(self.now(), entry)).await
    }

    async fn purge_expired(&self) -> Result<u64, CustodyError> {
        let mut gone = 0;
        for _ in 0..PURGE_BATCHES {
            let (batch, more) = self.ledger.purge_batch(self.now())?;
            gone += batch;
            if !more {
                break;
            }
        }
        Ok(gone)
    }
}
