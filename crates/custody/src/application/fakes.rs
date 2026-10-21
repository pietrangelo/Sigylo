//! A reference in-memory vault with a hand-driven clock, used to test the use
//! cases. Single-threaded by construction, so atomicity is trivial here; the
//! vault's ledger keeps it with one transaction per step.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::collections::HashMap;

use super::ports::{ChunkStore, IdSource, TokenDigest, Vault};
use crate::core::{
    CLAIM_WINDOW_SECONDS, ChunkIndex, ChunkRef, ClaimDigest, ClaimToken, CustodyError, Deposit, DropId,
    GARBAGE_GRACE_SECONDS, ObjectName, Opened, PostedRequest, RESERVATION_FRESH_SECONDS, RESERVATION_SECONDS, Receipt,
    Request, Retention, RevocationDigest, RevocationToken, SealedChunk, UnixTime,
};

/// Drive a future that never actually waits (all fakes complete immediately).
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

#[derive(Debug, Default)]
pub struct FakeVault {
    pub now: Cell<i64>,
    deposits: RefCell<HashMap<DropId, (Deposit, i64)>>,
    claims: RefCell<HashMap<DropId, ClaimDigest>>,
    chunks: RefCell<HashMap<(DropId, ChunkIndex), ObjectName>>,
    /// Object names and when they are due for collection.
    garbage: RefCell<Vec<(ObjectName, i64)>>,
    requests: RefCell<HashMap<DropId, (Request, i64)>>,
    /// The chunk store that goes with this vault.
    pub store: FakeStore,
    /// Makes every new chunk outgrow the quota.
    pub full: Cell<bool>,
    /// Makes recording a stored chunk fail, as a lost connection would.
    pub unreachable_on_record: Cell<bool>,
}

impl FakeVault {
    pub fn advance(&self, seconds: i64) {
        self.now.set(self.now.get() + seconds);
    }

    pub fn is_empty(&self) -> bool {
        self.deposits.borrow().is_empty() && self.requests.borrow().is_empty() && self.chunks.borrow().is_empty()
    }

    pub fn stored_digest(&self, id: &DropId) -> Option<RevocationDigest> {
        self.deposits.borrow().get(id).and_then(|(d, _)| d.revocation)
    }

    pub fn stored_claim(&self, id: &DropId) -> Option<ClaimDigest> {
        self.claims.borrow().get(id).copied()
    }

    pub fn expires_at(&self, id: &DropId) -> Option<i64> {
        self.deposits.borrow().get(id).map(|(_, exp)| *exp)
    }

    pub fn stored_chunks(&self) -> usize {
        self.chunks.borrow().len()
    }

    pub fn garbage(&self) -> usize {
        self.garbage.borrow().len()
    }

    /// Puts `n` objects in the garbage, due now.
    pub fn add_garbage(&self, n: u16) {
        let now = self.now.get();
        let mut garbage = self.garbage.borrow_mut();
        for i in 0..n {
            let mut name = [0xE0; ObjectName::LEN];
            name[..2].copy_from_slice(&i.to_be_bytes());
            garbage.push((ObjectName::from_array(name), now));
        }
    }

    /// Drops chunk records, their objects joining the garbage (as the vault's ledger does).
    fn drop_chunks(&self, keep: impl Fn(&(DropId, ChunkIndex)) -> bool) {
        let due = self.now.get() + i64::from(GARBAGE_GRACE_SECONDS);
        let mut garbage = self.garbage.borrow_mut();
        self.chunks.borrow_mut().retain(|key, object| {
            let kept = keep(key);
            if !kept {
                garbage.push((*object, due));
            }
            kept
        });
    }

    fn takes(&self, id: &DropId, index: ChunkIndex, len: u32) -> bool {
        self.live(&self.deposits, id)
            && self.stored_claim(id).is_none()
            && self.deposits.borrow()[id].0.chunks.is_some_and(|count| count.takes(index, len as usize))
            && !self.chunks.borrow().contains_key(&(*id, index))
    }

    fn live<T>(&self, map: &RefCell<HashMap<DropId, (T, i64)>>, id: &DropId) -> bool {
        map.borrow().get(id).is_some_and(|(_, exp)| *exp > self.now.get())
    }

    fn chunks_of(&self, id: &DropId) -> u16 {
        self.chunks.borrow().keys().filter(|(owner, _)| owner == id).count() as u16
    }

    fn complete(&self, deposit: &Deposit) -> bool {
        self.chunks_of(&deposit.id) == deposit.chunks.map_or(0, |c| c.get())
    }

    /// Removes a deposit with everything hanging off it (as the vault's ledger does).
    fn remove_deposit(&self, id: &DropId) -> Option<Deposit> {
        self.claims.borrow_mut().remove(id);
        self.drop_chunks(|(owner, _)| owner != id);
        self.deposits.borrow_mut().remove(id).map(|(d, _)| d)
    }

    fn insert_deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError> {
        if self.live(&self.deposits, &deposit.id) {
            return Err(CustodyError::AlreadyExists);
        }
        self.remove_deposit(&deposit.id);
        let expires = self.now.get() + i64::from(deposit.lifetime.seconds());
        self.deposits.borrow_mut().insert(deposit.id, (deposit.clone(), expires));
        Ok(UnixTime(expires))
    }
}

impl Vault for &FakeVault {
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError> {
        self.insert_deposit(deposit)
    }

    async fn open(&self, id: &DropId, claim: &ClaimDigest) -> Result<Option<Opened>, CustodyError> {
        if !self.live(&self.deposits, id) || self.stored_claim(id).is_some() {
            return Ok(None);
        }
        let deposit = self.deposits.borrow()[id].0.clone();
        if !self.complete(&deposit) {
            return Ok(None);
        }
        let burn = deposit.retention == Retention::BurnAfterReading;
        match (burn, deposit.chunks) {
            (true, None) => {
                self.remove_deposit(id);
            }
            (true, Some(_)) => {
                self.claims.borrow_mut().insert(*id, *claim);
                let window = self.now.get() + i64::from(CLAIM_WINDOW_SECONDS);
                let mut deposits = self.deposits.borrow_mut();
                let expires = &mut deposits.get_mut(id).unwrap().1;
                *expires = (*expires).min(window);
            }
            (false, _) => {}
        }
        Ok(Some(Opened { payload: deposit.payload, burned: burn, chunks: deposit.chunks, claim: None }))
    }

    async fn reserve_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        if !self.takes(id, index, len) {
            return Ok(false);
        }
        if self.full.get() {
            return Err(CustodyError::StorageFull);
        }
        let due = self.now.get() + i64::from(RESERVATION_SECONDS);
        self.garbage.borrow_mut().push((*object, due));
        Ok(true)
    }

    async fn put_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        if self.unreachable_on_record.get() {
            return Err(CustodyError::VaultUnavailable);
        }
        let fresh = self.now.get() + i64::from(RESERVATION_SECONDS - RESERVATION_FRESH_SECONDS);
        let reserved = self.garbage.borrow().iter().any(|(name, due)| name == object && *due > fresh);
        if !reserved || !self.takes(id, index, len) {
            return Ok(false);
        }
        self.garbage.borrow_mut().retain(|(name, _)| name != object);
        self.chunks.borrow_mut().insert((*id, index), *object);
        Ok(true)
    }

    async fn open_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimDigest>,
    ) -> Result<Option<ChunkRef>, CustodyError> {
        if !self.live(&self.deposits, id) {
            return Ok(None);
        }
        let deposit = self.deposits.borrow()[id].0.clone();
        let burns = deposit.retention == Retention::BurnAfterReading;
        let allowed =
            if burns { claim.is_some() && self.stored_claim(id).as_ref() == claim } else { self.complete(&deposit) };
        let object = self.chunks.borrow().get(&(*id, index)).copied().filter(|_| allowed);
        Ok(object.map(|object| ChunkRef { object, burns }))
    }

    async fn burn_chunk(&self, id: &DropId, index: ChunkIndex, claim: &ClaimDigest) -> Result<bool, CustodyError> {
        if !self.live(&self.deposits, id) || self.stored_claim(id).as_ref() != Some(claim) {
            return Ok(false);
        }
        if !self.chunks.borrow().contains_key(&(*id, index)) {
            return Ok(false);
        }
        self.drop_chunks(|key| *key != (*id, index));
        if self.chunks_of(id) == 0 {
            self.remove_deposit(id);
        }
        Ok(true)
    }

    async fn garbage(&self, limit: u16) -> Result<Vec<ObjectName>, CustodyError> {
        let now = self.now.get();
        let due =
            self.garbage.borrow().iter().filter(|(_, due)| *due <= now).map(|(name, _)| *name).collect::<Vec<_>>();
        Ok(due.into_iter().take(usize::from(limit)).collect())
    }

    async fn forget_garbage(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        self.garbage.borrow_mut().retain(|(object, _)| !objects.contains(object));
        Ok(())
    }

    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<Option<Vec<ObjectName>>, CustodyError> {
        if !self.live(&self.deposits, id) || self.stored_digest(id) != Some(*digest) {
            return Ok(None);
        }
        let objects =
            self.chunks.borrow().iter().filter(|((owner, _), _)| owner == id).map(|(_, object)| *object).collect();
        self.remove_deposit(id);
        Ok(Some(objects))
    }

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError> {
        if self.live(&self.requests, &request.id) {
            return Err(CustodyError::AlreadyExists);
        }
        let expires = self.now.get() + i64::from(request.lifetime.seconds());
        self.requests.borrow_mut().insert(request.id, (request.clone(), expires));
        Ok(UnixTime(expires))
    }

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError> {
        if !self.live(&self.requests, id) {
            return Ok(None);
        }
        let requests = self.requests.borrow();
        let (request, expires) = &requests[id];
        Ok(Some(PostedRequest { recipient_key: request.recipient_key.clone(), expires_at: UnixTime(*expires) }))
    }

    async fn answer_request(&self, answer: &Deposit) -> Result<Option<Receipt>, CustodyError> {
        if !self.live(&self.requests, &answer.id) {
            return Ok(None);
        }
        let inbox = self.requests.borrow()[&answer.id].0.inbox;
        let expires_at = self.insert_deposit(&Deposit { id: inbox, ..answer.clone() })?;
        self.requests.borrow_mut().remove(&answer.id);
        Ok(Some(Receipt { id: inbox, expires_at }))
    }

    async fn purge_expired(&self) -> Result<u64, CustodyError> {
        let now = self.now.get();
        let before = self.deposits.borrow().len() + self.requests.borrow().len();
        let expired: Vec<DropId> =
            self.deposits.borrow().iter().filter(|(_, (_, exp))| *exp <= now).map(|(id, _)| *id).collect();
        for id in expired {
            self.remove_deposit(&id);
        }
        self.requests.borrow_mut().retain(|_, (_, exp)| *exp > now);
        Ok((before - self.deposits.borrow().len() - self.requests.borrow().len()) as u64)
    }
}

/// An in-memory chunk store that can be told to fail.
#[derive(Debug, Default)]
pub struct FakeStore {
    objects: RefCell<HashMap<ObjectName, SealedChunk>>,
    pub fail: Cell<bool>,
    /// How many writes reached the store, each a billed operation in R2.
    pub puts: Cell<usize>,
}

impl FakeStore {
    pub fn objects(&self) -> usize {
        self.objects.borrow().len()
    }

    pub fn names(&self) -> Vec<ObjectName> {
        self.objects.borrow().keys().copied().collect()
    }

    pub fn contents(&self) -> Vec<SealedChunk> {
        self.objects.borrow().values().cloned().collect()
    }

    fn check(&self) -> Result<(), CustodyError> {
        if self.fail.get() { Err(CustodyError::VaultUnavailable) } else { Ok(()) }
    }
}

impl ChunkStore for &FakeStore {
    async fn put(&self, object: &ObjectName, chunk: &SealedChunk) -> Result<(), CustodyError> {
        self.check()?;
        self.puts.set(self.puts.get() + 1);
        self.objects.borrow_mut().insert(*object, chunk.clone());
        Ok(())
    }

    async fn get(&self, object: &ObjectName) -> Result<Option<SealedChunk>, CustodyError> {
        self.check()?;
        Ok(self.objects.borrow().get(object).cloned())
    }

    async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        self.check()?;
        let mut stored = self.objects.borrow_mut();
        for object in objects {
            stored.remove(object);
        }
        Ok(())
    }
}

/// Reverses and tags the token: obviously not a hash, but one-way enough to
/// show that the vault never sees the token itself.
#[derive(Debug)]
pub struct ToyDigest;

impl TokenDigest for ToyDigest {
    fn digest(&self, token: &RevocationToken) -> RevocationDigest {
        let mut out = *token.expose();
        out.reverse();
        out[0] ^= 0x5A;
        RevocationDigest::from_array(out)
    }

    fn digest_claim(&self, claim: &ClaimToken) -> ClaimDigest {
        let mut out = *claim.expose();
        out.reverse();
        out[0] ^= 0xA5;
        ClaimDigest::from_array(out)
    }
}

/// Hands out ids `[1; 16]`, `[2; 16]`, …, claims `[1; 32]`, `[2; 32]`, … and
/// object names `[0xB0, 1, 1, …]`, `[0xB0, 2, 2, …]`, …: distinct and
/// predictable, for tests.
#[derive(Debug)]
pub struct SequentialIds(Cell<u8>, Cell<u8>, Cell<u8>);

impl SequentialIds {
    pub fn starting_at(first: u8) -> Self {
        Self(Cell::new(first), Cell::new(1), Cell::new(1))
    }
}

impl Default for SequentialIds {
    fn default() -> Self {
        Self::starting_at(1)
    }
}

impl IdSource for SequentialIds {
    fn fresh(&self) -> Result<DropId, CustodyError> {
        let n = self.0.get();
        self.0.set(n.wrapping_add(1));
        DropId::from_slice(&[n; DropId::LEN])
    }

    fn fresh_claim(&self) -> Result<ClaimToken, CustodyError> {
        let n = self.1.get();
        self.1.set(n.wrapping_add(1));
        Ok(ClaimToken::from_array([n; 32]))
    }

    fn fresh_object(&self) -> Result<ObjectName, CustodyError> {
        let n = self.2.get();
        self.2.set(n.wrapping_add(1));
        let mut name = [n; ObjectName::LEN];
        name[0] = 0xB0;
        Ok(ObjectName::from_array(name))
    }
}

/// A broken random source that keeps returning the same id.
#[derive(Debug)]
pub struct StuckIds;

impl IdSource for StuckIds {
    fn fresh(&self) -> Result<DropId, CustodyError> {
        DropId::from_slice(&[0xEE; DropId::LEN])
    }

    fn fresh_claim(&self) -> Result<ClaimToken, CustodyError> {
        Ok(ClaimToken::from_array([0xCC; 32]))
    }

    fn fresh_object(&self) -> Result<ObjectName, CustodyError> {
        Ok(ObjectName::from_array([0xDD; ObjectName::LEN]))
    }
}

/// A random source that fails.
#[derive(Debug)]
pub struct BrokenIds;

impl IdSource for BrokenIds {
    fn fresh(&self) -> Result<DropId, CustodyError> {
        Err(CustodyError::RandomnessUnavailable)
    }

    fn fresh_claim(&self) -> Result<ClaimToken, CustodyError> {
        Err(CustodyError::RandomnessUnavailable)
    }

    fn fresh_object(&self) -> Result<ObjectName, CustodyError> {
        Err(CustodyError::RandomnessUnavailable)
    }
}
