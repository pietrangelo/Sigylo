//! In-memory stand-ins for the ports, with a hand-driven clock and switches
//! that make them fail, used to test the vault.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::collections::{BTreeMap, HashMap};

use custody::{
    ChunkStore, ClaimDigest, ClaimToken, CustodyError, DropId, IdSource, ObjectName, RevocationDigest, RevocationToken,
    SealedChunk, SealedPayload, TokenDigest, UnixTime, Vault,
};

use super::accounts::AccountLedger;
use super::ports::{Clock, KeyValue, Link, PayloadStore};
use super::remote::serve;
use super::remote_accounts::serve_accounts;

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

/// An ordered map with transactions, like a Durable Object's storage.
#[derive(Debug, Default)]
pub struct MemoryKv {
    map: RefCell<BTreeMap<String, Vec<u8>>>,
    /// Fails the n-th write from now (1 = the next one), as a crash would.
    pub fail_write: Cell<u32>,
    /// Every read and write fails.
    pub down: Cell<bool>,
    /// Writes since the start.
    pub writes: Cell<u64>,
}

impl MemoryKv {
    pub fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        self.map.borrow().clone()
    }

    pub fn keys(&self) -> Vec<String> {
        self.map.borrow().keys().cloned().collect()
    }

    /// Overwrites a value, as damage on disk would.
    pub fn tamper(&self, key: &str, value: Vec<u8>) {
        self.map.borrow_mut().insert(key.to_string(), value);
    }

    fn check(&self) -> Result<(), CustodyError> {
        if self.down.get() { Err(CustodyError::VaultUnavailable) } else { Ok(()) }
    }

    fn write(&self) -> Result<(), CustodyError> {
        self.check()?;
        self.writes.set(self.writes.get() + 1);
        match self.fail_write.get() {
            0 => Ok(()),
            1 => {
                self.fail_write.set(0);
                Err(CustodyError::VaultUnavailable)
            }
            n => {
                self.fail_write.set(n - 1);
                Ok(())
            }
        }
    }
}

impl KeyValue for MemoryKv {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CustodyError> {
        self.check()?;
        Ok(self.map.borrow().get(key).cloned())
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), CustodyError> {
        self.write()?;
        self.map.borrow_mut().insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), CustodyError> {
        self.write()?;
        self.map.borrow_mut().remove(key);
        Ok(())
    }

    fn range(&self, start: &str, end: &str, limit: usize) -> Result<Vec<(String, Vec<u8>)>, CustodyError> {
        self.check()?;
        let map = self.map.borrow();
        let range = map.range::<str, _>((core::ops::Bound::Included(start), core::ops::Bound::Excluded(end)));
        Ok(range.take(limit).map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn atomically<T>(&self, step: impl FnOnce() -> Result<T, CustodyError>) -> Result<T, CustodyError> {
        let before = self.snapshot();
        let out = step();
        if out.is_err() {
            *self.map.borrow_mut() = before;
        }
        out
    }
}

/// One bucket for payloads and chunks, as R2 is.
#[derive(Debug, Default)]
pub struct MemoryBucket {
    objects: RefCell<HashMap<ObjectName, Vec<u8>>>,
    pub fail: Cell<bool>,
    /// Only reads fail.
    pub fail_reads: Cell<bool>,
    /// Only deletions fail.
    pub fail_deletes: Cell<bool>,
}

impl MemoryBucket {
    pub fn len(&self) -> usize {
        self.objects.borrow().len()
    }

    pub fn names(&self) -> Vec<ObjectName> {
        self.objects.borrow().keys().copied().collect()
    }

    pub fn holds(&self, bytes: &[u8]) -> bool {
        self.objects.borrow().values().any(|v| v == bytes)
    }

    fn check(&self) -> Result<(), CustodyError> {
        if self.fail.get() { Err(CustodyError::VaultUnavailable) } else { Ok(()) }
    }

    fn store(&self, object: &ObjectName, bytes: &[u8]) -> Result<(), CustodyError> {
        self.check()?;
        self.objects.borrow_mut().insert(*object, bytes.to_vec());
        Ok(())
    }

    fn fetch(&self, object: &ObjectName) -> Result<Option<Vec<u8>>, CustodyError> {
        self.check()?;
        if self.fail_reads.get() {
            return Err(CustodyError::VaultUnavailable);
        }
        Ok(self.objects.borrow().get(object).cloned())
    }

    fn remove(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        self.check()?;
        if self.fail_deletes.get() {
            return Err(CustodyError::VaultUnavailable);
        }
        let mut stored = self.objects.borrow_mut();
        for object in objects {
            stored.remove(object);
        }
        Ok(())
    }
}

impl PayloadStore for MemoryBucket {
    async fn put(&self, object: &ObjectName, payload: &SealedPayload) -> Result<(), CustodyError> {
        self.store(object, payload.as_bytes())
    }

    async fn get(&self, object: &ObjectName) -> Result<Option<SealedPayload>, CustodyError> {
        self.fetch(object)?.map(SealedPayload::new).transpose()
    }

    async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        self.remove(objects)
    }
}

impl ChunkStore for &MemoryBucket {
    async fn put(&self, object: &ObjectName, chunk: &SealedChunk) -> Result<(), CustodyError> {
        self.store(object, chunk.as_bytes())
    }

    async fn get(&self, object: &ObjectName) -> Result<Option<SealedChunk>, CustodyError> {
        self.fetch(object)?.map(SealedChunk::new).transpose()
    }

    async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        self.remove(objects)
    }
}

#[derive(Debug)]
pub struct ManualClock(pub Cell<i64>);

impl Default for ManualClock {
    fn default() -> Self {
        Self(Cell::new(1_800_000_000))
    }
}

impl ManualClock {
    pub fn advance(&self, seconds: i64) {
        self.0.set(self.0.get() + seconds);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> UnixTime {
        UnixTime(self.0.get())
    }
}

/// Distinct, predictable ids, claims and object names.
#[derive(Debug, Default)]
pub struct SequentialIds(Cell<u32>);

impl SequentialIds {
    fn next(&self) -> [u8; 16] {
        let n = self.0.get() + 1;
        self.0.set(n);
        let mut bytes = [0x5E; 16];
        bytes[12..].copy_from_slice(&n.to_be_bytes());
        bytes
    }
}

impl IdSource for &SequentialIds {
    fn fresh(&self) -> Result<DropId, CustodyError> {
        DropId::from_slice(&self.next())
    }

    fn fresh_claim(&self) -> Result<ClaimToken, CustodyError> {
        let mut claim = [0xC1; 32];
        claim[..16].copy_from_slice(&self.next());
        Ok(ClaimToken::from_array(claim))
    }

    fn fresh_object(&self) -> Result<ObjectName, CustodyError> {
        let mut name = self.next();
        name[0] = 0xB0;
        Ok(ObjectName::from_array(name))
    }
}

/// Reverses and tags the token: one-way enough to show the vault never sees it.
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

/// Carries calls straight to [`serve`], as the Durable Object would, and
/// counts them: each one is a request the Durable Object bills.
#[derive(Debug)]
pub struct Loopback<V> {
    pub vault: V,
    pub calls: Cell<u32>,
    /// Replaces every reply, as a broken link would.
    pub garble: RefCell<Option<Vec<u8>>>,
}

impl<V> Loopback<V> {
    pub fn new(vault: V) -> Self {
        Self { vault, calls: Cell::new(0), garble: RefCell::new(None) }
    }
}

impl<V: Vault> Link for Loopback<V> {
    async fn call(&self, call: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        self.calls.set(self.calls.get() + 1);
        let reply = serve(&self.vault, &call).await;
        Ok(self.garble.borrow().clone().unwrap_or(reply))
    }
}

/// Carries account calls straight to [`serve_accounts`], as the accounts
/// object would, and counts them: each one is a request it bills.
#[derive(Debug)]
pub struct AccountLoopback<'s, K, C> {
    pub ledger: AccountLedger<'s, K, C>,
    pub calls: Cell<u32>,
    /// Replaces every reply, as a broken link would.
    pub garble: RefCell<Option<Vec<u8>>>,
    /// Every call fails on the way, as a fetch that never arrives.
    pub cut: Cell<bool>,
}

impl<'s, K, C> AccountLoopback<'s, K, C> {
    pub fn new(ledger: AccountLedger<'s, K, C>) -> Self {
        Self { ledger, calls: Cell::new(0), garble: RefCell::new(None), cut: Cell::new(false) }
    }
}

impl<K: KeyValue, C: Clock> Link for AccountLoopback<'_, K, C> {
    async fn call(&self, call: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        if self.cut.get() {
            return Err(CustodyError::VaultUnavailable);
        }
        self.calls.set(self.calls.get() + 1);
        let reply = serve_accounts(&self.ledger, &call);
        Ok(self.garble.borrow().clone().unwrap_or(reply))
    }
}

impl MemoryKv {
    /// A raw value, read without the ledger.
    pub fn get_record(&self, key: &str) -> Option<Vec<u8>> {
        self.map.borrow().get(key).cloned()
    }
}
