//! A reference in-memory vault with a hand-driven clock, used to test the use
//! cases. Single-threaded by construction, so atomicity is trivial here; the
//! Postgres adapter proves it under real concurrency.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::collections::HashMap;

use super::ports::{IdSource, TokenDigest, Vault};
use crate::core::{
    CustodyError, Deposit, DropId, Opened, PostedRequest, Request, Retention, RevocationDigest, RevocationToken,
    UnixTime,
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
    requests: RefCell<HashMap<DropId, (Request, i64)>>,
}

impl FakeVault {
    pub fn advance(&self, seconds: i64) {
        self.now.set(self.now.get() + seconds);
    }

    pub fn is_empty(&self) -> bool {
        self.deposits.borrow().is_empty() && self.requests.borrow().is_empty()
    }

    pub fn stored_digest(&self, id: &DropId) -> Option<RevocationDigest> {
        self.deposits.borrow().get(id).and_then(|(d, _)| d.revocation)
    }

    fn live<T>(&self, map: &RefCell<HashMap<DropId, (T, i64)>>, id: &DropId) -> bool {
        map.borrow().get(id).is_some_and(|(_, exp)| *exp > self.now.get())
    }

    fn insert_deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError> {
        if self.live(&self.deposits, &deposit.id) {
            return Err(CustodyError::AlreadyExists);
        }
        let expires = self.now.get() + i64::from(deposit.lifetime.seconds());
        self.deposits.borrow_mut().insert(deposit.id, (deposit.clone(), expires));
        Ok(UnixTime(expires))
    }
}

impl Vault for &FakeVault {
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError> {
        self.insert_deposit(deposit)
    }

    async fn open(&self, id: &DropId) -> Result<Option<Opened>, CustodyError> {
        if !self.live(&self.deposits, id) {
            return Ok(None);
        }
        let mut deposits = self.deposits.borrow_mut();
        let burn = deposits[id].0.retention == Retention::BurnAfterReading;
        let payload = if burn { deposits.remove(id).unwrap().0.payload } else { deposits[id].0.payload.clone() };
        Ok(Some(Opened { payload, burned: burn }))
    }

    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<bool, CustodyError> {
        if self.live(&self.deposits, id) && self.stored_digest(id) == Some(*digest) {
            self.deposits.borrow_mut().remove(id);
            return Ok(true);
        }
        Ok(false)
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

    async fn answer_request(&self, answer: &Deposit) -> Result<Option<UnixTime>, CustodyError> {
        if !self.live(&self.requests, &answer.id) {
            return Ok(None);
        }
        let expires = self.insert_deposit(answer)?;
        self.requests.borrow_mut().remove(&answer.id);
        Ok(Some(expires))
    }

    async fn purge_expired(&self) -> Result<u64, CustodyError> {
        let now = self.now.get();
        let before = self.deposits.borrow().len() + self.requests.borrow().len();
        self.deposits.borrow_mut().retain(|_, (_, exp)| *exp > now);
        self.requests.borrow_mut().retain(|_, (_, exp)| *exp > now);
        Ok((before - self.deposits.borrow().len() - self.requests.borrow().len()) as u64)
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
}

/// Hands out `[1; 16]`, `[2; 16]`, …: distinct and predictable, for tests.
#[derive(Debug)]
pub struct SequentialIds(Cell<u8>);

impl SequentialIds {
    pub fn starting_at(first: u8) -> Self {
        Self(Cell::new(first))
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
}

/// A broken random source that keeps returning the same id.
#[derive(Debug)]
pub struct StuckIds;

impl IdSource for StuckIds {
    fn fresh(&self) -> Result<DropId, CustodyError> {
        DropId::from_slice(&[0xEE; DropId::LEN])
    }
}

/// A random source that fails.
#[derive(Debug)]
pub struct BrokenIds;

impl IdSource for BrokenIds {
    fn fresh(&self) -> Result<DropId, CustodyError> {
        Err(CustodyError::RandomnessUnavailable)
    }
}
