//! Deterministic stand-ins for the ports. They are NOT secure; they let the
//! use cases be tested without any crypto library or database. The toy
//! OPAQUE keeps the one property the use cases rely on: only the password
//! used at registration opens the relay's answer at login.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::collections::HashMap;

use super::ports::{
    AccountStore, KeyringKdf, KeyringWrite, OpaqueClient, OpaqueServer, SessionDigester, Throttle, Tokens,
};
use crate::core::{
    AccessError, AccountId, CredentialFinalization, CredentialRequest, CredentialResponse, ExportKey, Keyring,
    KeyringKey, KeyringSnapshot, KeyringVersion, LoginHandle, LoginState, Password, RegistrationRecord,
    RegistrationRequest, RegistrationResponse, SessionDigest, SessionToken, UnixTime, Username,
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

fn fnv(parts: &[&[u8]], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = 0xcbf2_9ce4_8422_2325u64 ^ i as u64;
        for part in parts {
            for &b in *part {
                h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01B3);
            }
            h = (h ^ 0xFF).wrapping_mul(0x0000_0100_0000_01B3);
        }
        chunk.copy_from_slice(&h.to_le_bytes()[..chunk.len()]);
    }
    out
}

/// Both halves of a toy OPAQUE.
#[derive(Debug, Default)]
pub struct ToyOpaque {
    counter: Cell<u8>,
}

impl ToyOpaque {
    fn oprf(account: &AccountId, blinded: &[u8]) -> Vec<u8> {
        fnv(&[b"oprf", account.as_bytes(), blinded], 64)
    }

    fn record(password: &Password, oprf: &[u8]) -> Vec<u8> {
        fnv(&[b"record", password.expose(), oprf], RegistrationRecord::LEN)
    }

    fn export(password: &Password, oprf: &[u8]) -> ExportKey {
        ExportKey::from_slice(&fnv(&[b"export", password.expose(), oprf], ExportKey::LEN)).unwrap()
    }

    fn mac(record: &[u8]) -> Vec<u8> {
        fnv(&[b"mac", record], CredentialFinalization::LEN)
    }
}

impl OpaqueServer for ToyOpaque {
    fn account_of(&self, username: &Username) -> AccountId {
        AccountId::from_slice(&fnv(&[b"account", username.as_bytes()], 32)).unwrap()
    }

    fn registration_response(
        &self,
        account: &AccountId,
        request: &RegistrationRequest,
    ) -> Result<RegistrationResponse, AccessError> {
        RegistrationResponse::from_slice(&Self::oprf(account, request.as_bytes()))
    }

    fn begin_login(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        request: &CredentialRequest,
    ) -> Result<(CredentialResponse, LoginState), AccessError> {
        let record = match record {
            Some(r) => r.as_bytes().to_vec(),
            None => fnv(&[b"fake", account.as_bytes()], RegistrationRecord::LEN),
        };
        let mut response = Self::oprf(account, &request.as_bytes()[..32]);
        response.extend_from_slice(&record);
        response.resize(CredentialResponse::LEN, 0);
        let mut state = Self::mac(&record);
        state.resize(LoginState::LEN, 0);
        Ok((CredentialResponse::from_slice(&response)?, LoginState::from_slice(&state)?))
    }

    fn finish_login(&self, state: &LoginState, finalization: &CredentialFinalization) -> Result<(), AccessError> {
        if state.expose()[..64] == *finalization.as_bytes() { Ok(()) } else { Err(AccessError::NotAuthentic) }
    }
}

impl OpaqueClient for ToyOpaque {
    type Registration = Vec<u8>;
    type Login = Vec<u8>;

    fn begin_registration(&self, password: &Password) -> Result<(RegistrationRequest, Vec<u8>), AccessError> {
        let blinded = fnv(&[b"blind", password.expose()], 32);
        Ok((RegistrationRequest::from_slice(&blinded)?, blinded))
    }

    fn finish_registration(
        &self,
        _state: Vec<u8>,
        password: &Password,
        response: &RegistrationResponse,
    ) -> Result<(RegistrationRecord, ExportKey), AccessError> {
        let oprf = response.as_bytes();
        Ok((RegistrationRecord::from_slice(&Self::record(password, oprf))?, Self::export(password, oprf)))
    }

    fn begin_login(&self, password: &Password) -> Result<(CredentialRequest, Vec<u8>), AccessError> {
        self.counter.set(self.counter.get().wrapping_add(1));
        let mut request = fnv(&[b"blind", password.expose()], 32);
        request.extend_from_slice(&[self.counter.get(); 64]);
        Ok((CredentialRequest::from_slice(&request)?, request))
    }

    fn finish_login(
        &self,
        _state: Vec<u8>,
        password: &Password,
        response: &CredentialResponse,
    ) -> Result<(CredentialFinalization, ExportKey), AccessError> {
        let oprf = &response.as_bytes()[..64];
        let record = &response.as_bytes()[64..64 + RegistrationRecord::LEN];
        if Self::record(password, oprf) != record {
            return Err(AccessError::NotAuthentic);
        }
        Ok((CredentialFinalization::from_slice(&Self::mac(record))?, Self::export(password, oprf)))
    }
}

#[derive(Debug)]
pub struct ToyKdf;

impl KeyringKdf for ToyKdf {
    fn derive(&self, export_key: &ExportKey, info: &[u8]) -> KeyringKey {
        KeyringKey::from_slice(&fnv(&[export_key.expose(), info], KeyringKey::LEN)).unwrap()
    }
}

#[derive(Debug)]
pub struct ToyDigest;

impl SessionDigester for ToyDigest {
    fn digest(&self, token: &SessionToken) -> SessionDigest {
        SessionDigest::from_array(fnv(&[b"digest", token.expose()], 32).try_into().unwrap())
    }
}

#[derive(Debug, Default)]
pub struct SequentialTokens {
    counter: Cell<u8>,
    pub broken: Cell<bool>,
}

impl SequentialTokens {
    fn next<const N: usize>(&self) -> Result<[u8; N], AccessError> {
        if self.broken.get() {
            return Err(AccessError::RandomnessUnavailable);
        }
        self.counter.set(self.counter.get() + 1);
        Ok([self.counter.get(); N])
    }
}

impl Tokens for SequentialTokens {
    fn session(&self) -> Result<SessionToken, AccessError> {
        Ok(SessionToken::from_array(self.next()?))
    }

    fn login_handle(&self) -> Result<LoginHandle, AccessError> {
        Ok(LoginHandle::from_array(self.next()?))
    }
}

/// Admits `budget` logins, then refuses.
#[derive(Debug)]
pub struct CountingThrottle {
    pub budget: Cell<u32>,
}

impl Default for CountingThrottle {
    fn default() -> Self {
        Self { budget: Cell::new(u32::MAX) }
    }
}

impl Throttle for CountingThrottle {
    async fn admit(&self, _account: &AccountId) -> bool {
        let left = self.budget.get();
        self.budget.set(left.saturating_sub(1));
        left > 0
    }
}

#[derive(Debug, Clone)]
struct Account {
    record: RegistrationRecord,
    keyring: Option<Keyring>,
    version: u64,
}

/// A reference in-memory store with a hand-driven clock.
#[derive(Debug, Default)]
pub struct FakeStore {
    pub now: Cell<i64>,
    pub broken: Cell<bool>,
    accounts: RefCell<HashMap<AccountId, Account>>,
    logins: RefCell<HashMap<[u8; LoginHandle::LEN], (AccountId, LoginState, i64)>>,
    pub sessions: RefCell<HashMap<SessionDigest, (AccountId, i64)>>,
}

impl FakeStore {
    pub fn advance(&self, seconds: u32) {
        self.now.set(self.now.get() + i64::from(seconds));
    }

    pub fn account_count(&self) -> usize {
        self.accounts.borrow().len()
    }

    pub fn parked_logins(&self) -> usize {
        self.logins.borrow().len()
    }

    fn up(&self) -> Result<(), AccessError> {
        if self.broken.get() { Err(AccessError::StoreUnavailable) } else { Ok(()) }
    }

    fn session(&self, digest: &SessionDigest) -> Option<AccountId> {
        let sessions = self.sessions.borrow();
        let (account, expires) = sessions.get(digest)?;
        (*expires > self.now.get() && self.accounts.borrow().contains_key(account)).then_some(*account)
    }
}

impl AccountStore for FakeStore {
    async fn enroll(&self, account: &AccountId, record: &RegistrationRecord) -> Result<bool, AccessError> {
        self.up()?;
        let mut accounts = self.accounts.borrow_mut();
        if accounts.contains_key(account) {
            return Ok(false);
        }
        accounts.insert(*account, Account { record: record.clone(), keyring: None, version: 0 });
        Ok(true)
    }

    async fn record(&self, account: &AccountId) -> Result<Option<RegistrationRecord>, AccessError> {
        self.up()?;
        Ok(self.accounts.borrow().get(account).map(|a| a.record.clone()))
    }

    async fn park_login(
        &self,
        handle: &LoginHandle,
        account: &AccountId,
        state: &LoginState,
        lifetime_seconds: u32,
    ) -> Result<(), AccessError> {
        self.up()?;
        let expires = self.now.get() + i64::from(lifetime_seconds);
        self.logins.borrow_mut().insert(*handle.expose(), (*account, state.clone(), expires));
        Ok(())
    }

    async fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError> {
        self.up()?;
        let taken = self.logins.borrow_mut().remove(handle.expose());
        Ok(taken.filter(|(_, _, expires)| *expires > self.now.get()).map(|(a, s, _)| (a, s)))
    }

    async fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError> {
        self.up()?;
        if !self.accounts.borrow().contains_key(account) {
            return Ok(None);
        }
        let expires = self.now.get() + i64::from(lifetime_seconds);
        self.sessions.borrow_mut().insert(*digest, (*account, expires));
        Ok(Some(UnixTime(expires)))
    }

    async fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError> {
        self.up()?;
        self.sessions.borrow_mut().remove(digest);
        Ok(())
    }

    async fn keyring(&self, digest: &SessionDigest) -> Result<Option<KeyringSnapshot>, AccessError> {
        self.up()?;
        let Some(account) = self.session(digest) else { return Ok(None) };
        let accounts = self.accounts.borrow();
        let a = &accounts[&account];
        Ok(Some(KeyringSnapshot { keyring: a.keyring.clone(), version: KeyringVersion(a.version) }))
    }

    async fn store_keyring(
        &self,
        digest: &SessionDigest,
        keyring: &Keyring,
        expected: KeyringVersion,
    ) -> Result<KeyringWrite, AccessError> {
        self.up()?;
        let Some(account) = self.session(digest) else { return Ok(KeyringWrite::Unauthorized) };
        let mut accounts = self.accounts.borrow_mut();
        let a = accounts.get_mut(&account).expect("live session has an account");
        if a.version != expected.0 {
            return Ok(KeyringWrite::Stale);
        }
        a.keyring = Some(keyring.clone());
        a.version += 1;
        Ok(KeyringWrite::Stored(KeyringVersion(a.version)))
    }

    async fn close_account(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        self.up()?;
        let Some(account) = self.session(digest) else { return Ok(false) };
        self.accounts.borrow_mut().remove(&account);
        self.sessions.borrow_mut().retain(|_, (a, _)| *a != account);
        self.logins.borrow_mut().retain(|_, (a, _, _)| *a != account);
        Ok(true)
    }

    async fn purge_expired(&self) -> Result<u64, AccessError> {
        self.up()?;
        let now = self.now.get();
        let before = self.logins.borrow().len() + self.sessions.borrow().len();
        self.logins.borrow_mut().retain(|_, (_, _, e)| *e > now);
        self.sessions.borrow_mut().retain(|_, (_, e)| *e > now);
        Ok((before - self.logins.borrow().len() - self.sessions.borrow().len()) as u64)
    }
}
