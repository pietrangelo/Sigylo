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
    AccountStore, KeyringKdf, KeyringWrite, OpaqueClient, OpaqueServer, Passes, SessionDigester, Throttle, Tokens,
};
use crate::core::{
    AccessError, AccountId, Budget, CredentialFinalization, CredentialRequest, CredentialResponse, DevicePass,
    ExportKey, Keyring, KeyringKey, KeyringSnapshot, KeyringVersion, LoginHandle, LoginState, MAX_SESSIONS, Password,
    RegistrationRecord, RegistrationRequest, RegistrationResponse, SessionDigest, SessionToken, UnixTime, Username,
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

    /// A toy record is a hash: one byte repeated is none a device makes.
    fn check_record(&self, record: &RegistrationRecord) -> Result<(), AccessError> {
        let bytes = record.as_bytes();
        if bytes.iter().all(|b| *b == bytes[0]) { Err(AccessError::MalformedMessage) } else { Ok(()) }
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
        state.extend_from_slice(account.as_bytes());
        state.resize(LoginState::LEN, 0);
        Ok((CredentialResponse::from_slice(&response)?, LoginState::from_slice(&state)?))
    }

    fn finish_login(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        state: &LoginState,
        finalization: &CredentialFinalization,
    ) -> Result<(), AccessError> {
        let record = match record {
            Some(r) => r.as_bytes().to_vec(),
            None => fnv(&[b"fake", account.as_bytes()], RegistrationRecord::LEN),
        };
        let (mac, bound) = state.expose().split_at(64);
        if mac == finalization.as_bytes() && mac == Self::mac(&record) && bound[..32] == *account.as_bytes() {
            Ok(())
        } else {
            Err(AccessError::NotAuthentic)
        }
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

/// Admits `limit` attempts per account and budget, then refuses.
#[derive(Debug)]
pub struct CountingThrottle {
    pub limit: Cell<u32>,
    spent: RefCell<HashMap<(AccountId, Vec<u8>), u32>>,
}

impl CountingThrottle {
    pub fn spent_total(&self) -> u32 {
        self.spent.borrow().values().sum()
    }
}

impl Default for CountingThrottle {
    fn default() -> Self {
        Self { limit: Cell::new(u32::MAX), spent: RefCell::default() }
    }
}

impl Throttle for CountingThrottle {
    async fn admit(&self, account: &AccountId, budget: &Budget) -> bool {
        let bucket = match budget {
            Budget::Login => vec![0],
            Budget::Registration => vec![1],
            Budget::Device(pass) => [&[2][..], pass.expose()].concat(),
        };
        let mut spent = self.spent.borrow_mut();
        let count = spent.entry((*account, bucket)).or_default();
        *count += 1;
        *count <= self.limit.get()
    }
}

/// Passes that are a plain hash of account and record: forgeable, but
/// bound the way real ones are.
#[derive(Debug)]
pub struct ToyPasses;

impl Passes for ToyPasses {
    fn issue(&self, account: &AccountId, record: &RegistrationRecord) -> Result<DevicePass, AccessError> {
        DevicePass::from_slice(&fnv(&[b"pass", account.as_bytes(), record.as_bytes()], DevicePass::LEN))
    }

    fn admits(&self, pass: &DevicePass, account: &AccountId, record: &RegistrationRecord) -> bool {
        self.issue(account, record).is_ok_and(|p| p == *pass)
    }
}

#[derive(Debug, Clone)]
struct Account {
    record: RegistrationRecord,
    keyring: Option<Keyring>,
    version: u64,
}

/// A parked login: whose, its state, its expiry, the budget it was filed under.
type Parked = (AccountId, LoginState, i64, Budget);

/// A reference in-memory store with a hand-driven clock.
#[derive(Debug, Default)]
pub struct FakeStore {
    pub now: Cell<i64>,
    pub broken: Cell<bool>,
    accounts: RefCell<HashMap<AccountId, Account>>,
    logins: RefCell<HashMap<[u8; LoginHandle::LEN], Parked>>,
    pub sessions: RefCell<HashMap<SessionDigest, (AccountId, i64)>>,
    /// When set, the name changes hands right before the next session
    /// opens: the account is closed and enrolled again with this record.
    pub hand_over_before_session: RefCell<Option<RegistrationRecord>>,
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

    /// The budget a parked login was filed under.
    pub fn parked_budget(&self, handle: &LoginHandle) -> Option<Budget> {
        self.logins.borrow().get(handle.expose()).map(|(_, _, _, budget)| budget.clone())
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
        budget: &Budget,
    ) -> Result<(), AccessError> {
        self.up()?;
        let expires = self.now.get() + i64::from(lifetime_seconds);
        self.logins.borrow_mut().insert(*handle.expose(), (*account, state.clone(), expires, budget.clone()));
        Ok(())
    }

    async fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError> {
        self.up()?;
        let taken = self.logins.borrow_mut().remove(handle.expose());
        Ok(taken.filter(|(_, _, expires, _)| *expires > self.now.get()).map(|(a, s, _, _)| (a, s)))
    }

    async fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        record: &RegistrationRecord,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError> {
        self.up()?;
        if let Some(newcomer) = self.hand_over_before_session.borrow_mut().take() {
            self.sessions.borrow_mut().retain(|_, (a, _)| a != account);
            self.accounts.borrow_mut().insert(*account, Account { record: newcomer, keyring: None, version: 0 });
        }
        if self.accounts.borrow().get(account).is_none_or(|a| a.record != *record) {
            return Ok(None);
        }
        let expires = self.now.get() + i64::from(lifetime_seconds);
        let mut sessions = self.sessions.borrow_mut();
        sessions.insert(*digest, (*account, expires));
        loop {
            let mine = sessions.iter().filter(|(_, (a, _))| a == account);
            if mine.clone().count() <= MAX_SESSIONS as usize {
                break;
            }
            // The earliest expiry goes, then the lowest digest; never the new one.
            let oldest = *mine
                .filter(|(d, _)| *d != digest)
                .min_by_key(|(d, (_, e))| (*e, *d.as_bytes()))
                .map(|(d, _)| d)
                .expect("over the cap");
            sessions.remove(&oldest);
        }
        Ok(Some(UnixTime(expires)))
    }

    async fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError> {
        self.up()?;
        self.sessions.borrow_mut().remove(digest);
        Ok(())
    }

    async fn close_sessions(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        self.up()?;
        let Some(account) = self.session(digest) else { return Ok(false) };
        self.sessions.borrow_mut().retain(|_, (a, _)| *a != account);
        Ok(true)
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
        self.logins.borrow_mut().retain(|_, (a, _, _, _)| *a != account);
        Ok(true)
    }

    async fn purge_expired(&self) -> Result<u64, AccessError> {
        self.up()?;
        let now = self.now.get();
        let before = self.logins.borrow().len() + self.sessions.borrow().len();
        self.logins.borrow_mut().retain(|_, (_, _, e, _)| *e > now);
        self.sessions.borrow_mut().retain(|_, (_, e)| *e > now);
        Ok((before - self.logins.borrow().len() - self.sessions.borrow().len()) as u64)
    }
}
