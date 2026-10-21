//! Account store contract tests against the vault, driven through the real
//! OPAQUE adapters: a [`Gatekeeper`] over [`RemoteAccounts`], whose link
//! carries every call to [`serve_accounts`] on an [`AccountLedger`], as the
//! accounts Durable Object does, over an ordered key-value store, the
//! object's [`Scratch`] and a clock moved by hand.
//!
//! The cases the PostgreSQL store was held to, plus two only the vault
//! keeps: how many requests each use case costs the object, and that a name
//! handed over between the record read and the session opens nothing.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::{Pin, pin};
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;

use access::{
    AccessError, AccountId, AccountStore, Budget, Gatekeeper, Keyring, KeyringVersion, KeyringWrite,
    LOGIN_WINDOW_SECONDS, LoginChallenge, LoginHandle, LoginState, MAX_SESSIONS, Member, OpaqueServer, Password,
    RegistrationRecord, SESSION_SECONDS, Session, SessionDigest, SessionDigester, Throttle, Tokens, UnixTime, Username,
};
use access_adapters::{
    HkdfKeyringKdf, HmacPasses, HmacSessionDigest, OpaqueDevice, OpaqueKeys, RandomTokens, throttle_bucket,
};
use custody::CustodyError;
use futures_util::future::join_all;
use vault::core::account_keys;
use vault::core::{
    ACCOUNT_BYTES_CEILING, ACCOUNT_COST, AccountUsage, COUNTER_COST, KeyringRecord, PARKED_LOGIN_COST,
    REGISTRATION_RESERVE, SESSION_COST, SHARED_POOL, SessionRecord,
};
use vault::{
    AccountCall, AccountLedger, Accounts, Class, Clock, KeyValue, Link, RemoteAccounts, Scratch, VaultThrottle,
    serve_accounts,
};

/// Drives a future to its end. Nothing here waits for anything real: a call
/// is pending once, while in flight, and ready when polled again.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

/// Pending once, as a fetch to the Durable Object is: the relay's other
/// requests go on meanwhile, though the object serves one at a time.
#[derive(Debug, Default)]
struct InFlight(bool);

impl Future for InFlight {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// An ordered map with transactions, as a Durable Object's storage is.
#[derive(Debug, Default)]
struct MemoryKv(RefCell<BTreeMap<String, Vec<u8>>>);

impl MemoryKv {
    fn entries(&self) -> Vec<(String, Vec<u8>)> {
        self.0.borrow().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

impl KeyValue for MemoryKv {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CustodyError> {
        Ok(self.0.borrow().get(key).cloned())
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), CustodyError> {
        self.0.borrow_mut().insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), CustodyError> {
        self.0.borrow_mut().remove(key);
        Ok(())
    }

    fn range(&self, start: &str, end: &str, limit: usize) -> Result<Vec<(String, Vec<u8>)>, CustodyError> {
        let map = self.0.borrow();
        let range = map.range::<str, _>((core::ops::Bound::Included(start), core::ops::Bound::Excluded(end)));
        Ok(range.take(limit).map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn atomically<T>(&self, step: impl FnOnce() -> Result<T, CustodyError>) -> Result<T, CustodyError> {
        let before = self.0.borrow().clone();
        let out = step();
        if out.is_err() {
            *self.0.borrow_mut() = before;
        }
        out
    }
}

/// The object's clock, moved by hand: time travel without touching a record.
#[derive(Debug)]
struct ManualClock(Cell<i64>);

impl Clock for ManualClock {
    fn now(&self) -> custody::UnixTime {
        custody::UnixTime(self.0.get())
    }
}

/// The accounts object: its storage, its memory and its clock.
#[derive(Debug)]
struct World {
    kv: MemoryKv,
    scratch: Scratch,
    clock: ManualClock,
}

impl Default for World {
    fn default() -> Self {
        Self { kv: MemoryKv::default(), scratch: Scratch::default(), clock: ManualClock(Cell::new(1_800_000_000)) }
    }
}

type Ledger<'w> = AccountLedger<'w, &'w MemoryKv, &'w ManualClock>;

impl World {
    fn now(&self) -> UnixTime {
        UnixTime(self.clock.0.get())
    }

    fn advance(&self, seconds: u32) {
        self.clock.0.set(self.clock.0.get() + i64::from(seconds));
    }

    fn ledger(&self) -> Ledger<'_> {
        AccountLedger::new(&self.kv, &self.scratch, &self.clock)
    }

    /// One relay instance's way to the object.
    fn link(&self) -> Loopback<'_> {
        Loopback { ledger: self.ledger(), calls: Cell::new(0), hand_over: RefCell::new(None) }
    }

    fn usage(&self) -> AccountUsage {
        self.ledger().usage_now().unwrap()
    }

    /// Rewrites the usage record, as if the store held what `change` says.
    fn pretend(&self, change: impl FnOnce(&mut AccountUsage)) {
        let mut usage = self.usage();
        change(&mut usage);
        self.kv.put(account_keys::ACCOUNT_USAGE, &usage.encode()).unwrap();
    }

    /// Sessions filed for the account, live or expired, as their records
    /// and as the account's index say.
    fn sessions(&self, account: &AccountId) -> usize {
        let filed = self
            .kv
            .entries()
            .into_iter()
            .filter(|(key, _)| key.starts_with('s'))
            .filter(|(_, value)| SessionRecord::decode(value).unwrap().account == *account)
            .count();
        let (start, end) = account_keys::sessions_of(account);
        assert_eq!(self.kv.range(&start, &end, usize::MAX).unwrap().len(), filed, "index and records disagree");
        filed
    }

    /// Logins in progress, attempt counters and units charged, from the
    /// memory's `Debug`, which prints counts only.
    fn memory(&self) -> (u64, u64, u64) {
        let text = format!("{:?}", self.scratch);
        let n: Vec<u64> =
            text.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse().unwrap()).collect();
        assert_eq!(n.len(), 5, "{text}");
        (n[0], n[1], n[2] + n[3] + n[4])
    }
}

/// Carries each call to [`serve_accounts`], as the accounts object does,
/// and counts them: each one is a request the object bills.
#[derive(Debug)]
struct Loopback<'w> {
    ledger: Ledger<'w>,
    calls: Cell<u32>,
    /// Just before the next call that opens a session, the owner behind
    /// this session closes the account and someone else files this record
    /// under the name.
    hand_over: RefCell<Option<(SessionDigest, AccountId, RegistrationRecord)>>,
}

impl Link for Loopback<'_> {
    async fn call(&self, call: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        InFlight::default().await;
        self.calls.set(self.calls.get() + 1);
        if matches!(AccountCall::decode(&call), Some(AccountCall::OpenSession { .. }))
            && let Some((owner, account, record)) = self.hand_over.take()
        {
            assert_eq!(self.ledger.close_account(&owner), Ok(true));
            assert_eq!(self.ledger.enroll(&account, &record), Ok(true));
        }
        Ok(serve_accounts(&self.ledger, &call))
    }
}

#[derive(Debug)]
struct Open;

impl Throttle for Open {
    async fn admit(&self, _account: &AccountId, _budget: &Budget) -> bool {
        true
    }
}

fn keys() -> OpaqueKeys {
    OpaqueKeys::from_seed(&[9; 32]).unwrap()
}

type Remote<'a> = RemoteAccounts<&'a Loopback<'a>>;

type Relay<'a, R = Open> = Gatekeeper<OpaqueKeys, &'a Remote<'a>, RandomTokens, HmacSessionDigest, R, HmacPasses>;

fn remote<'a>(link: &'a Loopback<'a>) -> Remote<'a> {
    RemoteAccounts::new(link, throttle_bucket)
}

fn relay<'a>(world: &World, store: &'a Remote<'a>) -> Relay<'a> {
    relay_with(world, store, Open)
}

fn relay_with<'a, R: Throttle>(world: &World, store: &'a Remote<'a>, throttle: R) -> Relay<'a, R> {
    Gatekeeper::new(keys(), store, RandomTokens, keys().session_digest(), throttle, keys().passes(world.now()))
}

/// The relay's throttle: `limit` attempts a minute, counted in the object.
fn counter<'a>(store: &'a Remote<'a>, limit: u16) -> VaultThrottle<'a, Remote<'a>> {
    VaultThrottle::new(store, limit, throttle_bucket)
}

/// A fresh object, one link to it, the store behind the link and a relay
/// over that store with no throttle.
macro_rules! world {
    ($world:ident, $link:ident, $store:ident, $relay:ident) => {
        let $world = World::default();
        let $link = $world.link();
        let $store = remote(&$link);
        let $relay = relay(&$world, &$store);
    };
}

fn device() -> Member<OpaqueDevice, HkdfKeyringKdf> {
    Member::new(OpaqueDevice, HkdfKeyringKdf)
}

fn pw() -> Password {
    Password::new(b"correct horse battery".to_vec()).unwrap()
}

fn fresh_name() -> Username {
    let tag: String = RandomTokens.login_handle().unwrap().expose()[..8].iter().map(|b| format!("{b:02x}")).collect();
    Username::new(&format!("user-{tag}")).unwrap()
}

async fn register<R: Throttle>(relay: &Relay<'_, R>, name: &Username) {
    let (request, pending) = device().begin_registration(pw()).unwrap();
    let response = relay.registration_response(name, &request).await.unwrap();
    let (record, _) = device().finish_registration(pending, &response).unwrap();
    relay.register(name, &record).await.unwrap();
}

/// KE1 → KE2 → KE3, returning the challenge and KE3 without finishing.
async fn challenge<R: Throttle>(
    relay: &Relay<'_, R>,
    name: &Username,
) -> (LoginChallenge, access::CredentialFinalization) {
    let (request, pending) = device().begin_login(pw()).unwrap();
    let challenge = relay.begin_login(name, &request, None).await.unwrap();
    let (finalization, _) = device().finish_login(pending, &challenge.response).unwrap();
    (challenge, finalization)
}

async fn login<R: Throttle>(relay: &Relay<'_, R>, name: &Username) -> Session {
    let (challenge, finalization) = challenge(relay, name).await;
    relay.finish_login(&challenge.handle, &finalization).await.unwrap()
}

fn keyring(byte: u8) -> Keyring {
    Keyring::new(vec![byte; 500]).unwrap()
}

fn numbered(n: u64, tag: u8) -> [u8; 32] {
    let mut bytes = [tag; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    bytes
}

/// Parks logins of strangers on the shared budget until the object's memory
/// has no room for one more, and says how many it took.
async fn fill_with_logins(store: &Remote<'_>) -> u64 {
    let state = LoginState::from_slice(&[0x5A; LoginState::LEN]).unwrap();
    for n in 0u64.. {
        let mut handle = [0x4C; LoginHandle::LEN];
        handle[8..].copy_from_slice(&n.to_be_bytes());
        let account = AccountId::from_array(numbered(n, 0xA1));
        let parked = store
            .park_login(&LoginHandle::from_array(handle), &account, &state, LOGIN_WINDOW_SECONDS, &Budget::Login)
            .await;
        match parked {
            Ok(()) => {}
            Err(AccessError::StorageFull) => return n,
            Err(other) => panic!("{other:?}"),
        }
    }
    unreachable!()
}

/// Counts registrations of strangers until the object's memory refuses one
/// more, and says how many it took.
async fn fill_with_registrations(store: &Remote<'_>) -> u64 {
    for n in 0u64.. {
        let (account, bucket) = (AccountId::from_array(numbered(n, 0xA2)), numbered(n, 0xB2));
        if !store.admit(&account, &bucket, Class::Registration, 10).await.unwrap() {
            return n;
        }
    }
    unreachable!()
}

/// Runs `call`, and says how many requests it made to the object.
async fn counted<T>(link: &Loopback<'_>, call: impl Future<Output = T>) -> (T, u32) {
    let before = link.calls.get();
    let out = call.await;
    (out, link.calls.get() - before)
}

#[test]
fn register_login_keyring_and_sign_out() {
    block_on(async {
        world!(world, _link, _store, relay);
        let name = fresh_name();
        register(&relay, &name).await;
        let session = login(&relay, &name).await;
        assert_eq!(session.expires_at, UnixTime(world.now().0 + i64::from(SESSION_SECONDS)));

        let empty = relay.keyring(&session.token).await.unwrap();
        assert_eq!((empty.keyring, empty.version), (None, KeyringVersion::NONE));
        let v1 = relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE).await.unwrap();
        assert_eq!(v1, KeyringVersion(1));
        assert_eq!(
            relay.store_keyring(&session.token, &keyring(2), KeyringVersion::NONE).await.unwrap_err(),
            AccessError::Conflict
        );
        assert_eq!(relay.keyring(&session.token).await.unwrap().keyring, Some(keyring(1)));

        relay.sign_out(&session.token).await.unwrap();
        assert_eq!(relay.keyring(&session.token).await.unwrap_err(), AccessError::Unauthorized);
    });
}

#[test]
fn a_taken_name_is_never_overwritten() {
    block_on(async {
        world!(_world, _link, _store, relay);
        let name = fresh_name();
        // A rival started while the name was still free, and finishes second.
        let (request, pending) =
            device().begin_registration(Password::new(b"attacker password".to_vec()).unwrap()).unwrap();
        let response = relay.registration_response(&name, &request).await.unwrap();
        register(&relay, &name).await;
        let (record, _) = device().finish_registration(pending, &response).unwrap();
        assert_eq!(relay.register(&name, &record).await.unwrap_err(), AccessError::AlreadyRegistered);
        // Once taken, the name gets no OPRF evaluation at all.
        let (request, _) = device().begin_registration(pw()).unwrap();
        assert_eq!(relay.registration_response(&name, &request).await.unwrap_err(), AccessError::AlreadyRegistered);
        login(&relay, &name).await;
    });
}

#[test]
fn sessions_end_by_the_vault_clock() {
    block_on(async {
        world!(world, _link, _store, relay);
        let name = fresh_name();
        register(&relay, &name).await;
        let session = login(&relay, &name).await;
        world.advance(SESSION_SECONDS - 1);
        assert!(relay.keyring(&session.token).await.is_ok(), "a second before its end");
        world.advance(1);
        assert_eq!(relay.keyring(&session.token).await.unwrap_err(), AccessError::Unauthorized);
        assert_eq!(
            relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE).await.unwrap_err(),
            AccessError::Unauthorized
        );
        assert_eq!(relay.close_account(&session.token).await.unwrap_err(), AccessError::Unauthorized);
        assert_eq!(relay.sign_out_everywhere(&session.token).await.unwrap_err(), AccessError::Unauthorized);
    });
}

#[test]
fn an_expired_login_cannot_be_finished() {
    block_on(async {
        world!(world, _link, _store, relay);
        let name = fresh_name();
        register(&relay, &name).await;
        let (challenge, finalization) = challenge(&relay, &name).await;
        world.advance(LOGIN_WINDOW_SECONDS);
        assert_eq!(relay.finish_login(&challenge.handle, &finalization).await.unwrap_err(), AccessError::NotAuthentic);
    });
}

#[test]
fn closing_the_account_removes_record_keyring_sessions_and_logins() {
    block_on(async {
        world!(world, _link, store, relay);
        let name = fresh_name();
        register(&relay, &name).await;
        let session = login(&relay, &name).await;
        let other = login(&relay, &name).await;
        let (pending, _) = challenge(&relay, &name).await;
        relay.store_keyring(&session.token, &keyring(3), KeyringVersion::NONE).await.unwrap();
        relay.close_account(&session.token).await.unwrap();

        let account = keys().account_of(&name);
        assert_eq!(world.kv.get(&account_keys::account(&account)), Ok(None));
        assert_eq!(world.kv.get(&account_keys::keyring(&account)), Ok(None));
        assert_eq!(world.sessions(&account), 0);
        assert_eq!(store.take_login(&pending.handle).await, Ok(None));
        assert_eq!(relay.keyring(&other.token).await.unwrap_err(), AccessError::Unauthorized);
        // The name is free again.
        register(&relay, &name).await;
    });
}

#[test]
fn purge_removes_only_what_expired() {
    block_on(async {
        world!(world, _link, _store, relay);
        let name = fresh_name();
        register(&relay, &name).await;
        let stale = login(&relay, &name).await;
        world.advance(1000);
        let live = login(&relay, &name).await;
        world.advance(SESSION_SECONDS - 1000);
        assert!(relay.purge_expired().await.unwrap() >= 1);
        let digest = keys().session_digest().digest(&stale.token);
        assert_eq!(world.kv.get(&account_keys::session(&digest)), Ok(None));
        assert_eq!(world.sessions(&keys().account_of(&name)), 1);
        assert!(relay.keyring(&live.token).await.is_ok());
    });
}

#[test]
fn signing_out_everywhere_ends_every_session_of_the_account_only() {
    block_on(async {
        world!(_world, _link, _store, relay);
        let (ada, bob) = (fresh_name(), fresh_name());
        register(&relay, &ada).await;
        register(&relay, &bob).await;
        let laptop = login(&relay, &ada).await;
        let phone = login(&relay, &ada).await;
        let other = login(&relay, &bob).await;
        relay.store_keyring(&laptop.token, &keyring(1), KeyringVersion::NONE).await.unwrap();
        relay.sign_out_everywhere(&phone.token).await.unwrap();
        for gone in [&laptop, &phone] {
            assert_eq!(relay.keyring(&gone.token).await.unwrap_err(), AccessError::Unauthorized);
            assert_eq!(relay.sign_out_everywhere(&gone.token).await.unwrap_err(), AccessError::Unauthorized);
        }
        assert!(relay.keyring(&other.token).await.is_ok());
        // The account and its keyring stay.
        let again = login(&relay, &ada).await;
        assert_eq!(relay.keyring(&again.token).await.unwrap().keyring, Some(keyring(1)));
    });
}

#[test]
fn an_account_keeps_at_most_max_sessions_and_the_oldest_goes_first() {
    block_on(async {
        world!(world, _link, _store, relay);
        let name = fresh_name();
        register(&relay, &name).await;
        let mut sessions = Vec::new();
        for _ in 0..=MAX_SESSIONS {
            sessions.push(login(&relay, &name).await);
            world.advance(1);
        }
        assert_eq!(world.sessions(&keys().account_of(&name)), MAX_SESSIONS as usize);
        assert_eq!(relay.keyring(&sessions[0].token).await.unwrap_err(), AccessError::Unauthorized);
        for live in &sessions[1..] {
            assert!(relay.keyring(&live.token).await.is_ok());
        }
    });
}

#[test]
fn each_budget_has_its_own_count() {
    block_on(async {
        world!(_world, _link, store, relay);
        let throttle = counter(&store, 2);
        let name = fresh_name();
        register(&relay, &name).await;
        let session = login(&relay, &name).await;
        let account = keys().account_of(&name);
        let budgets = [Budget::Login, Budget::Registration, Budget::Device(session.pass.clone())];
        for budget in &budgets {
            assert!(throttle.admit(&account, budget).await);
            assert!(throttle.admit(&account, budget).await);
            assert!(!throttle.admit(&account, budget).await, "{budget:?}");
        }
        let fresh = login(&relay, &name).await;
        assert!(throttle.admit(&account, &Budget::Device(fresh.pass)).await, "every pass counts on its own");
    });
}

#[test]
fn a_flood_of_guesses_cannot_lock_out_a_device_that_logged_in_before() {
    block_on(async {
        world!(world, _link, store, open);
        let name = fresh_name();
        register(&open, &name).await;
        let session = login(&open, &name).await;
        let relay = relay_with(&world, &store, counter(&store, 3));
        let (request, _) = device().begin_login(pw()).unwrap();
        for _ in 0..3 {
            relay.begin_login(&name, &request, None).await.unwrap();
        }
        assert_eq!(relay.begin_login(&name, &request, None).await.unwrap_err(), AccessError::Throttled);
        let forged = access::DevicePass::from_array([7; access::DevicePass::LEN]);
        assert_eq!(relay.begin_login(&name, &request, Some(&forged)).await.unwrap_err(), AccessError::Throttled);
        // The owner's device still gets in, with the pass of its last login.
        let (request, pending) = device().begin_login(pw()).unwrap();
        let challenge = relay.begin_login(&name, &request, Some(&session.pass)).await.unwrap();
        let (finalization, _) = device().finish_login(pending, &challenge.response).unwrap();
        assert!(relay.finish_login(&challenge.handle, &finalization).await.is_ok());
    });
}

#[test]
fn each_use_case_costs_the_accounts_object_a_fixed_number_of_requests() {
    // Every request is billed and queued in one object: register/start 2,
    // register/finish 1, login/start 3, login/finish 3, a session route 1.
    block_on(async {
        let world = World::default();
        let link = world.link();
        let store = remote(&link);
        let relay = relay_with(&world, &store, counter(&store, 10));
        let name = fresh_name();

        let (request, pending) = device().begin_registration(pw()).unwrap();
        let (response, requests) = counted(&link, relay.registration_response(&name, &request)).await;
        assert_eq!(requests, 2, "register/start: the record, the attempt");
        let (record, _) = device().finish_registration(pending, &response.unwrap()).unwrap();
        let (enrolled, requests) = counted(&link, relay.register(&name, &record)).await;
        assert_eq!((enrolled, requests), (Ok(()), 1), "register/finish: the enrolment");
        let (request, _) = device().begin_registration(pw()).unwrap();
        let (taken, requests) = counted(&link, relay.registration_response(&name, &request)).await;
        assert_eq!((taken.unwrap_err(), requests), (AccessError::AlreadyRegistered, 1), "a taken name: the record");

        let mut pass = None;
        for round in ["without a pass", "with a pass"] {
            let (request, pending) = device().begin_login(pw()).unwrap();
            let (challenge, requests) = counted(&link, relay.begin_login(&name, &request, pass.as_ref())).await;
            assert_eq!(requests, 3, "login/start {round}: the record, the attempt, the login");
            let challenge = challenge.unwrap();
            let (finalization, _) = device().finish_login(pending, &challenge.response).unwrap();
            let (session, requests) = counted(&link, relay.finish_login(&challenge.handle, &finalization)).await;
            assert_eq!(requests, 3, "login/finish {round}: the login, the record, the session");
            pass = Some(session.unwrap().pass);
        }

        let session = login(&relay, &name).await;
        let token = &session.token;
        assert_eq!(counted(&link, relay.keyring(token)).await.1, 1);
        assert_eq!(counted(&link, relay.store_keyring(token, &keyring(1), KeyringVersion::NONE)).await.1, 1);
        assert_eq!(counted(&link, relay.sign_out(token)).await.1, 1);
        let session = login(&relay, &name).await;
        assert_eq!(counted(&link, relay.sign_out_everywhere(&session.token)).await.1, 1);
        let session = login(&relay, &name).await;
        assert_eq!(counted(&link, relay.close_account(&session.token)).await.1, 1);
        assert_eq!(counted(&link, relay.purge_expired()).await.1, 1);
        assert_eq!(world.usage().stored, 0);
    });
}

mod adversary {
    use super::*;

    #[test]
    fn concurrent_finishes_of_one_login_open_one_session() {
        block_on(async {
            world!(world, _link, _store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            let (challenge, finalization) = challenge(&relay, &name).await;
            // 12 relay instances race to finish the same login with the genuine KE3.
            let links: Vec<Loopback<'_>> = (0..12).map(|_| world.link()).collect();
            let stores: Vec<Remote<'_>> = links.iter().map(|link| remote(link)).collect();
            let relays: Vec<Relay<'_>> = stores.iter().map(|store| self::relay(&world, store)).collect();
            let outcomes =
                join_all(relays.iter().map(|relay| relay.finish_login(&challenge.handle, &finalization))).await;
            assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
            assert!(
                outcomes.iter().filter(|o| o.is_err()).all(|o| *o.as_ref().unwrap_err() == AccessError::NotAuthentic)
            );
            assert_eq!(world.sessions(&keys().account_of(&name)), 1);
        });
    }

    #[test]
    fn concurrent_keyring_writes_from_one_version_store_exactly_one() {
        block_on(async {
            world!(world, _link, _store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            let session = login(&relay, &name).await;
            let digest = &keys().session_digest().digest(&session.token);
            let links: Vec<Loopback<'_>> = (0..12).map(|_| world.link()).collect();
            let stores: Vec<Remote<'_>> = links.iter().map(|link| remote(link)).collect();
            let outcomes = join_all(stores.iter().enumerate().map(|(i, store)| async move {
                store.store_keyring(digest, &keyring(i as u8 + 1), KeyringVersion::NONE).await
            }))
            .await;
            let stored: Vec<_> = outcomes.iter().filter(|o| matches!(o, Ok(KeyringWrite::Stored(_)))).collect();
            assert_eq!(stored.len(), 1);
            assert!(
                outcomes.iter().all(|o| matches!(o, Ok(KeyringWrite::Stored(KeyringVersion(1)) | KeyringWrite::Stale)))
            );
            assert_eq!(relay.keyring(&session.token).await.unwrap().version, KeyringVersion(1));
        });
    }

    #[test]
    fn unknown_names_park_a_login_like_real_ones() {
        block_on(async {
            world!(_world, _link, store, relay);
            let ghost = fresh_name();
            let (request, _) = device().begin_login(pw()).unwrap();
            let challenge = relay.begin_login(&ghost, &request, None).await.unwrap();
            let parked = store.take_login(&challenge.handle).await.unwrap();
            assert_eq!(parked.map(|(account, _)| account), Some(keys().account_of(&ghost)));
        });
    }

    #[test]
    fn the_vault_holds_neither_names_nor_tokens() {
        block_on(async {
            world!(world, _link, _store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            let session = login(&relay, &name).await;
            challenge(&relay, &name).await;
            let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let token = session.token.expose();
            let holds = |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
            let entries = world.kv.entries();
            assert!(!entries.is_empty());
            for (key, value) in &entries {
                for needle in [name.as_bytes(), token.as_slice()] {
                    assert!(!holds(key.as_bytes(), needle) && !holds(value, needle), "{key}");
                    assert!(!key.contains(&hex(needle)), "{key}");
                }
            }
            let memory = format!("{:?}", world.scratch);
            assert!(!memory.contains(&hex(name.as_bytes())) && !memory.contains(&hex(token)), "{memory}");
        });
    }

    #[test]
    fn a_full_account_store_refuses_new_names_and_bigger_keyrings_but_lets_members_in() {
        // Accounts never expire: a flood of registrations must hit our own
        // ceiling, not the object's storage limit.
        block_on(async {
            world!(world, _link, _store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            let session = login(&relay, &name).await;
            let v1 = relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE).await.unwrap();
            world.pretend(|usage| usage.stored = ACCOUNT_BYTES_CEILING);
            let newcomer = fresh_name();
            let (request, pending) = device().begin_registration(pw()).unwrap();
            let response = relay.registration_response(&newcomer, &request).await.unwrap();
            let (record, _) = device().finish_registration(pending, &response).unwrap();
            assert_eq!(relay.register(&newcomer, &record).await, Err(AccessError::StorageFull));
            let bigger = Keyring::new(vec![2; 501]).unwrap();
            assert_eq!(relay.store_keyring(&session.token, &bigger, v1).await, Err(AccessError::StorageFull));
            // Same size, smaller, logging in, reading: all still work.
            let v2 = relay.store_keyring(&session.token, &keyring(3), v1).await.unwrap();
            let smaller = Keyring::new(vec![4; 10]).unwrap();
            relay.store_keyring(&session.token, &smaller, v2).await.unwrap();
            let again = login(&relay, &name).await;
            assert_eq!(relay.keyring(&again.token).await.unwrap().keyring, Some(smaller));
        });
    }

    #[test]
    fn a_flood_of_logins_fills_only_its_own_budget_and_expired_ones_make_room() {
        block_on(async {
            world!(world, _link, store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            challenge(&relay, &name).await;
            world.advance(1);
            assert_eq!(fill_with_logins(&store).await, SHARED_POOL / PARKED_LOGIN_COST - 1);
            let (request, _) = device().begin_login(pw()).unwrap();
            assert_eq!(relay.begin_login(&name, &request, None).await.unwrap_err(), AccessError::StorageFull);
            // Accounts have their own budget: registering still works.
            register(&relay, &fresh_name()).await;
            // The first login expires, and makes room on the spot.
            world.advance(LOGIN_WINDOW_SECONDS - 1);
            login(&relay, &name).await;
        });
    }

    #[test]
    fn a_flood_of_logins_does_not_stop_registrations_through_the_real_throttle() {
        // Registering a free name spends its own budget, whose counter draws
        // on a reserve the logins cannot reach.
        block_on(async {
            let world = World::default();
            let link = world.link();
            let store = remote(&link);
            let relay = relay_with(&world, &store, counter(&store, 10));
            let name = fresh_name();
            register(&relay, &name).await;
            assert_eq!(fill_with_logins(&store).await, SHARED_POOL / PARKED_LOGIN_COST);
            let (request, _) = device().begin_login(pw()).unwrap();
            assert_eq!(relay.begin_login(&name, &request, None).await.unwrap_err(), AccessError::Throttled);
            register(&relay, &fresh_name()).await;
        });
    }

    #[test]
    fn the_registration_reserve_has_its_own_end() {
        block_on(async {
            let world = World::default();
            let link = world.link();
            let store = remote(&link);
            let relay = relay_with(&world, &store, counter(&store, 10));
            fill_with_logins(&store).await;
            // The reserve, then what the logins left of the shared memory.
            let room = REGISTRATION_RESERVE / COUNTER_COST + (SHARED_POOL % PARKED_LOGIN_COST) / COUNTER_COST;
            assert_eq!(fill_with_registrations(&store).await, room);
            let (request, _) = device().begin_registration(pw()).unwrap();
            assert_eq!(relay.registration_response(&fresh_name(), &request).await.unwrap_err(), AccessError::Throttled);
        });
    }

    #[test]
    fn the_usage_record_is_what_the_vault_holds() {
        block_on(async {
            world!(world, _link, store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            let session = login(&relay, &name).await;
            relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE).await.unwrap();
            challenge(&relay, &name).await;
            counter(&store, 10).admit(&keys().account_of(&fresh_name()), &Budget::Login).await;
            let doomed = fresh_name();
            register(&relay, &doomed).await;
            let doomed_session = login(&relay, &doomed).await;
            relay.store_keyring(&doomed_session.token, &keyring(2), KeyringVersion::NONE).await.unwrap();
            relay.close_account(&doomed_session.token).await.unwrap();
            relay.sign_out(&session.token).await.unwrap();
            login(&relay, &name).await;

            let (mut stored, mut sessions) = (0, 0);
            for (key, value) in world.kv.entries() {
                match key.as_bytes()[0] {
                    b'a' => stored += ACCOUNT_COST,
                    b'k' => stored += KeyringRecord::decode(&value).unwrap().keyring.as_bytes().len() as u64,
                    b's' => sessions += SESSION_COST,
                    _ => {}
                }
            }
            let usage = world.usage();
            assert_eq!(usage.stored, stored, "stored bytes drifted from accounts and keyrings");
            assert_eq!(usage.sessions, sessions, "session bytes drifted from the sessions");
            let (logins, counters, units) = world.memory();
            assert_eq!((logins, counters), (1, 1));
            assert_eq!(units, logins * PARKED_LOGIN_COST + counters * COUNTER_COST, "memory drifted");
        });
    }

    #[test]
    fn the_login_budget_is_one_count_for_the_whole_world() {
        block_on(async {
            world!(world, _link, store, relay);
            let throttle = counter(&store, 10);
            let target = keys().account_of(&fresh_name());
            for i in 0..10 {
                assert!(throttle.admit(&target, &Budget::Login).await, "attempt {i}");
            }
            assert!(!throttle.admit(&target, &Budget::Login).await);
            // Another relay instance (another Cloudflare location) shares the count.
            let elsewhere = world.link();
            let elsewhere = remote(&elsewhere);
            assert!(!counter(&elsewhere, 10).admit(&target, &Budget::Login).await);
            assert!(
                throttle.admit(&keys().account_of(&fresh_name()), &Budget::Login).await,
                "other accounts are untouched"
            );
            // A minute later the budget is back, and the cron forgets the old window.
            world.advance(61);
            assert!(throttle.admit(&target, &Budget::Login).await);
            // The other account's counter already went on the way.
            world.advance(61);
            assert_eq!(relay.purge_expired().await, Ok(1));
            assert_eq!(world.memory(), (0, 0, 0));
        });
    }

    #[test]
    fn a_burst_from_many_relays_gets_exactly_the_budget() {
        block_on(async {
            let world = World::default();
            let target = &keys().account_of(&fresh_name());
            let links: Vec<Loopback<'_>> = (0..12).map(|_| world.link()).collect();
            let stores: Vec<Remote<'_>> = links.iter().map(|link| remote(link)).collect();
            let throttles: Vec<_> = stores.iter().map(|store| counter(store, 10)).collect();
            let outcomes = join_all((0..36).map(|i| {
                let throttle = &throttles[i % throttles.len()];
                async move { throttle.admit(target, &Budget::Login).await }
            }))
            .await;
            assert_eq!(outcomes.iter().filter(|admitted| **admitted).count(), 10);
        });
    }

    #[test]
    fn the_throttle_fails_closed() {
        block_on(async {
            world!(_world, _link, store, _relay);
            // A limit the object refuses stands in for any failure to count.
            for limit in [0, 1001, u16::MAX] {
                assert!(!counter(&store, limit).admit(&keys().account_of(&fresh_name()), &Budget::Login).await);
            }
        });
    }

    #[test]
    fn a_session_filed_without_the_relay_secret_opens_nothing() {
        // Whoever can call the accounts object can file a session for an
        // account it knows, but cannot hold a token whose keyed digest matches.
        block_on(async {
            world!(_world, _link, store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            let token = RandomTokens.session().unwrap();
            let unkeyed: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(token.expose()).into();
            let account = keys().account_of(&name);
            let record = store.record(&account).await.unwrap().unwrap();
            let unkeyed = SessionDigest::from_array(unkeyed);
            assert!(store.open_session(&unkeyed, &account, &record, SESSION_SECONDS).await.unwrap().is_some());
            assert_eq!(relay.keyring(&token).await.unwrap_err(), AccessError::Unauthorized);
            assert_eq!(relay.close_account(&token).await.unwrap_err(), AccessError::Unauthorized);
            // Nor can it file one that outlives a real session.
            let long = store.open_session(&SessionDigest::from_array([7; 32]), &account, &record, 86400).await;
            assert_eq!(long, Err(AccessError::StoreUnavailable), "a 24-hour session was filed");
        });
    }

    #[test]
    fn a_login_started_before_a_name_changed_hands_cannot_enter_the_new_account() {
        block_on(async {
            world!(_world, _link, store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            // The first owner has a genuine login in flight...
            let (challenge, finalization) = challenge(&relay, &name).await;
            let (account, state) = store.take_login(&challenge.handle).await.unwrap().unwrap();
            // ...closes the account, and someone else registers the free name.
            let session = login(&relay, &name).await;
            relay.close_account(&session.token).await.unwrap();
            register(&relay, &name).await;
            // Even with the old login put back, it does not finish into the new account.
            store.park_login(&challenge.handle, &account, &state, LOGIN_WINDOW_SECONDS, &Budget::Login).await.unwrap();
            assert_eq!(
                relay.finish_login(&challenge.handle, &finalization).await.unwrap_err(),
                AccessError::NotAuthentic
            );
        });
    }

    #[test]
    fn a_name_that_changes_hands_after_the_password_check_opens_no_session() {
        block_on(async {
            world!(world, link, store, relay);
            let name = fresh_name();
            register(&relay, &name).await;
            let owner = login(&relay, &name).await;
            let account = keys().account_of(&name);
            // Someone else's record for the same name, ready to be filed.
            let (request, pending) =
                device().begin_registration(Password::new(b"another password".to_vec()).unwrap()).unwrap();
            let response = keys().registration_response(&account, &request).unwrap();
            let (rival, _) = device().finish_registration(pending, &response).unwrap();
            // The KE3 is genuine, but the name changes hands between the
            // record read and the session.
            let (challenge, finalization) = challenge(&relay, &name).await;
            link.hand_over.replace(Some((keys().session_digest().digest(&owner.token), account, rival.clone())));
            assert_eq!(
                relay.finish_login(&challenge.handle, &finalization).await.unwrap_err(),
                AccessError::NotAuthentic
            );
            assert!(link.hand_over.borrow().is_none(), "the name did not change hands");
            assert_eq!(store.record(&account).await, Ok(Some(rival)));
            assert_eq!(world.sessions(&account), 0);
        });
    }
}
