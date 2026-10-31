//! Logins in progress and attempt counters, kept only in the accounts
//! object's memory: a flood of guesses writes no row, and nothing of it
//! reaches the storage's recovery history. A restart forgets them, which
//! costs a retried login and at most one more window of attempts.
//!
//! Memory is counted in the units of the SQL rows these replace, in three
//! pools: Shared for the shared login budget, and two reserves, for
//! registrations and for device logins, that overflow into Shared once
//! full. Guessing a name fills only Shared, so registrations and the owners'
//! devices keep their room; a device's pass holds one login at a time, so a
//! stolen pass cannot fill the account's room either. An account charges the
//! Device reserve from one of its device buckets at a time, its share; its
//! other buckets are charged to Shared, so accounts an attacker registers
//! hold one bucket each of the reserve, never their sixteen.
//!
//! Time comes in as an argument: no clock, no I/O, no randomness, and no
//! call that can panic.

use core::cell::{RefCell, RefMut};
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use access::{AccessError, AccountId, LoginHandle, LoginState, UnixTime};

use crate::core::{
    ATTEMPT_LIMIT_CEILING, ATTEMPT_WINDOW_SECONDS, COUNTER_COST, Class, DEVICE_BUCKETS_PER_ACCOUNT, DEVICE_RESERVE,
    DEVICE_SHARE_PER_ACCOUNT, PARKED_LOGIN_COST, REGISTRATION_RESERVE, SHARED_POOL,
};

/// Expired entries an admit or a park clears on its way.
const SWEEP_ON_THE_WAY: usize = 64;

/// The room an attempt that may park a login asks for: its counter and its
/// login, whether its counter already exists or not, so a refusal never
/// tells whether someone else tried the name this minute.
const ATTEMPT_AND_LOGIN: u64 = COUNTER_COST + PARKED_LOGIN_COST;
// An account charges the Device reserve from one bucket at a time, which
// holds one counter and one parked login at most: that is its share.
const _: () = assert!(ATTEMPT_AND_LOGIN == DEVICE_SHARE_PER_ACCOUNT);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pool {
    Shared,
    Registration,
    Device,
}

impl Pool {
    fn size(self) -> u64 {
        match self {
            Self::Shared => SHARED_POOL,
            Self::Registration => REGISTRATION_RESERVE,
            Self::Device => DEVICE_RESERVE,
        }
    }

    /// The pools a class is charged to: its reserve first, then Shared.
    fn chain(class: Class) -> &'static [Pool] {
        match class {
            Class::Login => &[Self::Shared],
            Class::Registration => &[Self::Registration, Self::Shared],
            Class::Device => &[Self::Device, Self::Shared],
        }
    }
}

/// Units charged to each pool.
#[derive(Default)]
struct Used {
    shared: u64,
    registration: u64,
    device: u64,
}

impl Used {
    fn of(&mut self, pool: Pool) -> &mut u64 {
        match pool {
            Pool::Shared => &mut self.shared,
            Pool::Registration => &mut self.registration,
            Pool::Device => &mut self.device,
        }
    }

    fn free(&self, pool: Pool) -> u64 {
        let used = match pool {
            Pool::Shared => self.shared,
            Pool::Registration => self.registration,
            Pool::Device => self.device,
        };
        pool.size().saturating_sub(used)
    }

    /// The first pool of `chain` with `units` free in one piece.
    fn room(&self, chain: &[Pool], units: u64) -> Option<Pool> {
        chain.iter().copied().find(|pool| self.free(*pool) >= units)
    }

    fn charge(&mut self, chain: &[Pool], units: u64) -> Option<Pool> {
        let pool = self.room(chain, units)?;
        let used = self.of(pool);
        *used = used.saturating_add(units);
        Some(pool)
    }

    fn refund(&mut self, pool: Pool, units: u64) {
        let used = self.of(pool);
        *used = used.saturating_sub(units);
    }
}

/// A login between its two round trips.
struct Parked {
    account: AccountId,
    expires_at: i64,
    charged: Pool,
    /// The device bucket it holds, if it spent a device budget.
    bucket: Option<[u8; 32]>,
    state: LoginState,
}

/// Attempts on one budget in the current window.
struct Counter {
    window_start: i64,
    attempts: u32,
    charged: Pool,
    /// The account whose device bucket this is.
    device_of: Option<[u8; 32]>,
}

impl Counter {
    fn expires_at(&self) -> i64 {
        self.window_start.saturating_add(i64::from(ATTEMPT_WINDOW_SECONDS))
    }
}

/// What an expiry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Login([u8; 16]),
    Counter(Class, [u8; 32]),
}

#[derive(Default)]
struct Inner {
    logins: BTreeMap<[u8; 16], Parked>,
    /// The one login each device bucket holds.
    by_bucket: BTreeMap<[u8; 32], [u8; 16]>,
    /// Each account's logins, so closing an account drops them.
    of_account: BTreeSet<([u8; 32], [u8; 16])>,
    counters: BTreeMap<(Class, [u8; 32]), Counter>,
    expiries: BTreeSet<(i64, Slot)>,
    used: Used,
    /// Device buckets each account holds: a bucket is held while its
    /// counter or its parked login lives, and counts once if both do.
    device_buckets: BTreeMap<[u8; 32], u8>,
    /// The one device bucket each account may charge to the Device reserve,
    /// and how many of its charges (its counter, its parked login) are
    /// there: an account's share of the reserve is one bucket's worth,
    /// [`DEVICE_SHARE_PER_ACCOUNT`]. Its other buckets are charged to Shared.
    device_reserved: BTreeMap<[u8; 32], ([u8; 32], u8)>,
}

impl Inner {
    fn remove_login(&mut self, handle: &[u8; 16]) -> Option<Parked> {
        let parked = self.logins.remove(handle)?;
        self.expiries.remove(&(parked.expires_at, Slot::Login(*handle)));
        let account = *parked.account.as_bytes();
        self.of_account.remove(&(account, *handle));
        if let Some(bucket) = parked.bucket
            && self.by_bucket.get(&bucket) == Some(handle)
        {
            self.by_bucket.remove(&bucket);
            self.release_bucket(&account, &bucket);
        }
        let device = parked.bucket.map(|bucket| (account, bucket));
        self.refund(parked.charged, PARKED_LOGIN_COST, device.as_ref());
        Some(parked)
    }

    fn remove_counter(&mut self, key: &(Class, [u8; 32])) -> Option<Counter> {
        let counter = self.counters.remove(key)?;
        self.expiries.remove(&(counter.expires_at(), Slot::Counter(key.0, key.1)));
        let device = counter.device_of.map(|account| (account, key.1));
        self.refund(counter.charged, COUNTER_COST, device.as_ref());
        if let Some(account) = counter.device_of {
            self.release_bucket(&account, &key.1);
        }
        Some(counter)
    }

    /// The pools a charge of `class` goes to. A device charge, which names
    /// its account and bucket, goes to the Device reserve only from the
    /// bucket that holds the account's share, or if none holds it yet: the
    /// account's other buckets are charged to Shared, never refused for the
    /// share. A device charge naming no bucket is a broken caller and gets
    /// Shared only.
    fn chain(&self, class: Class, device: Option<&([u8; 32], [u8; 32])>) -> &'static [Pool] {
        match (class, device) {
            (Class::Device, Some((account, bucket))) => match self.device_reserved.get(account) {
                Some((reserved, _)) if reserved != bucket => &[Pool::Shared],
                _ => Pool::chain(Class::Device),
            },
            (Class::Device, None) => &[Pool::Shared],
            _ => Pool::chain(class),
        }
    }

    /// Charges `units` to the first pool of the chain with room, and counts
    /// a charge to the Device reserve in the account's share.
    fn charge(&mut self, class: Class, device: Option<&([u8; 32], [u8; 32])>, units: u64) -> Option<Pool> {
        let pool = self.used.charge(self.chain(class, device), units)?;
        if pool == Pool::Device
            && let Some((account, bucket)) = device
        {
            let share = self.device_reserved.entry(*account).or_insert((*bucket, 0));
            share.1 = share.1.saturating_add(1);
        }
        Some(pool)
    }

    /// Gives `units` back to `pool`, and a charge to the Device reserve back
    /// to the account's share, which is free once nothing is left in it.
    fn refund(&mut self, pool: Pool, units: u64, device: Option<&([u8; 32], [u8; 32])>) {
        self.used.refund(pool, units);
        if pool == Pool::Device
            && let Some((account, bucket)) = device
            && let Some(share) = self.device_reserved.get_mut(account)
            && share.0 == *bucket
        {
            share.1 = share.1.saturating_sub(1);
            if share.1 == 0 {
                self.device_reserved.remove(account);
            }
        }
    }

    /// Whether `account` holds device `bucket`: its counter or its parked
    /// login is that account's.
    fn holds(&self, account: &[u8; 32], bucket: &[u8; 32]) -> bool {
        let by_counter = self
            .counters
            .get(&(Class::Device, *bucket))
            .is_some_and(|counter| counter.device_of.as_ref() == Some(account));
        let by_login = self
            .by_bucket
            .get(bucket)
            .and_then(|handle| self.logins.get(handle))
            .is_some_and(|parked| parked.account.as_bytes() == account);
        by_counter || by_login
    }

    /// Counts `bucket` for `account`, if nothing held it yet. Call before
    /// filing what will hold it.
    fn hold_bucket(&mut self, account: &[u8; 32], bucket: &[u8; 32]) {
        if !self.holds(account, bucket) {
            let tally = self.device_buckets.entry(*account).or_insert(0);
            *tally = tally.saturating_add(1);
        }
    }

    /// Stops counting `bucket` for `account` once nothing holds it. Call
    /// after removing what held it.
    fn release_bucket(&mut self, account: &[u8; 32], bucket: &[u8; 32]) {
        if !self.holds(account, bucket)
            && let Some(tally) = self.device_buckets.get_mut(account)
        {
            *tally = tally.saturating_sub(1);
            if *tally == 0 {
                self.device_buckets.remove(account);
            }
        }
    }

    /// Whether `account` may hold `bucket`: it holds it already, or holds
    /// fewer than [`DEVICE_BUCKETS_PER_ACCOUNT`] (after sweeping everything
    /// expired once, if not).
    fn may_hold(&mut self, account: &AccountId, bucket: &[u8; 32], now: i64) -> bool {
        let id = account.as_bytes();
        if self.holds(id, bucket) || self.device_tally(account) < DEVICE_BUCKETS_PER_ACCOUNT {
            return true;
        }
        self.sweep(now, usize::MAX);
        self.holds(id, bucket) || self.device_tally(account) < DEVICE_BUCKETS_PER_ACCOUNT
    }

    /// Removes up to `limit` entries expired at `now`, earliest first.
    fn sweep(&mut self, now: i64, limit: usize) -> u64 {
        let mut removed: u64 = 0;
        for _ in 0..limit {
            let Some(&(at, slot)) = self.expiries.first() else { break };
            if at > now {
                break;
            }
            self.expiries.remove(&(at, slot));
            let gone = match slot {
                Slot::Login(handle) => self.remove_login(&handle).is_some(),
                Slot::Counter(class, bucket) => self.remove_counter(&(class, bucket)).is_some(),
            };
            if gone {
                removed = removed.saturating_add(1);
            }
        }
        removed
    }

    /// The pool `units` would be charged to, sweeping everything expired
    /// once if nothing has room at first (which may free the account's
    /// share, so the chain is asked again).
    fn room(&mut self, class: Class, device: Option<&([u8; 32], [u8; 32])>, units: u64, now: i64) -> Option<Pool> {
        if let Some(pool) = self.used.room(self.chain(class, device), units) {
            return Some(pool);
        }
        self.sweep(now, usize::MAX);
        self.used.room(self.chain(class, device), units)
    }

    fn device_tally(&self, account: &AccountId) -> u8 {
        self.device_buckets.get(account.as_bytes()).copied().unwrap_or(0)
    }
}

/// Logins in progress and attempt counters of the accounts object, in its
/// memory only.
#[derive(Default)]
pub struct Scratch(RefCell<Inner>);

impl Scratch {
    fn inner(&self) -> Result<RefMut<'_, Inner>, AccessError> {
        self.0.try_borrow_mut().map_err(|_| AccessError::StoreUnavailable)
    }

    /// Counts an attempt on `class`'s budget, filed under `bucket`, and says
    /// whether it is within `limit` for the window. A full pool, or a new
    /// device bucket past the account's [`DEVICE_BUCKETS_PER_ACCOUNT`],
    /// refuses it uncounted; a device bucket other than the one holding the
    /// account's share of the Device reserve is charged to Shared. A `limit` outside 1 to
    /// [`ATTEMPT_LIMIT_CEILING`] is a broken caller: an error, which the
    /// throttle takes as a refusal.
    pub fn admit(
        &self,
        account: &AccountId,
        bucket: &[u8; 32],
        class: Class,
        limit: u16,
        now: UnixTime,
    ) -> Result<bool, AccessError> {
        if !(1..=ATTEMPT_LIMIT_CEILING).contains(&limit) {
            return Err(AccessError::StoreUnavailable);
        }
        let now = now.0;
        let mut guard = self.inner()?;
        let inner = &mut *guard;
        inner.sweep(now, SWEEP_ON_THE_WAY);
        let room = match class {
            Class::Registration => COUNTER_COST,
            Class::Login | Class::Device => ATTEMPT_AND_LOGIN,
        };
        let device_of = (class == Class::Device).then_some(*account.as_bytes());
        let device = device_of.map(|account| (account, *bucket));
        if inner.room(class, device.as_ref(), room, now).is_none() {
            return Ok(false);
        }
        let key = (class, *bucket);
        if let Some(counter) = inner.counters.get_mut(&key) {
            let ended = counter.expires_at();
            if ended <= now {
                // The window is over but not yet swept: a new one, in the
                // same room.
                counter.window_start = now;
                counter.attempts = 0;
                inner.expiries.remove(&(ended, Slot::Counter(class, *bucket)));
                inner.expiries.insert((counter.expires_at(), Slot::Counter(class, *bucket)));
            }
            counter.attempts = counter.attempts.saturating_add(1);
            return Ok(counter.attempts <= u32::from(limit));
        }
        if device_of.is_some() && !inner.may_hold(account, bucket, now) {
            return Ok(false);
        }
        let Some(charged) = inner.charge(class, device.as_ref(), COUNTER_COST) else { return Ok(false) };
        if let Some(account) = device_of {
            inner.hold_bucket(&account, bucket);
        }
        let counter = Counter { window_start: now, attempts: 1, charged, device_of };
        inner.expiries.insert((counter.expires_at(), Slot::Counter(class, *bucket)));
        inner.counters.insert(key, counter);
        Ok(true)
    }

    /// Parks a login until `expires_at`, charged to `class`'s pools. A login
    /// that spent a device budget names its `bucket`, replaces the one the
    /// bucket held, and holds the bucket for its account until it leaves: a
    /// new bucket past the account's [`DEVICE_BUCKETS_PER_ACCOUNT`] is
    /// refused, and one other than the bucket holding the account's share
    /// of the Device reserve is charged to Shared. A shared one names none.
    /// Registrations park nothing.
    #[allow(clippy::too_many_arguments)] // a login, whose, until when, under which budget, and the time now
    pub fn park(
        &self,
        handle: &LoginHandle,
        account: &AccountId,
        state: &LoginState,
        expires_at: UnixTime,
        class: Class,
        bucket: Option<&[u8; 32]>,
        now: UnixTime,
    ) -> Result<(), AccessError> {
        let bucket = match (class, bucket) {
            (Class::Login, None) => None,
            (Class::Device, Some(bucket)) => Some(*bucket),
            _ => return Err(AccessError::StoreUnavailable),
        };
        let now = now.0;
        let handle = *handle.expose();
        let mut inner = self.inner()?;
        inner.sweep(now, SWEEP_ON_THE_WAY);
        if inner.logins.contains_key(&handle) {
            return Err(AccessError::StoreUnavailable);
        }
        if let Some(bucket) = bucket
            && let Some(old) = inner.by_bucket.get(&bucket).copied()
        {
            inner.remove_login(&old);
        }
        if let Some(bucket) = bucket
            && !inner.may_hold(account, &bucket, now)
        {
            return Err(AccessError::StorageFull);
        }
        let device = bucket.map(|bucket| (*account.as_bytes(), bucket));
        if inner.room(class, device.as_ref(), PARKED_LOGIN_COST, now).is_none() {
            return Err(AccessError::StorageFull);
        }
        let Some(charged) = inner.charge(class, device.as_ref(), PARKED_LOGIN_COST) else {
            return Err(AccessError::StorageFull);
        };
        if let Some(bucket) = bucket {
            inner.hold_bucket(account.as_bytes(), &bucket);
            inner.by_bucket.insert(bucket, handle);
        }
        let parked = Parked { account: *account, expires_at: expires_at.0, charged, bucket, state: state.clone() };
        inner.expiries.insert((parked.expires_at, Slot::Login(handle)));
        inner.of_account.insert((*account.as_bytes(), handle));
        inner.logins.insert(handle, parked);
        Ok(())
    }

    /// Removes the login `handle` names, live or expired, and returns it only
    /// if still live at `now`: at most once.
    pub fn take(&self, handle: &LoginHandle, now: UnixTime) -> Result<Option<(AccountId, LoginState)>, AccessError> {
        let parked = self.inner()?.remove_login(handle.expose());
        Ok(parked.filter(|parked| parked.expires_at > now.0).map(|parked| (parked.account, parked.state)))
    }

    /// Drops the account's logins in progress. Its counters stay and end
    /// with their window.
    pub fn forget_account(&self, account: &AccountId) -> Result<(), AccessError> {
        let mut inner = self.inner()?;
        let id = *account.as_bytes();
        let handles: Vec<[u8; 16]> =
            inner.of_account.range((id, [0; 16])..=(id, [0xFF; 16])).map(|(_, handle)| *handle).collect();
        for handle in handles {
            inner.remove_login(&handle);
        }
        Ok(())
    }

    /// Removes up to `limit` logins and counters expired at `now` and says
    /// how many went. A counter expires when its window ends.
    pub fn sweep(&self, now: UnixTime, limit: usize) -> Result<u64, AccessError> {
        Ok(self.inner()?.sweep(now.0, limit))
    }
}

impl fmt::Debug for Scratch {
    /// Counts only: never a state, an account or a bucket.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(inner) = self.0.try_borrow() else { return f.debug_struct("Scratch").finish_non_exhaustive() };
        f.debug_struct("Scratch")
            .field("logins", &inner.logins.len())
            .field("counters", &inner.counters.len())
            .field("units", &(inner.used.shared, inner.used.registration, inner.used.device))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ENROLLS_PER_DAY;

    const T0: i64 = 1_800_000_000;

    fn at(seconds: i64) -> UnixTime {
        UnixTime(T0 + seconds)
    }

    fn numbered(n: u32, tag: u8) -> [u8; 32] {
        let mut bytes = [tag; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        bytes
    }

    fn account(n: u32) -> AccountId {
        AccountId::from_array(numbered(n, 0xA0))
    }

    fn bucket(n: u32) -> [u8; 32] {
        numbered(n, 0xB0)
    }

    fn tagged(n: u32, tag: u8) -> LoginHandle {
        let mut bytes = [tag; 16];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        LoginHandle::from_array(bytes)
    }

    fn handle(n: u32) -> LoginHandle {
        tagged(n, 0xC0)
    }

    fn state(byte: u8) -> LoginState {
        LoginState::from_slice(&[byte; LoginState::LEN]).unwrap()
    }

    /// [`file`] under [`handle`] `n`.
    fn attempt(scratch: &Scratch, n: u32, account: &AccountId, class: Class, bucket: &[u8; 32], now: i64) -> bool {
        file(scratch, &handle(n), account, class, bucket, now)
    }

    /// Admits an attempt at `now` and, unless it is a registration, parks its
    /// login for the whole window, as `begin_login` does. True when both went
    /// through.
    fn file(
        scratch: &Scratch,
        handle: &LoginHandle,
        account: &AccountId,
        class: Class,
        bucket: &[u8; 32],
        now: i64,
    ) -> bool {
        if scratch.admit(account, bucket, class, 10, at(now)) != Ok(true) {
            return false;
        }
        let device = (class == Class::Device).then_some(bucket);
        class == Class::Registration
            || scratch.park(handle, account, &state(1), at(now + 300), class, device, at(now)).is_ok()
    }

    /// A guess at a name, filed under the shared budget.
    fn guess(scratch: &Scratch, n: u32) -> bool {
        file(scratch, &tagged(n, 0xC1), &account(n), Class::Login, account(n).as_bytes(), 0)
    }

    /// Units charged to Shared, the Registration reserve and the Device reserve.
    fn units(scratch: &Scratch) -> (u64, u64, u64) {
        let used = &scratch.0.borrow().used;
        (used.shared, used.registration, used.device)
    }

    /// Fills Shared with guesses, each its own name: returns how many went in.
    fn fill_shared(scratch: &Scratch, from: u32) -> u32 {
        let mut n = from;
        while guess(scratch, n) {
            n += 1;
        }
        n - from
    }

    /// Device logins of `accounts` accounts with `passes` passes each (16 at
    /// most), numbered from `from`: returns how many went in.
    fn devices(scratch: &Scratch, from: u32, accounts: u32, passes: u32) -> u32 {
        let mut parked = 0;
        for a in from..from + accounts {
            for pass in 0..passes.min(u32::from(DEVICE_BUCKETS_PER_ACCOUNT)) {
                let n = a * 16 + pass;
                if file(scratch, &tagged(n, 0xC2), &account(a), Class::Device, &bucket(3_000_000 + n), 0) {
                    parked += 1;
                }
            }
        }
        parked
    }

    /// The device bucket `account` charges to the Device reserve, and how
    /// many of its charges (its counter, its login) are there.
    fn share(scratch: &Scratch, account: &AccountId) -> Option<([u8; 32], u8)> {
        scratch.0.borrow().device_reserved.get(account.as_bytes()).copied()
    }

    #[test]
    fn a_window_ends_at_exactly_sixty_seconds() {
        let scratch = Scratch::default();
        let ada = account(1);
        let admit = |now| scratch.admit(&ada, ada.as_bytes(), Class::Login, 2, at(now));
        assert_eq!(admit(0), Ok(true));
        assert_eq!(admit(59), Ok(true));
        assert_eq!(admit(59), Ok(false));
        assert_eq!(admit(60), Ok(true), "a new window starts 60 s after the first attempt");
        assert_eq!(admit(119), Ok(true));
        assert_eq!(admit(119), Ok(false));
    }

    #[test]
    fn attempts_past_the_limit_are_refused_until_the_window_ends() {
        let scratch = Scratch::default();
        let ada = account(1);
        let admit = |limit, now| scratch.admit(&ada, ada.as_bytes(), Class::Login, limit, at(now));
        for _ in 0..3 {
            assert_eq!(admit(3, 0), Ok(true));
        }
        for _ in 0..5 {
            assert_eq!(admit(3, 10), Ok(false));
        }
        assert_eq!(scratch.0.borrow().counters.len(), 1);
        assert_eq!(admit(3, 60), Ok(true));
        assert_eq!(admit(0, 60), Err(AccessError::StoreUnavailable), "a broken caller fails closed");
        assert_eq!(admit(ATTEMPT_LIMIT_CEILING + 1, 60), Err(AccessError::StoreUnavailable));
        assert_eq!(admit(ATTEMPT_LIMIT_CEILING, 60), Ok(true));
    }

    #[test]
    fn a_new_window_reuses_its_counters_room() {
        let scratch = Scratch::default();
        let ada = account(1);
        let registration = bucket(1);
        let both = |now| {
            assert_eq!(scratch.admit(&ada, ada.as_bytes(), Class::Login, 10, at(now)), Ok(true));
            assert_eq!(scratch.admit(&ada, &registration, Class::Registration, 10, at(now)), Ok(true));
        };
        both(0);
        // A hundred names that expire first, more than an admit sweeps on its
        // way, so at 60 s ada's counter is over but still there.
        for n in 100..200 {
            assert_eq!(scratch.admit(&account(n), account(n).as_bytes(), Class::Login, 10, at(-1)), Ok(true));
        }
        assert_eq!(scratch.admit(&ada, ada.as_bytes(), Class::Login, 1, at(60)), Ok(true), "a new window");
        assert_eq!(scratch.0.borrow().counters.len(), 36 + 2, "swept on the way: 64 of the hundred, not ada's");
        assert_eq!(scratch.0.borrow().expiries.len(), 36 + 2, "the old window's expiry goes with it");
        assert_eq!(units(&scratch), (COUNTER_COST * 37, COUNTER_COST, 0));
        assert_eq!(scratch.admit(&ada, ada.as_bytes(), Class::Login, 1, at(119)), Ok(false), "counted afresh");
        for now in [120, 180, 600] {
            both(now);
            assert_eq!(units(&scratch), (COUNTER_COST, COUNTER_COST, 0));
            assert_eq!(scratch.0.borrow().expiries.len(), 2);
        }
    }

    #[test]
    fn shared_holds_its_ceiling_and_no_more() {
        let scratch = Scratch::default();
        let guesses = fill_shared(&scratch, 0);
        assert_eq!(u64::from(guesses), SHARED_POOL / (COUNTER_COST + PARKED_LOGIN_COST));
        assert_eq!(units(&scratch), (SHARED_POOL, 0, 0));
        assert_eq!(scratch.admit(&account(guesses), account(guesses).as_bytes(), Class::Login, 10, at(0)), Ok(false));
        assert_eq!(
            scratch.park(&handle(guesses), &account(0), &state(1), at(300), Class::Login, None, at(0)),
            Err(AccessError::StorageFull)
        );
        assert_eq!(units(&scratch), (SHARED_POOL, 0, 0));
    }

    #[test]
    fn registrations_overflow_into_shared() {
        let scratch = Scratch::default();
        let mut n = 0;
        while attempt(&scratch, n, &account(n), Class::Registration, &bucket(n), 0) {
            n += 1;
        }
        assert_eq!(u64::from(n), (REGISTRATION_RESERVE + SHARED_POOL) / COUNTER_COST, "17 MiB of counters");
        assert_eq!(units(&scratch), (SHARED_POOL, REGISTRATION_RESERVE, 0));
    }

    #[test]
    fn a_window_later_everything_swept_returns_every_unit() {
        let scratch = Scratch::default();
        let (ada, bob) = (account(1), account(2));
        assert!(attempt(&scratch, 1, &ada, Class::Login, ada.as_bytes(), 0));
        assert!(attempt(&scratch, 2, &ada, Class::Device, &bucket(1), 0));
        assert!(attempt(&scratch, 3, &bob, Class::Registration, &bucket(2), 0));
        assert!(attempt(&scratch, 4, &bob, Class::Device, &bucket(3), 30));
        assert_eq!(units(&scratch), (512, 128, 1024));

        assert_eq!(scratch.sweep(at(59), usize::MAX), Ok(0));
        assert_eq!(scratch.sweep(at(60), 1), Ok(1), "a limit stops the sweep");
        assert_eq!(scratch.sweep(at(60), usize::MAX), Ok(2));
        assert_eq!(scratch.sweep(at(90), usize::MAX), Ok(1));
        assert_eq!(scratch.sweep(at(330), usize::MAX), Ok(3));
        assert_eq!(scratch.sweep(at(330), usize::MAX), Ok(0));

        assert_eq!(units(&scratch), (0, 0, 0));
        let inner = scratch.0.borrow();
        assert!(inner.logins.is_empty() && inner.counters.is_empty() && inner.expiries.is_empty());
        assert!(inner.by_bucket.is_empty() && inner.of_account.is_empty() && inner.device_buckets.is_empty());
        assert!(inner.device_reserved.is_empty());
    }

    #[test]
    fn an_accounts_second_device_bucket_goes_to_shared() {
        let scratch = Scratch::default();
        let (ada, bob) = (account(1), account(2));
        assert!(attempt(&scratch, 1, &ada, Class::Device, &bucket(1), 0));
        assert_eq!(units(&scratch), (0, 0, DEVICE_SHARE_PER_ACCOUNT), "the first bucket in the reserve");
        assert!(attempt(&scratch, 2, &ada, Class::Device, &bucket(2), 0), "a second bucket is not refused");
        assert_eq!(units(&scratch), (DEVICE_SHARE_PER_ACCOUNT, 0, DEVICE_SHARE_PER_ACCOUNT), "it goes to Shared");
        assert!(attempt(&scratch, 3, &ada, Class::Device, &bucket(1), 1), "the first bucket again");
        assert_eq!(units(&scratch), (DEVICE_SHARE_PER_ACCOUNT, 0, DEVICE_SHARE_PER_ACCOUNT), "its login replaced");
        assert_eq!(share(&scratch, &ada), Some((bucket(1), 2)), "a counter and a login");
        assert!(attempt(&scratch, 4, &bob, Class::Device, &bucket(3), 0));
        assert_eq!(units(&scratch), (DEVICE_SHARE_PER_ACCOUNT, 0, 2 * DEVICE_SHARE_PER_ACCOUNT), "bob has his own");
    }

    #[test]
    fn the_device_share_comes_back_once_on_every_way_out() {
        let scratch = Scratch::default();
        let ada = account(1);
        let reserve = || units(&scratch).2;

        // A counter swept at the end of its window.
        assert_eq!(scratch.admit(&ada, &bucket(1), Class::Device, 10, at(0)), Ok(true));
        assert_eq!((share(&scratch, &ada), reserve()), (Some((bucket(1), 1)), COUNTER_COST));
        assert_eq!(scratch.sweep(at(60), usize::MAX), Ok(1));
        assert_eq!((share(&scratch, &ada), reserve()), (None, 0));
        assert_eq!(scratch.sweep(at(60), usize::MAX), Ok(0));

        // A login taken, then its counter swept.
        assert!(attempt(&scratch, 1, &ada, Class::Device, &bucket(2), 100));
        assert_eq!(share(&scratch, &ada), Some((bucket(2), 2)));
        assert_eq!(scratch.take(&handle(1), at(101)), Ok(Some((ada, state(1)))));
        assert_eq!((share(&scratch, &ada), reserve()), (Some((bucket(2), 1)), COUNTER_COST));
        assert_eq!(scratch.take(&handle(1), at(101)), Ok(None));
        assert_eq!(share(&scratch, &ada), Some((bucket(2), 1)), "taken once, given back once");
        assert_eq!(scratch.sweep(at(160), usize::MAX), Ok(1));
        assert_eq!((share(&scratch, &ada), reserve()), (None, 0));

        // A login replaced in its bucket: one given back, one charged.
        assert!(attempt(&scratch, 2, &ada, Class::Device, &bucket(3), 200));
        assert!(attempt(&scratch, 3, &ada, Class::Device, &bucket(3), 201));
        assert_eq!((share(&scratch, &ada), reserve()), (Some((bucket(3), 2)), DEVICE_SHARE_PER_ACCOUNT));
        assert_eq!(scratch.take(&handle(2), at(202)), Ok(None), "the replaced login is gone");
        assert_eq!(share(&scratch, &ada), Some((bucket(3), 2)));
        assert_eq!(scratch.sweep(at(260), usize::MAX), Ok(1));
        assert_eq!(scratch.take(&handle(3), at(261)), Ok(Some((ada, state(1)))));
        assert_eq!((share(&scratch, &ada), reserve()), (None, 0));

        // A login expired, swept or taken late.
        assert!(attempt(&scratch, 4, &ada, Class::Device, &bucket(4), 1000));
        assert_eq!(scratch.sweep(at(1300), usize::MAX), Ok(2), "the counter and the login");
        assert_eq!((share(&scratch, &ada), reserve()), (None, 0));
        assert!(attempt(&scratch, 5, &ada, Class::Device, &bucket(5), 2000));
        assert_eq!(scratch.sweep(at(2060), usize::MAX), Ok(1));
        assert_eq!(scratch.take(&handle(5), at(2300)), Ok(None), "expired at 2300");
        assert_eq!((share(&scratch, &ada), reserve()), (None, 0));

        // An account forgotten: its counter keeps its part.
        assert!(attempt(&scratch, 6, &ada, Class::Device, &bucket(6), 3000));
        assert_eq!(scratch.forget_account(&ada), Ok(()));
        assert_eq!((share(&scratch, &ada), reserve()), (Some((bucket(6), 1)), COUNTER_COST));
        assert_eq!(scratch.sweep(at(3060), usize::MAX), Ok(1));
        assert_eq!((share(&scratch, &ada), reserve()), (None, 0));

        // Once given back, the share serves the account's next bucket.
        assert!(attempt(&scratch, 7, &ada, Class::Device, &bucket(7), 4000));
        assert_eq!(units(&scratch), (0, 0, DEVICE_SHARE_PER_ACCOUNT));
        assert_eq!(share(&scratch, &ada), Some((bucket(7), 2)));
    }

    #[test]
    fn a_bucket_charged_to_shared_gives_nothing_back_to_the_share() {
        let scratch = Scratch::default();
        let ada = account(1);
        assert_eq!(scratch.admit(&ada, &bucket(1), Class::Device, 10, at(0)), Ok(true));
        assert!(attempt(&scratch, 1, &ada, Class::Device, &bucket(2), 30), "in Shared");
        assert_eq!(units(&scratch), (DEVICE_SHARE_PER_ACCOUNT, 0, COUNTER_COST));
        assert_eq!(scratch.take(&handle(1), at(31)), Ok(Some((ada, state(1)))));
        assert_eq!(share(&scratch, &ada), Some((bucket(1), 1)), "Shared's refund leaves the share alone");
        assert_eq!(units(&scratch), (COUNTER_COST, 0, COUNTER_COST));
        assert_eq!(scratch.sweep(at(60), usize::MAX), Ok(1));
        assert_eq!(share(&scratch, &ada), None);
        // The second bucket's counter lives on in Shared; its next login
        // takes the free share.
        assert!(attempt(&scratch, 2, &ada, Class::Device, &bucket(2), 61));
        assert_eq!(units(&scratch), (COUNTER_COST, 0, PARKED_LOGIN_COST));
        assert_eq!(share(&scratch, &ada), Some((bucket(2), 1)));
        assert_eq!(scratch.sweep(at(90), usize::MAX), Ok(1), "the Shared counter");
        assert_eq!(share(&scratch, &ada), Some((bucket(2), 1)));
        assert_eq!(scratch.take(&handle(2), at(91)), Ok(Some((ada, state(1)))));
        assert_eq!((share(&scratch, &ada), units(&scratch)), (None, (0, 0, 0)));
    }

    #[test]
    fn take_returns_a_login_once_and_drops_an_expired_one_unreturned() {
        let scratch = Scratch::default();
        let ada = account(1);
        let park = |n, byte| scratch.park(&handle(n), &ada, &state(byte), at(300), Class::Login, None, at(0));
        park(1, 0xAB).unwrap();
        park(2, 0xAB).unwrap();
        let debug = format!("{scratch:?}");
        assert!(debug.contains("logins: 2"), "{debug}");
        assert!(!debug.contains("171") && !debug.contains("160"), "no state or account bytes: {debug}");

        assert_eq!(scratch.take(&handle(1), at(299)), Ok(Some((ada, state(0xAB)))));
        assert_eq!(scratch.take(&handle(1), at(299)), Ok(None));
        assert_eq!(scratch.take(&handle(2), at(300)), Ok(None), "expired at 300");
        assert_eq!(units(&scratch), (0, 0, 0), "the expired login went too");
        assert!(scratch.0.borrow().expiries.is_empty());
        assert_eq!(scratch.take(&handle(2), at(0)), Ok(None));
    }

    #[test]
    fn forgetting_an_account_drops_its_logins_and_keeps_every_count() {
        let scratch = Scratch::default();
        let (ada, bob) = (account(1), account(2));
        assert!(attempt(&scratch, 1, &ada, Class::Login, ada.as_bytes(), 0));
        assert!(attempt(&scratch, 2, &ada, Class::Device, &bucket(1), 0));
        assert!(attempt(&scratch, 3, &bob, Class::Login, bob.as_bytes(), 0));

        assert_eq!(scratch.forget_account(&ada), Ok(()));
        assert_eq!(scratch.take(&handle(1), at(1)), Ok(None));
        assert_eq!(scratch.take(&handle(2), at(1)), Ok(None));
        assert_eq!(scratch.take(&handle(3), at(1)), Ok(Some((bob, state(1)))));
        assert_eq!(scratch.0.borrow().counters.len(), 3, "counters age out on their own");
        assert_eq!(units(&scratch), (2 * COUNTER_COST, 0, COUNTER_COST));
        assert!(scratch.0.borrow().by_bucket.is_empty());
    }

    #[test]
    fn a_device_bucket_keeps_one_login_the_newest() {
        let scratch = Scratch::default();
        let ada = account(1);
        let pass = bucket(1);
        assert_eq!(scratch.admit(&ada, &pass, Class::Device, 10, at(0)), Ok(true));
        let park = |n, byte| scratch.park(&handle(n), &ada, &state(byte), at(300), Class::Device, Some(&pass), at(0));
        park(1, 1).unwrap();
        park(2, 2).unwrap();
        assert_eq!(units(&scratch), (0, 0, COUNTER_COST + PARKED_LOGIN_COST));
        assert_eq!(scratch.0.borrow().logins.len(), 1, "the replaced state is dropped");
        assert_eq!(scratch.take(&handle(1), at(1)), Ok(None));
        assert_eq!(scratch.take(&handle(2), at(1)), Ok(Some((ada, state(2)))));
        // The shared budget is not one bucket: each login stays.
        park_login(&scratch, 3, &ada);
        park_login(&scratch, 4, &ada);
        assert_eq!(scratch.0.borrow().logins.len(), 2);
    }

    fn park_login(scratch: &Scratch, n: u32, account: &AccountId) {
        scratch.park(&handle(n), account, &state(1), at(300), Class::Login, None, at(0)).unwrap();
    }

    mod adversary {
        use super::*;

        #[test]
        fn shared_full_registrations_and_devices_still_go_through() {
            let scratch = Scratch::default();
            fill_shared(&scratch, 0);
            let ada = account(1);
            assert!(attempt(&scratch, 1_000_001, &ada, Class::Registration, &bucket(1), 0));
            assert!(attempt(&scratch, 1_000_002, &ada, Class::Device, &bucket(2), 0));
            assert_eq!(units(&scratch), (SHARED_POOL, COUNTER_COST, COUNTER_COST + PARKED_LOGIN_COST));
        }

        #[test]
        fn device_logins_overflow_into_shared_and_stop_when_both_are_full() {
            let scratch = Scratch::default();
            let reserve = DEVICE_RESERVE / DEVICE_SHARE_PER_ACCOUNT;
            assert_eq!(u64::from(devices(&scratch, 0, reserve as u32, 1)), reserve, "one pass each");
            assert_eq!(units(&scratch), (0, 0, DEVICE_RESERVE));
            assert!(attempt(&scratch, 1, &account(5000), Class::Device, &bucket(1), 0));
            assert_eq!(units(&scratch), (COUNTER_COST + PARKED_LOGIN_COST, 0, DEVICE_RESERVE));
            fill_shared(&scratch, 0);
            assert_eq!(units(&scratch), (SHARED_POOL, 0, DEVICE_RESERVE));
            assert!(!attempt(&scratch, 2, &account(5001), Class::Device, &bucket(2), 0));
        }

        #[test]
        fn a_days_sybil_accounts_at_sixteen_passes_leave_the_device_reserve_room() {
            // Each account may hold 16 device buckets: if each could put them
            // all in the reserve, 1,024 self-registered accounts would fill
            // it, and the owners' devices would fall into Shared, which
            // guessing fills. One bucket each goes to the reserve, the rest
            // to Shared.
            let scratch = Scratch::default();
            let passes = u32::from(DEVICE_BUCKETS_PER_ACCOUNT);
            let parked = devices(&scratch, 0, ENROLLS_PER_DAY, passes);
            assert!(parked < ENROLLS_PER_DAY * passes, "Shared ran out");
            let (shared, _, reserve) = units(&scratch);
            assert_eq!(reserve, u64::from(ENROLLS_PER_DAY) * DEVICE_SHARE_PER_ACCOUNT, "one bucket each");
            assert!(SHARED_POOL - shared < DEVICE_SHARE_PER_ACCOUNT, "the other fifteen filled Shared");
            assert!(attempt(&scratch, 1, &account(900_000), Class::Device, &bucket(1), 0), "a fresh account");
            assert_eq!(units(&scratch).2, reserve + DEVICE_SHARE_PER_ACCOUNT);
            assert_eq!(scratch.take(&handle(1), at(1)), Ok(Some((account(900_000), state(1)))));
        }

        #[test]
        fn a_pass_parking_again_and_again_leaves_room_for_another_pass() {
            let scratch = Scratch::default();
            fill_shared(&scratch, 0);
            let room = 3 * DEVICE_SHARE_PER_ACCOUNT;
            let mut n = 0;
            while units(&scratch).2 < DEVICE_RESERVE - room {
                let filed = file(&scratch, &tagged(n, 0xC2), &account(10_000 + n), Class::Device, &bucket(n), 0);
                assert!(filed);
                n += 1;
            }
            let ada = account(1);
            let stolen = bucket(1_000_000);
            for n in 0..50 {
                assert_eq!(scratch.admit(&ada, &stolen, Class::Device, ATTEMPT_LIMIT_CEILING, at(0)), Ok(true));
                scratch.park(&handle(n), &ada, &state(1), at(300), Class::Device, Some(&stolen), at(0)).unwrap();
            }
            assert_eq!(units(&scratch).2, DEVICE_RESERVE - 2 * DEVICE_SHARE_PER_ACCOUNT, "one counter and one login");
            // The stolen pass holds ada's share: her other passes go to
            // Shared, which guessing filled. Other accounts keep their room.
            assert!(!attempt(&scratch, 50, &ada, Class::Device, &bucket(1_000_001), 0), "ada's share is held");
            assert!(attempt(&scratch, 51, &account(2), Class::Device, &bucket(1_000_002), 0), "bob's pass");
            assert!(attempt(&scratch, 52, &account(3), Class::Device, &bucket(1_000_003), 0), "carol's pass");
            assert!(!attempt(&scratch, 53, &account(4), Class::Device, &bucket(1_000_004), 0), "and now it is full");
        }

        #[test]
        fn an_account_counts_at_most_sixteen_live_device_buckets() {
            let scratch = Scratch::default();
            let (ada, bob) = (account(1), account(2));
            let admit = |who, pass, now| scratch.admit(who, &bucket(pass), Class::Device, 10, at(now));
            for pass in 0..u32::from(DEVICE_BUCKETS_PER_ACCOUNT) {
                assert_eq!(admit(&ada, pass, 0), Ok(true));
            }
            assert_eq!(admit(&ada, 16, 1), Ok(false), "a seventeenth pass");
            assert_eq!(admit(&ada, 0, 1), Ok(true), "a known pass still counts");
            assert_eq!(admit(&bob, 17, 1), Ok(true), "another account is untouched");
            assert_eq!(admit(&ada, 16, 60), Ok(true), "the old windows are over");
            assert_eq!(scratch.0.borrow().device_buckets.get(ada.as_bytes()), Some(&1));
        }

        #[test]
        fn parked_device_logins_count_against_their_account_after_the_counters_go() {
            // A counter lives 60 s, a parked login 300 s: if only counters
            // counted, one account rotating passes would hold a parked login
            // for every pass it ever used, and fill the Device reserve alone.
            let scratch = Scratch::default();
            let (ada, bob) = (account(1), account(2));
            let passes = u32::from(DEVICE_BUCKETS_PER_ACCOUNT);
            for pass in 0..passes {
                assert!(attempt(&scratch, pass, &ada, Class::Device, &bucket(pass), 0), "pass {pass}");
            }
            assert_eq!(scratch.sweep(at(61), usize::MAX), Ok(u64::from(passes)), "every counter went");
            assert_eq!(scratch.0.borrow().logins.len(), passes as usize, "every login is still parked");
            assert!(!attempt(&scratch, 100, &ada, Class::Device, &bucket(100), 61), "a seventeenth pass");
            let parked = (DEVICE_BUCKETS_PER_ACCOUNT, passes as usize);
            assert_eq!(scratch.0.borrow().device_buckets.get(ada.as_bytes()).copied(), Some(parked.0));
            assert_eq!(scratch.0.borrow().logins.len(), parked.1, "the refusal parked nothing");
            // Parking under a pass with no counter is refused the same way.
            let stray = scratch.park(&handle(101), &ada, &state(1), at(361), Class::Device, Some(&bucket(101)), at(61));
            assert_eq!(stray, Err(AccessError::StorageFull));
            // The sixteen passes the account holds still work, each counted once.
            for pass in 0..passes {
                assert!(attempt(&scratch, 200 + pass, &ada, Class::Device, &bucket(pass), 61), "pass {pass} again");
                assert_eq!(scratch.take(&handle(200 + pass), at(62)), Ok(Some((ada, state(1)))));
            }
            assert_eq!(scratch.0.borrow().device_buckets.get(ada.as_bytes()).copied(), Some(parked.0));
            assert!(attempt(&scratch, 300, &bob, Class::Device, &bucket(300), 61), "another account is untouched");
            // Once a pass's counter and login are both gone, its place is free.
            assert!(attempt(&scratch, 301, &ada, Class::Device, &bucket(100), 121), "the old windows are over");
            assert_eq!(scratch.0.borrow().device_buckets.get(ada.as_bytes()).copied(), Some(1));
        }

        #[test]
        fn a_device_bucket_is_counted_once_whatever_holds_it() {
            let scratch = Scratch::default();
            let ada = account(1);
            let tally = || scratch.0.borrow().device_buckets.get(ada.as_bytes()).copied();
            assert!(attempt(&scratch, 1, &ada, Class::Device, &bucket(1), 0));
            assert_eq!(tally(), Some(1), "a counter and a login in one bucket");
            assert!(attempt(&scratch, 2, &ada, Class::Device, &bucket(1), 1), "the login replaced");
            assert_eq!(tally(), Some(1));
            assert_eq!(scratch.sweep(at(60), usize::MAX), Ok(1), "the counter goes, the login stays");
            assert_eq!(tally(), Some(1));
            assert_eq!(scratch.take(&handle(2), at(61)), Ok(Some((ada, state(1)))));
            assert_eq!(tally(), None, "nothing holds the bucket");
            assert!(attempt(&scratch, 3, &ada, Class::Device, &bucket(2), 61));
            assert_eq!(scratch.forget_account(&ada), Ok(()));
            assert_eq!(tally(), Some(1), "the counter still holds its bucket");
            assert_eq!(scratch.sweep(at(121), usize::MAX), Ok(1));
            assert_eq!(tally(), None);
            assert!(scratch.0.borrow().device_buckets.is_empty());
        }

        #[test]
        fn when_full_a_name_with_a_live_counter_and_one_without_hear_the_same() {
            let scratch = Scratch::default();
            let (known, fresh) = (account(1), account(1_000_000));
            assert_eq!(scratch.admit(&known, known.as_bytes(), Class::Login, 10, at(0)), Ok(true));
            fill_shared(&scratch, 2);
            assert!(SHARED_POOL - units(&scratch).0 < COUNTER_COST + PARKED_LOGIN_COST);
            assert!(SHARED_POOL - units(&scratch).0 >= COUNTER_COST, "room for a counter, not for a login");

            let before = units(&scratch);
            for who in [&known, &fresh] {
                assert_eq!(scratch.admit(who, who.as_bytes(), Class::Login, 10, at(1)), Ok(false));
            }
            assert_eq!(units(&scratch), before);
            let attempts = scratch.0.borrow().counters.get(&(Class::Login, *known.as_bytes())).map(|c| c.attempts);
            assert_eq!(attempts, Some(1), "a refusal counts nothing");
        }

        #[test]
        fn a_handle_parked_twice_is_refused() {
            let scratch = Scratch::default();
            let ada = account(1);
            let pass = bucket(1);
            park_login(&scratch, 1, &ada);
            assert_eq!(
                scratch.park(&handle(1), &ada, &state(2), at(300), Class::Login, None, at(0)),
                Err(AccessError::StoreUnavailable)
            );
            assert_eq!(scratch.take(&handle(1), at(1)), Ok(Some((ada, state(1)))), "the first stays");
            for (class, bucket) in [(Class::Registration, None), (Class::Login, Some(&pass)), (Class::Device, None)] {
                assert_eq!(
                    scratch.park(&handle(2), &ada, &state(1), at(300), class, bucket, at(0)),
                    Err(AccessError::StoreUnavailable)
                );
            }
            assert_eq!(units(&scratch), (0, 0, 0));
        }
    }
}
