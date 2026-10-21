//! The account rules over the accounts object's ordered key-value store,
//! one atomic step per call, with the logins in progress and the attempt
//! counters in its memory ([`Scratch`]): the Access store, kept by Sigylo.
//!
//! Every method is a plain `fn`. The Durable Object runs one request at a
//! time only up to its first `await`, so a step that waited could see
//! another request's half-done work; a ledger that never waits cannot.
//! Memory is touched only once the step it follows has committed: if the
//! commit fails, the worst left behind is a login used up or one attempt
//! counted too many, and both fail safe.

use core::cell::Cell;

use access::{
    AccessError, AccountId, Keyring, KeyringSnapshot, KeyringVersion, KeyringWrite, LOGIN_WINDOW_SECONDS, LoginHandle,
    LoginState, MAX_SESSIONS, RegistrationRecord, SESSION_SECONDS, SessionDigest, UnixTime,
};
use custody::CustodyError;

use super::ports::{Clock, KeyValue};
use super::scratch::Scratch;
use crate::core::account_keys as keys;
use crate::core::{
    ACCOUNT_BYTES_CEILING, ACCOUNT_COST, ACCOUNT_PURGE_BATCHES, ACCOUNT_TEARDOWN_ROWS_PER_DAY, AccountRecord,
    AccountUsage, Class, ENROLLS_PER_DAY, KEYRING_ROWS_PER_DAY, KeyringRecord, PURGE_BATCH, SECONDS_PER_DAY,
    SESSION_BYTES_CEILING, SESSION_COST, SESSION_ROWS_PER_DAY, SessionRecord, snapshot,
};

/// Index entries one account's sessions may have: [`MAX_SESSIONS`], and one
/// stale entry left by damage, which the next walk clears. More is not an
/// account's index.
const MEMBER_ENTRIES: usize = MAX_SESSIONS as usize + 1;

/// Whose daily allowance a step's rows count against, besides the day's
/// total: a flood of one class never stops another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rows {
    Sessions,
    Keyrings,
    /// Accounts (counted by number) and teardown (never refused).
    Others,
}

/// A live session, as an index walk finds it.
struct Member {
    digest: SessionDigest,
    record: SessionRecord,
}

/// The Access store's rules on a [`KeyValue`] store and a [`Scratch`].
#[derive(Debug)]
pub struct AccountLedger<'s, K, C> {
    kv: K,
    scratch: &'s Scratch,
    clock: C,
    /// Writes made by the step in progress.
    writes: Cell<u32>,
}

fn day(now: UnixTime) -> u32 {
    u32::try_from(now.0.div_euclid(SECONDS_PER_DAY)).unwrap_or(0)
}

fn after(now: UnixTime, seconds: u32) -> UnixTime {
    UnixTime(now.0.saturating_add(i64::from(seconds)))
}

/// A record that does not decode is damage, not absence: refuse to act on it.
fn damaged() -> CustodyError {
    CustodyError::VaultUnavailable
}

/// What the Access context hears of a store fault: full is full, anything
/// else is a store that cannot answer.
fn fault(error: CustodyError) -> AccessError {
    match error {
        CustodyError::StorageFull => AccessError::StorageFull,
        _ => AccessError::StoreUnavailable,
    }
}

impl<'s, K: KeyValue, C: Clock> AccountLedger<'s, K, C> {
    pub fn new(kv: K, scratch: &'s Scratch, clock: C) -> Self {
        Self { kv, scratch, clock, writes: Cell::new(0) }
    }

    fn now(&self) -> UnixTime {
        UnixTime(self.clock.now().0)
    }

    // ---- storage, counting every write -------------------------------

    fn put(&self, key: &str, value: &[u8]) -> Result<(), CustodyError> {
        self.writes.set(self.writes.get().saturating_add(1));
        self.kv.put(key, value)
    }

    fn delete(&self, key: &str) -> Result<(), CustodyError> {
        self.writes.set(self.writes.get().saturating_add(1));
        self.kv.delete(key)
    }

    fn read<T>(&self, key: &str, decode: impl Fn(&[u8]) -> Option<T>) -> Result<Option<T>, CustodyError> {
        match self.kv.get(key)? {
            None => Ok(None),
            Some(bytes) => decode(&bytes).map(Some).ok_or_else(damaged),
        }
    }

    fn usage(&self, now: UnixTime) -> Result<AccountUsage, CustodyError> {
        Ok(self.read(keys::ACCOUNT_USAGE, AccountUsage::decode)?.unwrap_or_default().on(day(now)))
    }

    /// Runs one atomic step. If it wrote anything, the usage it updated is
    /// written too, and its rows, that write included, are counted for the
    /// day and for `rows`.
    fn step<T>(
        &self,
        now: UnixTime,
        rows: Rows,
        f: impl FnOnce(&mut AccountUsage) -> Result<T, CustodyError>,
    ) -> Result<T, CustodyError> {
        self.kv.atomically(|| {
            self.writes.set(0);
            let mut usage = self.usage(now)?;
            let out = f(&mut usage)?;
            let written = self.writes.get();
            if written > 0 {
                let written = written.saturating_add(1);
                usage.rows = usage.rows.saturating_add(written);
                match rows {
                    Rows::Sessions => usage.session_rows = usage.session_rows.saturating_add(written),
                    Rows::Keyrings => usage.keyring_rows = usage.keyring_rows.saturating_add(written),
                    Rows::Others => {}
                }
                self.kv.put(keys::ACCOUNT_USAGE, &usage.encode())?;
            }
            Ok(out)
        })
    }

    // ---- records -------------------------------------------------------

    fn account(&self, account: &AccountId) -> Result<Option<AccountRecord>, CustodyError> {
        self.read(&keys::account(account), AccountRecord::decode)
    }

    fn keyring_record(&self, account: &AccountId) -> Result<Option<KeyringRecord>, CustodyError> {
        self.read(&keys::keyring(account), KeyringRecord::decode)
    }

    fn session(&self, digest: &SessionDigest) -> Result<Option<SessionRecord>, CustodyError> {
        self.read(&keys::session(digest), SessionRecord::decode)
    }

    /// The account behind a session that lives at `now`, if its account
    /// does too.
    fn live_session(&self, now: UnixTime, digest: &SessionDigest) -> Result<Option<AccountId>, CustodyError> {
        let Some(session) = self.session(digest)?.filter(|s| s.expires_at > now) else { return Ok(None) };
        Ok(self.account(&session.account)?.map(|_| session.account))
    }

    /// Deletes a session and both its index entries; its weight is free again.
    fn remove_session(
        &self,
        usage: &mut AccountUsage,
        digest: &SessionDigest,
        session: &SessionRecord,
    ) -> Result<(), CustodyError> {
        self.delete(&keys::session(digest))?;
        self.delete(&keys::member_session(&session.account, session.expires_at, digest))?;
        self.delete(&keys::session_expiry(session.expires_at, digest))?;
        usage.sessions = usage.sessions.saturating_sub(SESSION_COST);
        Ok(())
    }

    /// The account's sessions, earliest expiry first, then lowest digest.
    /// An index entry whose session is gone, or is another account's or
    /// expires at another time, is stale: it is deleted, and nothing it
    /// named is touched.
    fn members(&self, account: &AccountId) -> Result<Vec<Member>, CustodyError> {
        let (start, end) = keys::sessions_of(account);
        let entries = self.kv.range(&start, &end, MEMBER_ENTRIES + 1)?;
        if entries.len() > MEMBER_ENTRIES {
            return Err(damaged());
        }
        let mut members = Vec::with_capacity(entries.len());
        for (key, _) in entries {
            let (owner, expires_at, digest) = keys::parse_member_session(&key).ok_or_else(damaged)?;
            match self.session(&digest)? {
                Some(record) if owner == *account && record.account == owner && record.expires_at == expires_at => {
                    members.push(Member { digest, record });
                }
                _ => self.delete(&key)?,
            }
        }
        Ok(members)
    }

    /// Whether today's rows leave room for purging (see
    /// [`ACCOUNT_TEARDOWN_ROWS_PER_DAY`]).
    fn may_tear_down(&self, now: UnixTime) -> Result<bool, CustodyError> {
        Ok(self.usage(now)?.rows < ACCOUNT_TEARDOWN_ROWS_PER_DAY)
    }

    /// Removes expired sessions, earliest first, in one step that looks at
    /// [`PURGE_BATCH`] index entries at most. Says how many went, and
    /// whether more may be waiting.
    fn purge_batch(&self, now: UnixTime) -> Result<(u64, bool), CustodyError> {
        if !self.may_tear_down(now)? {
            return Ok((0, false));
        }
        self.step(now, Rows::Others, |usage| {
            let expired = self.kv.range(keys::SESSION_EXPIRY, &keys::session_expiry_bound(now), PURGE_BATCH)?;
            let more = expired.len() == PURGE_BATCH;
            let mut gone: u64 = 0;
            for (key, _) in expired {
                let (at, digest) = keys::parse_session_expiry(&key).ok_or_else(damaged)?;
                match self.session(&digest)? {
                    Some(session) if session.expires_at == at => {
                        self.remove_session(usage, &digest, &session)?;
                        gone = gone.saturating_add(1);
                    }
                    _ => self.delete(&key)?,
                }
            }
            Ok((gone, more))
        })
    }

    fn purge_sessions(&self, now: UnixTime) -> Result<u64, CustodyError> {
        let mut gone: u64 = 0;
        for _ in 0..ACCOUNT_PURGE_BATCHES {
            let (batch, more) = self.purge_batch(now)?;
            gone = gone.saturating_add(batch);
            if !more {
                break;
            }
        }
        Ok(gone)
    }

    // ---- use cases -----------------------------------------------------

    /// False when the name is taken: that answer comes before any ceiling,
    /// so a taken name says taken even on a full store.
    pub fn enroll(&self, account: &AccountId, record: &RegistrationRecord) -> Result<bool, AccessError> {
        let now = self.now();
        self.step(now, Rows::Others, |usage| {
            if self.account(account)?.is_some() {
                return Ok(false);
            }
            // A keyring with no account is damage: never hand it to a new owner.
            if self.kv.get(&keys::keyring(account))?.is_some() {
                return Err(damaged());
            }
            if usage.enrolls >= ENROLLS_PER_DAY || usage.stored.saturating_add(ACCOUNT_COST) > ACCOUNT_BYTES_CEILING {
                return Err(CustodyError::StorageFull);
            }
            self.put(&keys::account(account), &AccountRecord { record: record.clone() }.encode())?;
            usage.stored = usage.stored.saturating_add(ACCOUNT_COST);
            usage.enrolls = usage.enrolls.saturating_add(1);
            Ok(true)
        })
        .map_err(fault)
    }

    /// Writes nothing.
    pub fn record(&self, account: &AccountId) -> Result<Option<RegistrationRecord>, AccessError> {
        Ok(self.account(account).map_err(fault)?.map(|a| a.record))
    }

    /// Parks a login in memory for `lifetime_seconds` (1 to
    /// [`LOGIN_WINDOW_SECONDS`]), under the budget its attempt spent: the
    /// shared one with no bucket, a device's with its bucket. Registrations
    /// park nothing.
    pub fn park_login(
        &self,
        handle: &LoginHandle,
        account: &AccountId,
        state: &LoginState,
        lifetime_seconds: u32,
        class: Class,
        bucket: Option<&[u8; 32]>,
    ) -> Result<(), AccessError> {
        if !(1..=LOGIN_WINDOW_SECONDS).contains(&lifetime_seconds) {
            return Err(AccessError::StoreUnavailable);
        }
        let now = self.now();
        self.scratch.park(handle, account, state, after(now, lifetime_seconds), class, bucket, now)
    }

    /// At most once; an expired login is removed without being returned.
    pub fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError> {
        self.scratch.take(handle, self.now())
    }

    /// Opens a session for `lifetime_seconds` (1 to [`SESSION_SECONDS`]) if
    /// the account still has `record`. One past [`MAX_SESSIONS`] ends the
    /// account's session that expires first, the lowest digest on a tie,
    /// before the ceiling is checked, so an account at its limit always
    /// signs in.
    pub fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        record: &RegistrationRecord,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError> {
        if !(1..=SESSION_SECONDS).contains(&lifetime_seconds) {
            return Err(AccessError::StoreUnavailable);
        }
        let now = self.now();
        let full = |usage: &AccountUsage| usage.sessions.saturating_add(SESSION_COST) > SESSION_BYTES_CEILING;
        // At the ceiling, what expired goes first, in a step of its own.
        if full(&self.usage(now).map_err(fault)?) {
            self.purge_batch(now).map_err(fault)?;
        }
        self.step(now, Rows::Sessions, |usage| {
            if self.account(account)?.is_none_or(|a| a.record != *record) {
                return Ok(None);
            }
            if usage.session_rows >= SESSION_ROWS_PER_DAY {
                return Err(CustodyError::StorageFull);
            }
            // A digest is of 32 random bytes: one already filed is a fault.
            if self.kv.get(&keys::session(digest))?.is_some() {
                return Err(damaged());
            }
            let members = self.members(account)?;
            let excess = members.len().saturating_sub(MAX_SESSIONS as usize - 1);
            for member in members.iter().take(excess) {
                self.remove_session(usage, &member.digest, &member.record)?;
            }
            if full(usage) {
                return Err(CustodyError::StorageFull);
            }
            let expires_at = after(now, lifetime_seconds);
            self.put(&keys::session(digest), &SessionRecord { account: *account, expires_at }.encode())?;
            self.put(&keys::member_session(account, expires_at, digest), &[])?;
            self.put(&keys::session_expiry(expires_at, digest), &[])?;
            usage.sessions = usage.sessions.saturating_add(SESSION_COST);
            Ok(Some(expires_at))
        })
        .map_err(fault)
    }

    /// Ends the session, live or expired. Never refused.
    pub fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError> {
        let now = self.now();
        self.step(now, Rows::Others, |usage| match self.session(digest)? {
            Some(session) => self.remove_session(usage, digest, &session),
            None => Ok(()),
        })
        .map_err(fault)
    }

    /// Ends every session of the account behind a live one. Never refused.
    pub fn close_sessions(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        let now = self.now();
        self.step(now, Rows::Others, |usage| {
            let Some(account) = self.live_session(now, digest)? else { return Ok(false) };
            for member in self.members(&account)? {
                self.remove_session(usage, &member.digest, &member.record)?;
            }
            Ok(true)
        })
        .map_err(fault)
    }

    /// Writes nothing.
    pub fn keyring(&self, digest: &SessionDigest) -> Result<Option<KeyringSnapshot>, AccessError> {
        let now = self.now();
        let read = || -> Result<Option<KeyringSnapshot>, CustodyError> {
            let Some(account) = self.live_session(now, digest)? else { return Ok(None) };
            Ok(Some(snapshot(self.keyring_record(&account)?)))
        };
        read().map_err(fault)
    }

    /// Writes the keyring over version `expected` only. A stale write says
    /// so before any ceiling; past the day's keyring rows nothing is written,
    /// and otherwise a full store still takes a keyring no larger than the
    /// one it replaces.
    pub fn store_keyring(
        &self,
        digest: &SessionDigest,
        keyring: &Keyring,
        expected: KeyringVersion,
    ) -> Result<KeyringWrite, AccessError> {
        let now = self.now();
        self.step(now, Rows::Keyrings, |usage| {
            let Some(account) = self.live_session(now, digest)? else { return Ok(KeyringWrite::Unauthorized) };
            let old = self.keyring_record(&account)?;
            let (version, old_len) = old.map_or((KeyringVersion::NONE, 0), |k| (k.version, k.keyring.as_bytes().len()));
            if version != expected {
                return Ok(KeyringWrite::Stale);
            }
            if usage.keyring_rows >= KEYRING_ROWS_PER_DAY {
                return Err(CustodyError::StorageFull);
            }
            let (old_len, new_len) = (old_len as u64, keyring.as_bytes().len() as u64);
            let freed = usage.stored.saturating_sub(old_len);
            if new_len > old_len && freed.saturating_add(new_len) > ACCOUNT_BYTES_CEILING {
                return Err(CustodyError::StorageFull);
            }
            let next = KeyringVersion(version.0.checked_add(1).ok_or_else(damaged)?);
            self.put(&keys::keyring(&account), &KeyringRecord { version: next, keyring: keyring.clone() }.encode())?;
            usage.stored = freed.saturating_add(new_len);
            Ok(KeyringWrite::Stored(next))
        })
        .map_err(fault)
    }

    /// Removes the account behind a live session whole: its record, its
    /// keyring, every session and, once that is committed, its logins in
    /// progress. The name is free again. Never refused.
    pub fn close_account(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        let now = self.now();
        let closed = self
            .step(now, Rows::Others, |usage| {
                let Some(account) = self.live_session(now, digest)? else { return Ok(None) };
                for member in self.members(&account)? {
                    self.remove_session(usage, &member.digest, &member.record)?;
                }
                if let Some(old) = self.keyring_record(&account)? {
                    self.delete(&keys::keyring(&account))?;
                    usage.stored = usage.stored.saturating_sub(old.keyring.as_bytes().len() as u64);
                }
                self.delete(&keys::account(&account))?;
                usage.stored = usage.stored.saturating_sub(ACCOUNT_COST);
                Ok(Some(account))
            })
            .map_err(fault)?;
        let Some(account) = closed else { return Ok(false) };
        self.scratch.forget_account(&account)?;
        Ok(true)
    }

    /// Removes expired sessions (up to [`ACCOUNT_PURGE_BATCHES`] batches,
    /// none past the day's teardown rows) and every expired login and
    /// counter in memory, and says how many went in all.
    pub fn purge_expired(&self) -> Result<u64, AccessError> {
        let now = self.now();
        let sessions = self.purge_sessions(now);
        // Memory is swept even when the store cannot be.
        let swept = self.scratch.sweep(now, usize::MAX)?;
        Ok(sessions.map_err(fault)?.saturating_add(swept))
    }

    /// Counts an attempt on `class`'s budget, filed under `bucket` (see
    /// [`Scratch::admit`]). Writes nothing.
    pub fn admit(&self, account: &AccountId, bucket: &[u8; 32], class: Class, limit: u16) -> Result<bool, AccessError> {
        self.scratch.admit(account, bucket, class, limit, self.now())
    }

    /// What the accounts object holds right now, and has written today.
    pub fn usage_now(&self) -> Result<AccountUsage, AccessError> {
        self.usage(self.now()).map_err(fault)
    }
}
