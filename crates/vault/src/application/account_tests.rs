//! The accounts ledger against the Access store contract, its ceilings and
//! its adversaries, driven in the accounts object's own terms: one
//! synchronous step per call, over an in-memory store with a hand-driven
//! clock and the memory-only scratch; and last as the relay reaches it, a
//! [`RemoteAccounts`](super::RemoteAccounts) over a loopback to
//! [`serve_accounts`](super::serve_accounts).

use access::{
    AccessError, AccountId, Keyring, KeyringSnapshot, KeyringVersion, KeyringWrite, LOGIN_WINDOW_SECONDS, LoginHandle,
    LoginState, MAX_KEYRING_LEN, MAX_SESSIONS, RegistrationRecord, SESSION_SECONDS, SessionDigest, UnixTime,
};

use super::fakes::{ManualClock, MemoryKv};
use super::{AccountLedger, Clock, Scratch};
use crate::core::{
    ACCOUNT_BYTES_CEILING, ACCOUNT_COST, ACCOUNT_TEARDOWN_ROWS_PER_DAY, AccountUsage, Class, ENROLLS_PER_DAY,
    KEYRING_BYTES_CEILING, KEYRING_GROWTH_BYTES_PER_DAY, KEYRING_ROWS_PER_DAY, KeyringRecord, SECONDS_PER_DAY,
    SESSION_BYTES_CEILING, SESSION_COST, SESSION_OPEN_ROWS, SESSION_ROWS_PER_DAY, SESSIONS_PER_DAY, SessionRecord,
    account_keys as keys,
};

#[derive(Debug, Default)]
struct Desk {
    kv: MemoryKv,
    scratch: Scratch,
    clock: ManualClock,
}

type Ledger<'a> = AccountLedger<'a, &'a MemoryKv, &'a ManualClock>;

impl Desk {
    fn ledger(&self) -> Ledger<'_> {
        AccountLedger::new(&self.kv, &self.scratch, &self.clock)
    }

    fn now(&self) -> i64 {
        self.clock.now().0
    }

    fn advance(&self, seconds: u32) {
        self.clock.advance(i64::from(seconds));
    }

    fn next_day(&self) {
        self.clock.advance(SECONDS_PER_DAY);
    }

    fn usage(&self) -> AccountUsage {
        self.ledger().usage_now().unwrap()
    }

    /// Rewrites the usage as if the store had got there.
    fn pretend(&self, change: impl FnOnce(&mut AccountUsage)) {
        let mut usage = self.usage();
        change(&mut usage);
        self.kv.tamper(keys::ACCOUNT_USAGE, usage.encode());
    }

    fn enrolled(&self, n: u32) -> AccountId {
        assert_eq!(self.ledger().enroll(&account(n), &record(n)), Ok(true));
        account(n)
    }

    /// Opens session `d` of account `n` for `seconds`.
    fn open(&self, n: u32, d: u32, seconds: u32) -> Option<UnixTime> {
        self.ledger().open_session(&digest(d), &account(n), &record(n), seconds).unwrap()
    }

    fn live(&self, d: u32) -> bool {
        self.ledger().keyring(&digest(d)).unwrap().is_some()
    }

    fn store(&self, d: u32, ring: &Keyring, expected: u64) -> Result<KeyringWrite, AccessError> {
        self.ledger().store_keyring(&digest(d), ring, KeyringVersion(expected))
    }

    fn park(&self, h: u32, n: u32, seconds: u32) {
        self.ledger().park_login(&handle(h), &account(n), &state(1), seconds, Class::Login, None).unwrap();
    }

    fn keys_starting(&self, letter: char) -> Vec<String> {
        self.kv.keys().into_iter().filter(|k| k.starts_with(letter)).collect()
    }

    /// Plants an index entry, as damage on disk would.
    fn plant(&self, key: String) {
        self.kv.tamper(&key, Vec::new());
    }
}

fn numbered<const N: usize>(n: u32, tag: u8) -> [u8; N] {
    let mut bytes = [tag; N];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    bytes
}

fn account(n: u32) -> AccountId {
    AccountId::from_array(numbered(n, 0xA0))
}

fn record(n: u32) -> RegistrationRecord {
    RegistrationRecord::from_slice(&numbered::<{ RegistrationRecord::LEN }>(n, 0x4E)).unwrap()
}

fn digest(n: u32) -> SessionDigest {
    SessionDigest::from_array(numbered(n, 0xD0))
}

fn handle(n: u32) -> LoginHandle {
    LoginHandle::from_array(numbered(n, 0xC0))
}

fn bucket(n: u32) -> [u8; 32] {
    numbered(n, 0xB0)
}

fn state(byte: u8) -> LoginState {
    LoginState::from_slice(&[byte; LoginState::LEN]).unwrap()
}

fn ring(len: usize, byte: u8) -> Keyring {
    Keyring::new(vec![byte; len]).unwrap()
}

/// The digest a session record is filed under.
fn filed_under(key: &str) -> SessionDigest {
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&key[1 + 2 * i..3 + 2 * i], 16).unwrap();
    }
    assert_eq!(keys::session(&SessionDigest::from_array(bytes)), key);
    SessionDigest::from_array(bytes)
}

/// What a broken store, damage or a broken caller gets.
fn unavailable<T>() -> Result<T, AccessError> {
    Err(AccessError::StoreUnavailable)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

mod accounts {
    use super::*;

    #[test]
    fn enroll_never_overwrites_an_account() {
        let desk = Desk::default();
        let ledger = desk.ledger();
        assert_eq!(ledger.enroll(&account(1), &record(1)), Ok(true));
        assert_eq!(ledger.enroll(&account(1), &record(2)), Ok(false));
        assert_eq!(ledger.record(&account(1)), Ok(Some(record(1))));
        assert_eq!((desk.usage().accounts, desk.usage().keyrings), (ACCOUNT_COST, 0));
        assert_eq!(desk.usage().enrolls, 1);
    }

    #[test]
    fn record_reads_back_what_was_enrolled_and_nothing_else() {
        let desk = Desk::default();
        assert_eq!(desk.ledger().record(&account(1)), Ok(None));
        desk.enrolled(1);
        desk.enrolled(2);
        assert_eq!(desk.ledger().record(&account(1)), Ok(Some(record(1))));
        assert_eq!(desk.ledger().record(&account(2)), Ok(Some(record(2))));
        assert_eq!(desk.ledger().record(&account(3)), Ok(None));
    }

    #[test]
    fn a_session_is_dead_at_its_expiry_second() {
        let desk = Desk::default();
        desk.enrolled(1);
        assert_eq!(desk.open(1, 1, 100), Some(UnixTime(desk.now() + 100)));
        desk.advance(99);
        assert!(desk.live(1));
        desk.advance(1);
        assert!(!desk.live(1));
        assert_eq!(desk.store(1, &ring(10, 1), 0), Ok(KeyringWrite::Unauthorized));
        assert_eq!(desk.ledger().close_sessions(&digest(1)), Ok(false));
        assert_eq!(desk.ledger().close_account(&digest(1)), Ok(false));
        assert_eq!(desk.ledger().record(&account(1)), Ok(Some(record(1))));
    }

    #[test]
    fn a_login_is_taken_once_and_an_expired_one_is_removed_unreturned() {
        let desk = Desk::default();
        let ledger = desk.ledger();
        ledger.park_login(&handle(1), &account(1), &state(1), 300, Class::Login, None).unwrap();
        assert_eq!(ledger.take_login(&handle(1)), Ok(Some((account(1), state(1)))));
        assert_eq!(ledger.take_login(&handle(1)), Ok(None));
        ledger.park_login(&handle(2), &account(1), &state(2), 10, Class::Device, Some(&bucket(1))).unwrap();
        desk.advance(10);
        assert_eq!(ledger.take_login(&handle(2)), Ok(None));
        assert!(format!("{:?}", desk.scratch).contains("logins: 0"), "{:?}", desk.scratch);
    }

    #[test]
    fn close_session_ends_a_session_at_any_expiry() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 100);
        desk.open(1, 2, 100);
        assert_eq!(desk.ledger().close_session(&digest(1)), Ok(()));
        assert!(!desk.live(1));
        assert!(desk.live(2));
        desk.advance(200);
        assert_eq!(desk.ledger().close_session(&digest(2)), Ok(()));
        assert_eq!(desk.ledger().close_session(&digest(9)), Ok(()));
        let left: Vec<String> = desk.kv.keys().into_iter().filter(|k| !k.starts_with(['a', 'w'])).collect();
        assert_eq!(left, Vec::<String>::new());
        assert_eq!(desk.usage().sessions, 0);
    }

    #[test]
    fn close_sessions_ends_every_session_of_this_account_only() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        for d in 1..=3 {
            desk.open(1, d, 1000);
        }
        desk.open(2, 4, 1000);
        desk.open(2, 5, 1000);
        assert_eq!(desk.ledger().close_sessions(&digest(2)), Ok(true));
        for d in 1..=3 {
            assert!(!desk.live(d));
        }
        assert!(desk.live(4) && desk.live(5));
        assert_eq!(desk.usage().sessions, 2 * SESSION_COST);
        assert_eq!(desk.ledger().record(&account(1)), Ok(Some(record(1))));
    }

    #[test]
    fn close_sessions_needs_a_live_session() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 10);
        desk.open(1, 2, 100);
        assert_eq!(desk.ledger().close_sessions(&digest(9)), Ok(false));
        desk.advance(10);
        assert_eq!(desk.ledger().close_sessions(&digest(1)), Ok(false));
        assert!(desk.live(2));
    }

    #[test]
    fn the_seventeenth_session_ends_the_one_that_expires_first_never_the_new_one() {
        let desk = Desk::default();
        desk.enrolled(1);
        for d in 1..=MAX_SESSIONS {
            desk.open(1, d, 1000 + d);
        }
        // The newcomer expires before all of them, and still stays.
        assert!(desk.open(1, 17, 10).is_some());
        assert!(desk.live(17));
        assert!(!desk.live(1));
        for d in 2..=MAX_SESSIONS {
            assert!(desk.live(d), "session {d}");
        }
        assert_eq!(desk.keys_starting('s').len(), MAX_SESSIONS as usize);
        assert_eq!(desk.usage().sessions, u64::from(MAX_SESSIONS) * SESSION_COST);
    }

    #[test]
    fn on_a_tie_the_lowest_digest_goes_but_never_the_new_one() {
        let desk = Desk::default();
        desk.enrolled(1);
        for d in (2..=17).rev() {
            desk.open(1, d, 1000);
        }
        // Same second, lowest digest of all: it is the one being opened.
        assert!(desk.open(1, 1, 1000).is_some());
        assert!(desk.live(1));
        assert!(!desk.live(2));
        for d in 3..=17 {
            assert!(desk.live(d), "session {d}");
        }
    }

    #[test]
    fn eviction_leaves_other_accounts_alone() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        for d in 1..=MAX_SESSIONS {
            desk.open(2, 100 + d, 500);
        }
        for d in 1..=20 {
            desk.open(1, d, 1000);
        }
        for d in 1..=MAX_SESSIONS {
            assert!(desk.live(100 + d));
        }
        for d in 1..=20 {
            assert_eq!(desk.live(d), d > 4, "session {d}");
        }
        assert_eq!(desk.usage().sessions, 2 * u64::from(MAX_SESSIONS) * SESSION_COST);
    }

    #[test]
    fn a_keyring_is_written_only_over_the_version_read() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        let none = KeyringSnapshot { keyring: None, version: KeyringVersion::NONE };
        assert_eq!(desk.ledger().keyring(&digest(1)), Ok(Some(none)));
        assert_eq!(desk.store(1, &ring(10, 1), 0), Ok(KeyringWrite::Stored(KeyringVersion(1))));
        assert_eq!(desk.store(1, &ring(10, 2), 0), Ok(KeyringWrite::Stale));
        assert_eq!(desk.store(1, &ring(20, 3), 1), Ok(KeyringWrite::Stored(KeyringVersion(2))));
        let written = KeyringSnapshot { keyring: Some(ring(20, 3)), version: KeyringVersion(2) };
        assert_eq!(desk.ledger().keyring(&digest(1)), Ok(Some(written)));
        assert_eq!((desk.usage().accounts, desk.usage().keyrings), (ACCOUNT_COST, 20));
    }

    #[test]
    fn keyrings_need_a_live_session() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 10);
        assert_eq!(desk.ledger().keyring(&digest(9)), Ok(None));
        assert_eq!(desk.store(9, &ring(10, 1), 0), Ok(KeyringWrite::Unauthorized));
        desk.advance(10);
        assert_eq!(desk.ledger().keyring(&digest(1)), Ok(None));
        assert_eq!(desk.store(1, &ring(10, 1), 0), Ok(KeyringWrite::Unauthorized));
        assert_eq!(desk.keys_starting('k'), Vec::<String>::new());
    }

    #[test]
    fn closing_an_account_removes_it_whole_and_frees_the_name() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        for d in 1..=3 {
            desk.open(1, d, 1000);
        }
        desk.open(2, 9, 1000);
        desk.store(1, &ring(100, 1), 0).unwrap();
        let ledger = desk.ledger();
        desk.park(1, 1, 300);
        ledger.park_login(&handle(2), &account(1), &state(2), 300, Class::Device, Some(&bucket(1))).unwrap();
        desk.park(3, 2, 300);
        assert_eq!(ledger.close_account(&digest(2)), Ok(true));
        assert_eq!(ledger.record(&account(1)), Ok(None));
        for d in 1..=3 {
            assert!(!desk.live(d));
        }
        assert!(desk.live(9));
        assert_eq!(ledger.take_login(&handle(1)), Ok(None));
        assert_eq!(ledger.take_login(&handle(2)), Ok(None));
        assert_eq!(ledger.take_login(&handle(3)), Ok(Some((account(2), state(1)))));
        let expires = UnixTime(desk.now() + 1000);
        let mut left = vec![
            keys::account(&account(2)),
            keys::session(&digest(9)),
            keys::member_session(&account(2), expires, &digest(9)),
            keys::session_expiry(expires, &digest(9)),
            keys::ACCOUNT_USAGE.to_string(),
        ];
        left.sort();
        assert_eq!(desk.kv.keys(), left);
        let usage = desk.usage();
        assert_eq!((usage.accounts, usage.keyrings, usage.sessions), (ACCOUNT_COST, 0, SESSION_COST));
        // The name is free again, and nothing of the old account comes with it.
        assert_eq!(ledger.enroll(&account(1), &record(5)), Ok(true));
        assert!(ledger.open_session(&digest(20), &account(1), &record(5), 1000).unwrap().is_some());
        let none = KeyringSnapshot { keyring: None, version: KeyringVersion::NONE };
        assert_eq!(ledger.keyring(&digest(20)), Ok(Some(none)));
    }

    #[test]
    fn closing_an_account_needs_a_live_session() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 10);
        assert_eq!(desk.ledger().close_account(&digest(9)), Ok(false));
        desk.advance(10);
        assert_eq!(desk.ledger().close_account(&digest(1)), Ok(false));
        assert_eq!(desk.ledger().record(&account(1)), Ok(Some(record(1))));
    }

    #[test]
    fn purge_removes_only_what_expired_and_counts_logins_sessions_and_counters() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 100);
        desk.open(1, 2, 1000);
        desk.park(1, 1, 50);
        desk.park(2, 1, 300);
        let ledger = desk.ledger();
        assert_eq!(ledger.admit(&account(1), account(1).as_bytes(), Class::Login, 10), Ok(true));
        assert_eq!(ledger.admit(&account(2), &bucket(2), Class::Registration, 10), Ok(true));
        desk.advance(100);
        assert_eq!(ledger.purge_expired(), Ok(1 + 1 + 2));
        assert!(!desk.live(1));
        assert!(desk.live(2));
        assert_eq!(desk.keys_starting('s').len(), 1);
        assert_eq!(desk.keys_starting('e').len(), 1);
        assert_eq!(desk.keys_starting('m').len(), 1);
        assert_eq!(desk.usage().sessions, SESSION_COST);
        assert_eq!(ledger.purge_expired(), Ok(0));
        assert_eq!(ledger.take_login(&handle(2)), Ok(Some((account(1), state(1)))));
    }

    #[test]
    fn a_session_opens_only_on_the_record_the_password_was_checked_against() {
        let desk = Desk::default();
        desk.enrolled(1);
        let ledger = desk.ledger();
        assert_eq!(ledger.open_session(&digest(1), &account(1), &record(2), 100), Ok(None));
        assert_eq!(ledger.open_session(&digest(1), &account(9), &record(9), 100), Ok(None));
        assert_eq!(desk.keys_starting('s'), Vec::<String>::new());
        assert_eq!(desk.usage().session_rows, 0);
    }

    #[test]
    fn lifetimes_out_of_range_are_refused() {
        let desk = Desk::default();
        desk.enrolled(1);
        let ledger = desk.ledger();
        let park = |h: u32, seconds: u32, class: Class, bucket: Option<&[u8; 32]>| {
            ledger.park_login(&handle(h), &account(1), &state(1), seconds, class, bucket)
        };
        for seconds in [0, LOGIN_WINDOW_SECONDS + 1, u32::MAX] {
            assert_eq!(park(1, seconds, Class::Login, None), Err(AccessError::StoreUnavailable), "{seconds}");
        }
        assert_eq!(park(1, LOGIN_WINDOW_SECONDS, Class::Login, None), Ok(()));
        assert_eq!(park(2, 1, Class::Device, Some(&bucket(1))), Ok(()));
        assert_eq!(park(3, 1, Class::Registration, None), Err(AccessError::StoreUnavailable), "nothing parks");
        assert_eq!(park(4, 1, Class::Device, None), Err(AccessError::StoreUnavailable));
        for seconds in [0, SESSION_SECONDS + 1, u32::MAX] {
            let opened = ledger.open_session(&digest(1), &account(1), &record(1), seconds);
            assert_eq!(opened, Err(AccessError::StoreUnavailable), "{seconds}");
        }
        let opened = ledger.open_session(&digest(1), &account(1), &record(1), SESSION_SECONDS);
        assert_eq!(opened, Ok(Some(UnixTime(desk.now() + i64::from(SESSION_SECONDS)))));
    }

    #[test]
    fn each_step_writes_the_rows_it_is_billed_for() {
        let desk = Desk::default();
        let rows = |run: &dyn Fn()| {
            let before = desk.kv.writes.get();
            run();
            desk.kv.writes.get() - before
        };
        let ledger = desk.ledger();
        assert_eq!(rows(&|| assert!(ledger.enroll(&account(1), &record(1)).unwrap())), 2);
        assert_eq!(rows(&|| assert!(desk.open(1, 1, 1000).is_some())), u64::from(SESSION_OPEN_ROWS));
        assert_eq!(rows(&|| assert!(desk.store(1, &ring(10, 1), 0).is_ok())), 2);
        assert_eq!(rows(&|| assert!(desk.live(1))), 0);
        assert_eq!(rows(&|| assert!(ledger.record(&account(1)).unwrap().is_some())), 0);
        assert_eq!(rows(&|| desk.park(1, 1, 300)), 0);
        assert_eq!(rows(&|| assert!(ledger.take_login(&handle(1)).unwrap().is_some())), 0);
        assert_eq!(rows(&|| assert!(ledger.admit(&account(1), &bucket(1), Class::Login, 10).unwrap())), 0);
        assert_eq!(rows(&|| ledger.close_session(&digest(1)).unwrap()), 4);
        assert_eq!(rows(&|| ledger.close_session(&digest(1)).unwrap()), 0, "nothing to close");
        for d in 1..=MAX_SESSIONS {
            desk.open(1, d, 1000);
        }
        let evicting = u64::from(SESSION_OPEN_ROWS) + 3;
        assert_eq!(rows(&|| assert!(desk.open(1, 17, 1000).is_some())), evicting, "one session evicted");
        assert_eq!(rows(&|| assert!(ledger.close_sessions(&digest(17)).unwrap())), 1 + 3 * 16);
        desk.open(1, 1, 10);
        desk.open(1, 2, 10);
        desk.advance(10);
        assert_eq!(rows(&|| assert!(ledger.purge_expired().is_ok())), 1 + 3 * 2);
        desk.open(1, 3, 1000);
        desk.open(1, 4, 1000);
        assert_eq!(rows(&|| assert!(ledger.close_account(&digest(3)).unwrap())), 3 + 3 * 2);
        desk.enrolled(2);
        desk.open(2, 5, 1000);
        assert_eq!(rows(&|| assert!(ledger.close_account(&digest(5)).unwrap())), 2 + 3, "no keyring to delete");
        assert_eq!(u64::from(desk.usage().rows), desk.kv.writes.get());
    }
}

mod account_ceilings {
    use super::*;

    #[test]
    fn accounts_and_keyrings_each_fill_their_own_ceiling() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.store(1, &ring(1000, 1), 0).unwrap();
        assert_eq!((desk.usage().accounts, desk.usage().keyrings), (ACCOUNT_COST, 1000));
        desk.pretend(|u| u.accounts = ACCOUNT_BYTES_CEILING - ACCOUNT_COST);
        assert_eq!(desk.ledger().enroll(&account(2), &record(2)), Ok(true), "exactly fits");
        assert_eq!(desk.ledger().enroll(&account(3), &record(3)), Err(AccessError::StorageFull));
        assert_eq!(desk.ledger().record(&account(3)), Ok(None));
        assert_eq!(desk.usage().accounts, ACCOUNT_BYTES_CEILING);
        assert_eq!(desk.store(1, &ring(2000, 2), 1), Ok(KeyringWrite::Stored(KeyringVersion(2))), "keyrings grow");
        assert_eq!(desk.usage().keyrings, 2000);
    }

    #[test]
    fn a_full_keyring_store_never_stops_registration() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.pretend(|u| u.keyrings = KEYRING_BYTES_CEILING);
        assert_eq!(desk.store(1, &ring(1, 1), 0), Err(AccessError::StorageFull));
        assert_eq!(desk.ledger().enroll(&account(2), &record(2)), Ok(true));
        assert!(desk.open(2, 2, 1000).is_some(), "and the newcomer signs in");
        assert_eq!(desk.usage().keyrings, KEYRING_BYTES_CEILING);
    }

    #[test]
    fn a_taken_name_stays_taken_when_the_store_is_full() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.pretend(|u| u.accounts = ACCOUNT_BYTES_CEILING);
        assert_eq!(desk.ledger().enroll(&account(1), &record(2)), Ok(false));
        assert_eq!(desk.ledger().enroll(&account(2), &record(2)), Err(AccessError::StorageFull));
    }

    #[test]
    fn a_full_store_still_takes_a_keyring_no_larger_than_before() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.store(1, &ring(1000, 1), 0).unwrap();
        desk.pretend(|u| u.keyrings = KEYRING_BYTES_CEILING);
        assert_eq!(desk.store(1, &ring(1000, 2), 1), Ok(KeyringWrite::Stored(KeyringVersion(2))));
        assert_eq!(desk.store(1, &ring(400, 3), 2), Ok(KeyringWrite::Stored(KeyringVersion(3))));
        assert_eq!(desk.usage().keyrings, KEYRING_BYTES_CEILING - 600);
        assert_eq!(desk.store(1, &ring(1000, 4), 3), Ok(KeyringWrite::Stored(KeyringVersion(4))), "fits exactly");
        assert_eq!(desk.store(1, &ring(1001, 5), 4), Err(AccessError::StorageFull));
        let kept = KeyringSnapshot { keyring: Some(ring(1000, 4)), version: KeyringVersion(4) };
        assert_eq!(desk.ledger().keyring(&digest(1)), Ok(Some(kept)));
        assert_eq!(desk.usage().keyrings, KEYRING_BYTES_CEILING);
        assert_eq!(desk.ledger().enroll(&account(2), &record(2)), Ok(true), "registration goes on");
    }

    #[test]
    fn a_stale_write_says_stale_even_when_the_store_is_full() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.pretend(|u| {
            u.keyrings = KEYRING_BYTES_CEILING;
            u.keyring_growth = KEYRING_GROWTH_BYTES_PER_DAY;
        });
        assert_eq!(desk.store(1, &ring(5000, 1), 7), Ok(KeyringWrite::Stale));
        assert_eq!(desk.store(1, &ring(5000, 1), 0), Err(AccessError::StorageFull));
    }

    #[test]
    fn keyrings_grow_by_at_most_the_days_budget_and_other_writes_are_exempt() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        desk.open(1, 1, SESSION_SECONDS);
        desk.open(2, 2, SESSION_SECONDS);
        assert_eq!(desk.store(1, &ring(1000, 1), 0), Ok(KeyringWrite::Stored(KeyringVersion(1))));
        assert_eq!(desk.usage().keyring_growth, 1000, "a new keyring grows by its length");
        assert_eq!(desk.store(1, &ring(1500, 2), 1), Ok(KeyringWrite::Stored(KeyringVersion(2))));
        assert_eq!(desk.usage().keyring_growth, 1500, "a larger one by the difference");
        desk.store(1, &ring(1500, 3), 2).unwrap();
        desk.store(1, &ring(10, 4), 3).unwrap();
        assert_eq!(desk.usage().keyring_growth, 1500, "the same size or smaller costs nothing");
        // Shrinking gives nothing back: the budget counts growth, not bytes held.
        desk.pretend(|u| u.keyring_growth = KEYRING_GROWTH_BYTES_PER_DAY - 100);
        assert_eq!(desk.store(2, &ring(100, 1), 0), Ok(KeyringWrite::Stored(KeyringVersion(1))), "exactly fits");
        assert_eq!(desk.store(1, &ring(11, 5), 4), Err(AccessError::StorageFull), "one byte more");
        assert_eq!(desk.store(1, &ring(10, 5), 4), Ok(KeyringWrite::Stored(KeyringVersion(5))), "no growth");
        assert_eq!(desk.store(2, &ring(50, 2), 1), Ok(KeyringWrite::Stored(KeyringVersion(2))), "shrinking");
        assert_eq!(desk.usage().keyring_growth, KEYRING_GROWTH_BYTES_PER_DAY);
        assert!(desk.open(1, 3, 1000).is_some(), "sign-in goes on");
        assert_eq!(desk.ledger().enroll(&account(3), &record(3)), Ok(true), "and registration");
        desk.next_day();
        desk.open(1, 4, 1000);
        assert_eq!(desk.store(4, &ring(11, 6), 5), Ok(KeyringWrite::Stored(KeyringVersion(6))), "a new day");
        assert_eq!(desk.usage().keyring_growth, 1);
    }

    #[test]
    fn a_fresh_account_signs_in_while_others_hold_every_session_two_days_allow() {
        // Sessions live 12 hours, so the live ones were opened over two UTC
        // days at most: while today's session rows are not spent, the ceiling
        // still has room for one more.
        assert!(SESSION_BYTES_CEILING >= 2 * u64::from(SESSIONS_PER_DAY) * SESSION_COST);
        let desk = Desk::default();
        desk.enrolled(1);
        desk.pretend(|u| {
            u.sessions = (2 * u64::from(SESSIONS_PER_DAY) - 1) * SESSION_COST;
            u.session_rows = SESSION_ROWS_PER_DAY - SESSION_OPEN_ROWS;
        });
        assert!(desk.open(1, 1, SESSION_SECONDS).is_some());
        assert!(desk.usage().sessions <= SESSION_BYTES_CEILING);
        let opened = desk.ledger().open_session(&digest(2), &account(1), &record(1), 1000);
        assert_eq!(opened, Err(AccessError::StorageFull), "the day's rows stop sign-in first");
    }

    #[test]
    fn a_full_session_store_purges_before_refusing() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        desk.open(1, 1, 10);
        desk.open(1, 2, 10);
        desk.pretend(|u| u.sessions = SESSION_BYTES_CEILING);
        let ledger = desk.ledger();
        let open = || ledger.open_session(&digest(3), &account(2), &record(2), 100);
        assert_eq!(open(), Err(AccessError::StorageFull), "nothing expired yet");
        desk.advance(10);
        assert_eq!(open(), Ok(Some(UnixTime(desk.now() + 100))));
        assert_eq!(desk.usage().sessions, SESSION_BYTES_CEILING - 2 * SESSION_COST + SESSION_COST);
        assert_eq!(desk.keys_starting('s').len(), 1);
    }

    #[test]
    fn an_account_at_its_session_limit_signs_in_on_a_full_store() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        for d in 1..=MAX_SESSIONS {
            desk.open(1, d, 1000);
        }
        desk.pretend(|u| u.sessions = SESSION_BYTES_CEILING);
        assert!(desk.open(1, 17, 1000).is_some());
        assert!(!desk.live(1));
        let other = desk.ledger().open_session(&digest(30), &account(2), &record(2), 1000);
        assert_eq!(other, Err(AccessError::StorageFull));
        assert_eq!(desk.usage().sessions, SESSION_BYTES_CEILING);
    }

    #[test]
    fn keyring_rows_past_their_daily_allowance_stop_only_keyrings() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, SESSION_SECONDS);
        desk.pretend(|u| u.keyring_rows = KEYRING_ROWS_PER_DAY);
        assert_eq!(desk.store(1, &ring(10, 1), 0), Err(AccessError::StorageFull));
        assert!(desk.open(1, 2, 1000).is_some(), "sign-in goes on");
        desk.enrolled(2);
        assert_eq!(desk.ledger().close_session(&digest(2)), Ok(()));
        desk.next_day();
        desk.open(1, 3, 1000);
        assert_eq!(desk.store(3, &ring(10, 1), 0), Ok(KeyringWrite::Stored(KeyringVersion(1))));
    }

    #[test]
    fn enrolls_past_their_daily_allowance_stop_only_registration() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.pretend(|u| u.enrolls = ENROLLS_PER_DAY);
        assert_eq!(desk.ledger().enroll(&account(2), &record(2)), Err(AccessError::StorageFull));
        assert_eq!(desk.ledger().enroll(&account(1), &record(1)), Ok(false), "a taken name still says taken");
        assert!(desk.open(1, 1, 1000).is_some());
        assert_eq!(desk.store(1, &ring(10, 1), 0), Ok(KeyringWrite::Stored(KeyringVersion(1))));
        desk.next_day();
        assert_eq!(desk.ledger().enroll(&account(2), &record(2)), Ok(true));
    }

    #[test]
    fn session_rows_past_their_daily_allowance_stop_only_sign_in() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, SESSION_SECONDS);
        desk.pretend(|u| u.session_rows = SESSION_ROWS_PER_DAY);
        let opened = desk.ledger().open_session(&digest(2), &account(1), &record(1), 1000);
        assert_eq!(opened, Err(AccessError::StorageFull));
        assert_eq!(desk.store(1, &ring(10, 1), 0), Ok(KeyringWrite::Stored(KeyringVersion(1))));
        desk.enrolled(2);
        assert_eq!(desk.ledger().close_session(&digest(1)), Ok(()));
        desk.next_day();
        assert!(desk.open(1, 2, 1000).is_some());
    }

    #[test]
    fn closing_works_past_every_daily_allowance() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        for d in 1..=3 {
            desk.open(1, d, 1000);
        }
        desk.open(2, 4, 1000);
        desk.store(4, &ring(10, 1), 0).unwrap();
        desk.pretend(|u| {
            u.rows = u32::MAX;
            u.session_rows = u32::MAX;
            u.keyring_rows = u32::MAX;
            u.enrolls = u32::MAX;
            u.keyring_growth = u32::MAX;
        });
        assert_eq!(desk.ledger().close_session(&digest(1)), Ok(()));
        assert!(!desk.live(1));
        assert_eq!(desk.ledger().close_sessions(&digest(2)), Ok(true));
        assert!(!desk.live(3));
        assert_eq!(desk.ledger().close_account(&digest(4)), Ok(true));
        assert_eq!(desk.ledger().record(&account(2)), Ok(None));
        let usage = desk.usage();
        assert_eq!((usage.accounts, usage.keyrings, usage.sessions), (ACCOUNT_COST, 0, 0));
    }

    #[test]
    fn purging_waits_for_the_next_day_past_the_teardown_allowance() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 10);
        desk.park(1, 1, 10);
        desk.advance(10);
        desk.pretend(|u| u.rows = ACCOUNT_TEARDOWN_ROWS_PER_DAY);
        assert_eq!(desk.ledger().purge_expired(), Ok(1), "memory is swept; the store waits");
        assert_eq!(desk.keys_starting('s').len(), 1);
        desk.next_day();
        assert_eq!(desk.ledger().purge_expired(), Ok(1));
        assert_eq!(desk.keys_starting('s'), Vec::<String>::new());
        assert_eq!(desk.usage().sessions, 0);
    }

    #[test]
    fn usage_matches_what_the_store_holds_after_a_random_run() {
        let desk = Desk::default();
        let mut seed: u64 = 0x5167_7100;
        let mut next = |below: u32| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            ((seed >> 33) % u64::from(below)) as u32
        };
        for _ in 0..3000 {
            let ledger = desk.ledger();
            let (n, d) = (next(6), next(40));
            let _ = match next(8) {
                0 => ledger.enroll(&account(n), &record(n)).map(|_| ()),
                1 | 2 => ledger.open_session(&digest(d), &account(n), &record(n), 1 + next(2000)).map(|_| ()),
                3 => ledger.close_session(&digest(d)),
                4 => ledger.close_sessions(&digest(d)).map(|_| ()),
                5 => {
                    let expected = ledger.keyring(&digest(d)).ok().flatten().map_or(0, |k| k.version.0);
                    let len = 1 + next(3000) as usize;
                    ledger.store_keyring(&digest(d), &ring(len, 1), KeyringVersion(expected)).map(|_| ())
                }
                6 => ledger.close_account(&digest(d)).map(|_| ()),
                _ => ledger.purge_expired().map(|_| ()),
            };
            desk.advance(next(60));
        }
        let held = desk.kv.snapshot();
        let (mut accounts, mut keyrings, mut sessions) = (0, 0, 0);
        for (key, value) in &held {
            match key.as_bytes()[0] {
                b'a' => accounts += ACCOUNT_COST,
                b'k' => keyrings += KeyringRecord::decode(value).unwrap().keyring.as_bytes().len() as u64,
                b's' => {
                    sessions += SESSION_COST;
                    let session = SessionRecord::decode(value).unwrap();
                    let filed = filed_under(key);
                    let member = keys::member_session(&session.account, session.expires_at, &filed);
                    assert!(held.contains_key(&member), "{key} has its account's entry");
                    assert!(held.contains_key(&keys::session_expiry(session.expires_at, &filed)));
                    assert!(held.contains_key(&keys::account(&session.account)), "{key} has its account");
                }
                b'm' => assert!(keys::parse_member_session(key).is_some()),
                b'e' => assert!(keys::parse_session_expiry(key).is_some()),
                _ => assert_eq!(key, keys::ACCOUNT_USAGE),
            }
        }
        let indexed = desk.keys_starting('m').len();
        assert_eq!((indexed, desk.keys_starting('e').len()), (desk.keys_starting('s').len(), indexed));
        assert!(accounts > ACCOUNT_COST && keyrings > 0 && sessions > SESSION_COST, "the run kept something");
        let usage = desk.usage();
        assert_eq!((usage.accounts, usage.keyrings, usage.sessions), (accounts, keyrings, sessions));
    }
}

mod account_adversary {
    use super::*;

    #[test]
    fn a_login_is_taken_once_and_never_after_its_account_closed() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.park(1, 1, 300);
        desk.park(2, 1, 300);
        let ledger = desk.ledger();
        assert_eq!(ledger.take_login(&handle(1)), Ok(Some((account(1), state(1)))));
        assert_eq!(ledger.take_login(&handle(1)), Ok(None));
        assert_eq!(ledger.close_account(&digest(1)), Ok(true));
        assert_eq!(ledger.take_login(&handle(2)), Ok(None));
    }

    #[test]
    fn a_flood_of_largest_keyrings_stops_at_the_days_growth_and_never_stops_registration() {
        // When accounts and keyrings shared one ceiling, 904 accounts with
        // the largest keyring filled it, far under a day's registrations, and
        // no name could register again. The day's growth stops them first.
        let desk = Desk::default();
        let flood = (64 * 1024 * 1024 / (ACCOUNT_COST + MAX_KEYRING_LEN as u64)) as u32 + 1;
        assert_eq!(flood, 904);
        for n in 0..flood {
            desk.enrolled(n);
            assert!(desk.open(n, n, SESSION_SECONDS).is_some());
        }
        let largest = ring(MAX_KEYRING_LEN, 7);
        let per_day = KEYRING_GROWTH_BYTES_PER_DAY / MAX_KEYRING_LEN as u32;
        let mut stored = 0;
        for n in 0..flood {
            match desk.store(n, &largest, 0) {
                Ok(KeyringWrite::Stored(_)) => stored += 1,
                refused => {
                    assert_eq!(refused, Err(AccessError::StorageFull), "account {n}");
                    // Every later write is refused alike: a few stand for the rest.
                    if n > per_day + 8 {
                        break;
                    }
                }
            }
        }
        assert_eq!(stored, per_day, "one day's growth, no more");
        assert!(desk.usage().keyrings * 13 <= KEYRING_BYTES_CEILING, "under a thirteenth of the ceiling");
        assert_eq!(desk.ledger().enroll(&account(flood), &record(flood)), Ok(true), "a fresh name still registers");
        assert!(desk.open(flood, flood, 1000).is_some(), "and signs in");
        // A member whose keyring was written rewrites it at the same size.
        assert_eq!(desk.store(0, &largest, 1), Ok(KeyringWrite::Stored(KeyringVersion(2))));
        desk.next_day();
        for n in per_day..=2 * per_day {
            assert!(desk.open(n, flood + 1 + n, SESSION_SECONDS).is_some());
            let written = desk.store(flood + 1 + n, &largest, 0).is_ok();
            assert_eq!(written, n < 2 * per_day, "the budget is daily: account {n}");
        }
    }

    #[test]
    fn a_version_one_usage_on_disk_never_undercounts_and_never_underflows() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.store(1, &ring(1000, 1), 0).unwrap();
        // What version 1 wrote for this store: one weight for both.
        let usage = desk.usage();
        let mut old = vec![1];
        old.extend_from_slice(&(ACCOUNT_COST + 1000).to_be_bytes());
        old.extend_from_slice(&usage.sessions.to_be_bytes());
        for count in [usage.day, usage.rows, usage.session_rows, usage.keyring_rows, usage.enrolls] {
            old.extend_from_slice(&count.to_be_bytes());
        }
        desk.kv.tamper(keys::ACCOUNT_USAGE, old);
        let read = desk.usage();
        assert_eq!((read.accounts, read.keyrings), (ACCOUNT_COST + 1000, ACCOUNT_COST + 1000));
        assert_eq!(read.keyring_growth, 0);
        desk.store(1, &ring(1500, 2), 1).unwrap();
        assert_eq!(desk.usage().keyrings, ACCOUNT_COST + 1500, "each counter is over by what the other held");
        assert_eq!(desk.ledger().close_account(&digest(1)), Ok(true));
        let usage = desk.usage();
        assert_eq!((usage.accounts, usage.keyrings), (1000, ACCOUNT_COST), "never below what is held");
        desk.enrolled(2);
        desk.open(2, 2, 1000);
        desk.pretend(|u| (u.accounts, u.keyrings) = (0, 0));
        assert_eq!(desk.ledger().close_account(&digest(2)), Ok(true));
        assert_eq!((desk.usage().accounts, desk.usage().keyrings), (0, 0), "saturates at zero");
    }

    /// Two accounts, one at its session limit with a keyring, and one
    /// expired session for the purge.
    fn busy() -> Desk {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        for d in 1..=MAX_SESSIONS {
            desk.open(1, d, 1000 + d);
        }
        desk.store(3, &ring(100, 1), 0).unwrap();
        desk.open(2, 20, 10);
        desk.open(2, 21, 1000);
        desk.advance(10);
        desk
    }

    #[test]
    fn a_write_failing_anywhere_in_a_step_leaves_the_store_as_it_was() {
        type Op = fn(&Ledger<'_>) -> Result<(), AccessError>;
        let ops: [(&str, Op); 7] = [
            ("enroll", |l| l.enroll(&account(5), &record(5)).map(|_| ())),
            ("open_session", |l| l.open_session(&digest(40), &account(1), &record(1), 1000).map(|_| ())),
            ("close_session", |l| l.close_session(&digest(1))),
            ("close_sessions", |l| l.close_sessions(&digest(2)).map(|_| ())),
            ("store_keyring", |l| l.store_keyring(&digest(3), &ring(200, 2), KeyringVersion(1)).map(|_| ())),
            ("close_account", |l| l.close_account(&digest(3)).map(|_| ())),
            ("purge_expired", |l| l.purge_expired().map(|_| ())),
        ];
        for (name, op) in ops {
            for n in 1.. {
                let desk = busy();
                let before = desk.kv.snapshot();
                desk.kv.fail_write.set(n);
                let result = op(&desk.ledger());
                if desk.kv.fail_write.get() != 0 {
                    // The step made fewer than n writes: it ran clean.
                    assert_eq!(result, Ok(()), "{name}");
                    assert_ne!(desk.kv.snapshot(), before, "{name} wrote");
                    break;
                }
                assert_eq!(result, Err(AccessError::StoreUnavailable), "{name} at write {n}");
                assert_eq!(desk.kv.snapshot(), before, "{name} at write {n}");
            }
        }
    }

    #[test]
    fn damaged_records_read_as_damage_never_as_another_accounts_data() {
        // An account record.
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.kv.tamper(&keys::account(&account(1)), vec![1; 10]);
        let ledger = desk.ledger();
        assert_eq!(ledger.record(&account(1)), unavailable());
        assert_eq!(ledger.enroll(&account(1), &record(1)), unavailable());
        assert_eq!(ledger.keyring(&digest(1)), unavailable());
        assert_eq!(ledger.store_keyring(&digest(1), &ring(10, 1), KeyringVersion(0)), unavailable());
        assert_eq!(ledger.open_session(&digest(2), &account(1), &record(1), 100), unavailable());
        assert_eq!(ledger.close_sessions(&digest(1)), unavailable());
        assert_eq!(ledger.close_account(&digest(1)), unavailable());
        // A keyring.
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.store(1, &ring(10, 1), 0).unwrap();
        let mut cut = desk.kv.get_record(&keys::keyring(&account(1))).unwrap();
        cut.pop();
        desk.kv.tamper(&keys::keyring(&account(1)), cut);
        let ledger = desk.ledger();
        assert_eq!(ledger.keyring(&digest(1)), unavailable());
        assert_eq!(ledger.store_keyring(&digest(1), &ring(10, 1), KeyringVersion(1)), unavailable());
        assert_eq!(ledger.close_account(&digest(1)), unavailable());
        // A keyring left with no account is never handed to whoever takes the name next.
        let orphan = KeyringRecord { version: KeyringVersion(3), keyring: ring(10, 1) };
        desk.kv.tamper(&keys::keyring(&account(7)), orphan.encode());
        assert_eq!(ledger.enroll(&account(7), &record(7)), unavailable());
        assert_eq!(ledger.record(&account(7)), Ok(None));
        // A session record.
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.kv.tamper(&keys::session(&digest(1)), vec![1, 2, 3]);
        let ledger = desk.ledger();
        assert_eq!(ledger.keyring(&digest(1)), unavailable());
        assert_eq!(ledger.close_session(&digest(1)), unavailable());
        assert_eq!(ledger.open_session(&digest(2), &account(1), &record(1), 100), unavailable());
        // A session whose account is gone opens nothing.
        let ghost = SessionRecord { account: account(3), expires_at: UnixTime(desk.now() + 100) };
        desk.kv.tamper(&keys::session(&digest(9)), ghost.encode());
        assert_eq!(ledger.keyring(&digest(9)), Ok(None));
        assert_eq!(ledger.store_keyring(&digest(9), &ring(10, 1), KeyringVersion(0)), Ok(KeyringWrite::Unauthorized));
        assert_eq!(ledger.close_sessions(&digest(9)), Ok(false));
        assert_eq!(ledger.close_account(&digest(9)), Ok(false));
        // The usage.
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.kv.tamper(keys::ACCOUNT_USAGE, vec![1; 36]);
        let ledger = desk.ledger();
        assert_eq!(ledger.enroll(&account(2), &record(2)), unavailable());
        assert_eq!(ledger.open_session(&digest(2), &account(1), &record(1), 100), unavailable());
        assert_eq!(ledger.close_session(&digest(1)), unavailable());
        assert_eq!(ledger.purge_expired(), unavailable());
        assert_eq!(ledger.record(&account(1)), Ok(Some(record(1))), "reading writes no usage");
    }

    #[test]
    fn stale_index_entries_go_without_touching_the_counters() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        desk.open(1, 1, 1000);
        desk.open(2, 2, 1000);
        let soon = |seconds| UnixTime(desk.now() + seconds);
        // No session behind it; another account's session; the right session at another expiry.
        let stale = [
            keys::member_session(&account(1), soon(500), &digest(50)),
            keys::member_session(&account(1), soon(1000), &digest(2)),
            keys::member_session(&account(1), soon(999), &digest(1)),
        ];
        for key in &stale {
            desk.plant(key.clone());
        }
        let sessions = desk.usage().sessions;
        assert!(desk.open(1, 3, 1000).is_some());
        for key in &stale {
            assert_eq!(desk.kv.get_record(key), None, "{key}");
        }
        assert_eq!(desk.usage().sessions, sessions + SESSION_COST);
        assert!(desk.live(1) && desk.live(2) && desk.live(3));
        desk.plant(keys::member_session(&account(1), soon(700), &digest(2)));
        assert_eq!(desk.ledger().close_sessions(&digest(1)), Ok(true));
        assert!(desk.live(2), "another account's session is not closed through a stale entry");
        assert_eq!(desk.keys_starting('m'), vec![keys::member_session(&account(2), soon(1000), &digest(2))]);
        assert_eq!(desk.usage().sessions, SESSION_COST);
        // An expiry entry with no session, and one whose session expires later.
        desk.plant(keys::session_expiry(soon(5), &digest(60)));
        desk.plant(keys::session_expiry(soon(5), &digest(2)));
        desk.advance(10);
        assert_eq!(desk.ledger().purge_expired(), Ok(0));
        assert_eq!(desk.keys_starting('e'), vec![keys::session_expiry(soon(990), &digest(2))]);
        assert!(desk.live(2));
        assert_eq!(desk.usage().sessions, SESSION_COST);
    }

    #[test]
    fn an_index_longer_than_any_account_holds_is_damage() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        let later = UnixTime(desk.now() + 2000);
        // One stale entry beside a full set is tolerated, and cleared.
        for d in 2..=MAX_SESSIONS {
            desk.open(1, d, 1000);
        }
        desk.plant(keys::member_session(&account(1), later, &digest(100)));
        assert!(desk.open(1, 17, 1000).is_some());
        assert_eq!(desk.keys_starting('m').len(), MAX_SESSIONS as usize);
        // More than that is not an account's index.
        desk.plant(keys::member_session(&account(1), later, &digest(101)));
        desk.plant(keys::member_session(&account(1), later, &digest(102)));
        let ledger = desk.ledger();
        assert_eq!(ledger.open_session(&digest(18), &account(1), &record(1), 1000), unavailable());
        assert_eq!(ledger.close_sessions(&digest(17)), unavailable());
        assert_eq!(ledger.close_account(&digest(17)), unavailable());
        // Nor is a key that does not read back.
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.plant(format!("{}0", keys::sessions_of(&account(1)).0));
        assert_eq!(desk.ledger().close_sessions(&digest(1)), Err(AccessError::StoreUnavailable));
    }

    #[test]
    fn a_store_that_is_down_answers_unavailable() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        desk.kv.down.set(true);
        let ledger = desk.ledger();
        assert_eq!(ledger.enroll(&account(2), &record(2)), unavailable());
        assert_eq!(ledger.record(&account(1)), unavailable());
        assert_eq!(ledger.open_session(&digest(2), &account(1), &record(1), 100), unavailable());
        assert_eq!(ledger.close_session(&digest(1)), unavailable());
        assert_eq!(ledger.close_sessions(&digest(1)), unavailable());
        assert_eq!(ledger.keyring(&digest(1)), unavailable());
        assert_eq!(ledger.store_keyring(&digest(1), &ring(10, 1), KeyringVersion(0)), unavailable());
        assert_eq!(ledger.close_account(&digest(1)), unavailable());
        assert_eq!(ledger.purge_expired(), unavailable());
    }

    #[test]
    fn a_flood_of_logins_for_random_names_writes_no_row() {
        let desk = Desk::default();
        let ledger = desk.ledger();
        for n in 0..10_000 {
            let name = account(n);
            assert_eq!(ledger.record(&name), Ok(None));
            assert_eq!(ledger.admit(&name, name.as_bytes(), Class::Login, 10), Ok(true));
            assert_eq!(ledger.park_login(&handle(n), &name, &state(1), 300, Class::Login, None), Ok(()));
        }
        assert_eq!(desk.kv.writes.get(), 0);
        assert_eq!(desk.kv.keys(), Vec::<String>::new());
    }

    #[test]
    fn the_store_never_holds_a_login_state_a_handle_or_a_bucket() {
        let desk = Desk::default();
        desk.enrolled(1);
        let ledger = desk.ledger();
        let (secret, pass) = (state(0x77), bucket(0x0BAD));
        assert_eq!(ledger.admit(&account(1), &pass, Class::Device, 10), Ok(true));
        ledger.park_login(&handle(1), &account(1), &secret, 300, Class::Device, Some(&pass)).unwrap();
        assert_eq!(ledger.take_login(&handle(1)), Ok(Some((account(1), secret.clone()))));
        desk.open(1, 1, 1000);
        desk.store(1, &ring(100, 1), 0).unwrap();
        ledger.park_login(&handle(2), &account(1), &secret, 300, Class::Device, Some(&pass)).unwrap();
        for (key, value) in desk.kv.snapshot() {
            for held in [key.as_bytes(), value.as_slice()] {
                assert!(!contains(held, secret.expose()), "{key}");
                assert!(!contains(held, &pass), "{key}");
                assert!(!contains(held, handle(2).expose()), "{key}");
            }
        }
    }

    #[test]
    fn attempt_limits_outside_their_range_are_refused() {
        let desk = Desk::default();
        let ledger = desk.ledger();
        let admit = |limit| ledger.admit(&account(1), account(1).as_bytes(), Class::Login, limit);
        assert_eq!(admit(0), Err(AccessError::StoreUnavailable));
        assert_eq!(admit(1001), Err(AccessError::StoreUnavailable));
        assert_eq!(admit(1), Ok(true));
        assert_eq!(admit(1), Ok(false));
    }

    #[test]
    fn a_digest_already_filed_is_never_filed_again() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.enrolled(2);
        desk.open(1, 1, 100);
        let ledger = desk.ledger();
        assert_eq!(ledger.open_session(&digest(1), &account(2), &record(2), 1000), unavailable());
        assert_eq!(ledger.open_session(&digest(1), &account(1), &record(1), 1000), unavailable());
        desk.advance(100);
        assert_eq!(ledger.open_session(&digest(1), &account(2), &record(2), 1000), unavailable(), "expired too");
        let filed = SessionRecord::decode(&desk.kv.get_record(&keys::session(&digest(1))).unwrap()).unwrap();
        assert_eq!(filed.account, account(1));
        assert_eq!(desk.usage().sessions, SESSION_COST);
    }

    #[test]
    fn a_keyring_version_that_cannot_grow_is_damage() {
        let desk = Desk::default();
        desk.enrolled(1);
        desk.open(1, 1, 1000);
        let last = KeyringRecord { version: KeyringVersion(u64::MAX), keyring: ring(10, 1) };
        desk.kv.tamper(&keys::keyring(&account(1)), last.encode());
        assert_eq!(desk.store(1, &ring(10, 2), u64::MAX), Err(AccessError::StoreUnavailable));
        assert_eq!(desk.kv.get_record(&keys::keyring(&account(1))), Some(last.encode()));
    }
}

mod remote_accounts {
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use access::{AccountStore, Budget, DevicePass, Throttle};
    use custody::{CustodyError, DropId, RevocationDigest};

    use super::super::fakes::{AccountLoopback, block_on};
    use super::super::{Accounts, RemoteAccounts, VaultThrottle, serve_accounts};
    use super::*;
    use crate::core::{AccountCall, AccountReply, Call, Reply};

    type Link<'a> = AccountLoopback<'a, &'a MemoryKv, &'a ManualClock>;

    fn link(desk: &Desk) -> Link<'_> {
        AccountLoopback::new(desk.ledger())
    }

    /// Files attempts the way `throttle_bucket` does, without hashing: the
    /// shared budget under the account, every other budget and pass apart.
    fn toy_bucket(account: &AccountId, budget: &Budget) -> [u8; 32] {
        let mut bucket = *account.as_bytes();
        match budget {
            Budget::Login => {}
            Budget::Registration => bucket[31] ^= 0x01,
            Budget::Device(pass) => {
                bucket[30] ^= pass.expose()[0];
                bucket[31] ^= 0x02;
            }
        }
        bucket
    }

    fn device(n: u8) -> Budget {
        Budget::Device(DevicePass::from_array([n; DevicePass::LEN]))
    }

    /// Polls once: a call that waits for anything but its link fails here.
    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("the call waited"),
        }
    }

    #[test]
    fn one_port_call_is_one_request_and_answers_as_the_ledger_does() {
        let desk = Desk::default();
        let link = link(&desk);
        let remote = RemoteAccounts::new(&link, toy_bucket);
        let requests = |n: u32| assert_eq!(link.calls.get(), n);
        assert_eq!(block_on(remote.enroll(&account(1), &record(1))), Ok(true));
        requests(1);
        assert_eq!(block_on(remote.enroll(&account(1), &record(2))), Ok(false));
        requests(2);
        assert_eq!(block_on(remote.record(&account(1))), Ok(Some(record(1))));
        assert_eq!(block_on(remote.record(&account(2))), Ok(None));
        requests(4);
        assert_eq!(block_on(remote.park_login(&handle(1), &account(1), &state(1), 300, &Budget::Login)), Ok(()));
        requests(5);
        assert_eq!(block_on(remote.take_login(&handle(1))), Ok(Some((account(1), state(1)))));
        assert_eq!(block_on(remote.take_login(&handle(1))), Ok(None));
        requests(7);
        let expires = UnixTime(desk.now() + 1000);
        assert_eq!(block_on(remote.open_session(&digest(1), &account(1), &record(1), 1000)), Ok(Some(expires)));
        assert_eq!(block_on(remote.open_session(&digest(2), &account(1), &record(2), 1000)), Ok(None));
        requests(9);
        let none = KeyringSnapshot { keyring: None, version: KeyringVersion::NONE };
        assert_eq!(block_on(remote.keyring(&digest(1))), Ok(Some(none)));
        assert_eq!(block_on(remote.keyring(&digest(2))), Ok(None));
        requests(11);
        let stored = KeyringWrite::Stored(KeyringVersion(1));
        assert_eq!(block_on(remote.store_keyring(&digest(1), &ring(10, 1), KeyringVersion::NONE)), Ok(stored));
        assert_eq!(
            block_on(remote.store_keyring(&digest(1), &ring(10, 2), KeyringVersion::NONE)),
            Ok(KeyringWrite::Stale)
        );
        assert_eq!(
            block_on(remote.store_keyring(&digest(2), &ring(10, 2), KeyringVersion(1))),
            Ok(KeyringWrite::Unauthorized)
        );
        requests(14);
        let snapshot = KeyringSnapshot { keyring: Some(ring(10, 1)), version: KeyringVersion(1) };
        assert_eq!(block_on(remote.keyring(&digest(1))), Ok(Some(snapshot)));
        requests(15);
        assert_eq!(block_on(remote.open_session(&digest(3), &account(1), &record(1), 1000)), Ok(Some(expires)));
        assert_eq!(block_on(remote.close_session(&digest(3))), Ok(()));
        assert_eq!(block_on(remote.close_sessions(&digest(3))), Ok(false));
        requests(18);
        assert_eq!(block_on(remote.admit(&account(1), &bucket(1), Class::Login, 1)), Ok(true));
        assert_eq!(block_on(remote.admit(&account(1), &bucket(1), Class::Login, 1)), Ok(false));
        requests(20);
        assert_eq!(block_on(remote.close_account(&digest(1))), Ok(true));
        assert_eq!(block_on(remote.close_account(&digest(1))), Ok(false));
        assert_eq!(block_on(remote.record(&account(1))), Ok(None));
        requests(23);
        desk.advance(60);
        assert_eq!(block_on(remote.purge_expired()), Ok(1), "the counter");
        requests(24);
    }

    #[test]
    fn logins_park_under_the_budget_their_attempt_spent() {
        let desk = Desk::default();
        desk.enrolled(1);
        let link = link(&desk);
        let remote = RemoteAccounts::new(&link, toy_bucket);
        let park =
            |h: u32, budget: &Budget| block_on(remote.park_login(&handle(h), &account(1), &state(1), 300, budget));
        let taken = |h: u32| block_on(remote.take_login(&handle(h))).unwrap().is_some();
        // A device's bucket holds one login in progress: a new one replaces it.
        park(1, &device(1)).unwrap();
        park(2, &device(1)).unwrap();
        assert!(!taken(1) && taken(2));
        // Another pass of the same account has a bucket of its own.
        park(3, &device(1)).unwrap();
        park(4, &device(2)).unwrap();
        assert!(taken(3) && taken(4));
        // The shared budget files no bucket, and keeps every login.
        park(5, &Budget::Login).unwrap();
        park(6, &Budget::Login).unwrap();
        assert!(taken(5) && taken(6));
        // A registration has no login to park, and the object hears nothing of it.
        let requests = link.calls.get();
        assert_eq!(park(7, &Budget::Registration), unavailable());
        assert_eq!(link.calls.get(), requests);
    }

    #[test]
    fn the_throttle_counts_once_per_account_and_budget_for_every_relay() {
        assert_eq!(Class::of(&Budget::Login), Class::Login);
        assert_eq!(Class::of(&Budget::Registration), Class::Registration);
        assert_eq!(Class::of(&device(1)), Class::Device);
        let desk = Desk::default();
        let (here, there) = (link(&desk), link(&desk));
        let (here, there) = (RemoteAccounts::new(&here, toy_bucket), RemoteAccounts::new(&there, toy_bucket));
        let (here, there) = (VaultThrottle::new(&here, 2, toy_bucket), VaultThrottle::new(&there, 2, toy_bucket));
        assert!(block_on(here.admit(&account(1), &Budget::Login)));
        assert!(block_on(there.admit(&account(1), &Budget::Login)));
        assert!(!block_on(here.admit(&account(1), &Budget::Login)));
        assert!(!block_on(there.admit(&account(1), &Budget::Login)));
        // Spending one budget never spends another, nor another account's.
        for budget in [Budget::Registration, device(1), device(2)] {
            assert!(block_on(here.admit(&account(1), &budget)));
            assert!(block_on(there.admit(&account(1), &budget)));
            assert!(!block_on(here.admit(&account(1), &budget)));
        }
        assert!(block_on(here.admit(&account(2), &Budget::Login)));
        desk.advance(60);
        assert!(block_on(there.admit(&account(1), &Budget::Login)));
    }

    #[test]
    fn every_accounts_call_is_ready_on_its_first_poll() {
        let desk = Desk::default();
        let link = link(&desk);
        let remote = RemoteAccounts::new(&link, toy_bucket);
        let throttle = VaultThrottle::new(&remote, 10, toy_bucket);
        assert_eq!(ready(remote.enroll(&account(1), &record(1))), Ok(true));
        assert_eq!(ready(remote.record(&account(1))), Ok(Some(record(1))));
        assert!(ready(throttle.admit(&account(1), &device(1))));
        assert_eq!(ready(remote.admit(&account(1), &bucket(1), Class::Login, 10)), Ok(true));
        assert_eq!(ready(remote.park_login(&handle(1), &account(1), &state(1), 300, &device(1))), Ok(()));
        assert!(ready(remote.take_login(&handle(1))).unwrap().is_some());
        assert!(ready(remote.open_session(&digest(1), &account(1), &record(1), 1000)).unwrap().is_some());
        assert!(ready(remote.open_session(&digest(2), &account(1), &record(1), 1000)).unwrap().is_some());
        assert!(ready(remote.keyring(&digest(1))).unwrap().is_some());
        assert!(matches!(
            ready(remote.store_keyring(&digest(1), &ring(10, 1), KeyringVersion::NONE)),
            Ok(KeyringWrite::Stored(_))
        ));
        assert_eq!(ready(remote.close_session(&digest(2))), Ok(()));
        assert_eq!(ready(remote.close_sessions(&digest(1))), Ok(true));
        assert!(ready(remote.open_session(&digest(3), &account(1), &record(1), 1000)).unwrap().is_some());
        assert_eq!(ready(remote.close_account(&digest(3))), Ok(true));
        assert!(ready(remote.purge_expired()).is_ok());
        assert_eq!(link.calls.get(), 15);
    }

    mod remote_adversary {
        use super::*;

        #[test]
        fn a_garbled_or_mismatched_reply_is_a_fault_and_never_an_answer() {
            let desk = Desk::default();
            desk.enrolled(1);
            desk.park(1, 1, 300);
            let link = link(&desk);
            let remote = RemoteAccounts::new(&link, toy_bucket);
            let throttle = VaultThrottle::new(&remote, 10, toy_bucket);
            for garble in [
                vec![],
                vec![0xFF],
                AccountReply::Done.encode(),
                AccountReply::Purged(1).encode(),
                AccountReply::Written(KeyringWrite::Stale).encode(),
                Reply::Flag(true).encode(),
                Reply::Failed(CustodyError::StorageFull).encode(),
            ] {
                *link.garble.borrow_mut() = Some(garble);
                assert_eq!(block_on(remote.record(&account(1))), unavailable());
                assert_eq!(block_on(remote.take_login(&handle(1))), unavailable());
                assert_eq!(block_on(remote.open_session(&digest(1), &account(1), &record(1), 100)), unavailable());
                assert_eq!(block_on(remote.enroll(&account(2), &record(2))), unavailable());
                assert!(!block_on(throttle.admit(&account(1), &Budget::Login)));
            }
            // An answer to another call is no answer to this one.
            *link.garble.borrow_mut() = Some(AccountReply::Login(Some((account(1), state(9)))).encode());
            assert_eq!(block_on(remote.record(&account(1))), unavailable());
            *link.garble.borrow_mut() = Some(AccountReply::Flag(true).encode());
            assert_eq!(block_on(remote.keyring(&digest(1))), unavailable());
            // A fault the object reports arrives as it is.
            *link.garble.borrow_mut() = Some(AccountReply::Failed(AccessError::StorageFull).encode());
            assert_eq!(block_on(remote.enroll(&account(2), &record(2))), Err(AccessError::StorageFull));
            assert!(!block_on(throttle.admit(&account(1), &Budget::Login)));
        }

        #[test]
        fn a_call_that_does_not_decode_is_refused_and_changes_nothing() {
            let desk = Desk::default();
            desk.enrolled(1);
            desk.open(1, 1, 1000);
            let before = desk.kv.snapshot();
            let ledger = desk.ledger();
            let refused = AccountReply::Failed(AccessError::StoreUnavailable).encode();
            let revoke = Call::Revoke {
                id: DropId::from_slice(&[1; 16]).unwrap(),
                digest: RevocationDigest::from_array([2; 32]),
            };
            for junk in [
                vec![],
                vec![0x41],
                vec![0x4B, 0],
                vec![0x4C; 68],
                Call::PurgeExpired.encode(),
                // As long as a keyring write: a custody call never runs here.
                revoke.encode(),
                AccountReply::Done.encode(),
            ] {
                assert_eq!(serve_accounts(&ledger, &junk), refused, "{junk:?}");
            }
            assert_eq!(desk.kv.snapshot(), before);
            // Noise under every tag: never a panic, always a reply.
            let mut seed: u64 = 0x5EED;
            let mut next = || {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                (seed >> 33) as u32
            };
            for _ in 0..5000 {
                let len = next() as usize % 300;
                let mut junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                if let Some(tag) = junk.first_mut() {
                    *tag = 0x41 + (*tag % 12);
                }
                let reply = serve_accounts(&ledger, &junk);
                assert!(AccountReply::decode(&reply).is_some());
                if AccountCall::decode(&junk).is_none() {
                    assert_eq!(reply, refused);
                }
            }
        }

        #[test]
        fn a_cut_link_or_a_store_that_is_down_answers_unavailable() {
            let desk = Desk::default();
            desk.enrolled(1);
            desk.open(1, 1, 1000);
            desk.park(1, 1, 300);
            let link = link(&desk);
            let remote = RemoteAccounts::new(&link, toy_bucket);
            let ring = ring(10, 1);
            link.cut.set(true);
            assert_eq!(block_on(remote.enroll(&account(2), &record(2))), unavailable());
            assert_eq!(block_on(remote.record(&account(1))), unavailable());
            assert_eq!(
                block_on(remote.park_login(&handle(2), &account(1), &state(1), 300, &Budget::Login)),
                unavailable()
            );
            assert_eq!(block_on(remote.take_login(&handle(1))), unavailable());
            assert_eq!(block_on(remote.open_session(&digest(2), &account(1), &record(1), 100)), unavailable());
            assert_eq!(block_on(remote.close_session(&digest(1))), unavailable());
            assert_eq!(block_on(remote.close_sessions(&digest(1))), unavailable());
            assert_eq!(block_on(remote.keyring(&digest(1))), unavailable());
            assert_eq!(block_on(remote.store_keyring(&digest(1), &ring, KeyringVersion::NONE)), unavailable());
            assert_eq!(block_on(remote.close_account(&digest(1))), unavailable());
            assert_eq!(block_on(remote.purge_expired()), unavailable());
            assert_eq!(block_on(remote.admit(&account(1), &bucket(1), Class::Login, 10)), unavailable());
            link.cut.set(false);
            assert_eq!(block_on(remote.take_login(&handle(1))), Ok(Some((account(1), state(1)))), "nothing was lost");
            desk.kv.down.set(true);
            assert_eq!(block_on(remote.enroll(&account(2), &record(2))), unavailable());
            assert_eq!(block_on(remote.record(&account(1))), unavailable());
            assert_eq!(block_on(remote.open_session(&digest(2), &account(1), &record(1), 100)), unavailable());
            assert_eq!(block_on(remote.close_session(&digest(1))), unavailable());
            assert_eq!(block_on(remote.close_sessions(&digest(1))), unavailable());
            assert_eq!(block_on(remote.keyring(&digest(1))), unavailable());
            assert_eq!(block_on(remote.store_keyring(&digest(1), &ring, KeyringVersion::NONE)), unavailable());
            assert_eq!(block_on(remote.close_account(&digest(1))), unavailable());
            assert_eq!(block_on(remote.purge_expired()), unavailable());
            // A full store says full, across the wire too.
            desk.kv.down.set(false);
            desk.pretend(|usage| usage.enrolls = ENROLLS_PER_DAY);
            assert_eq!(block_on(remote.enroll(&account(2), &record(2))), Err(AccessError::StorageFull));
        }

        #[test]
        fn the_throttle_refuses_on_every_fault() {
            let desk = Desk::default();
            let link = link(&desk);
            let remote = RemoteAccounts::new(&link, toy_bucket);
            // Limits a caller may not ask for: the object refuses them, the throttle admits nothing.
            for limit in [0, crate::core::ATTEMPT_LIMIT_CEILING + 1] {
                assert_eq!(block_on(remote.admit(&account(1), &bucket(1), Class::Login, limit)), unavailable());
                assert!(!block_on(VaultThrottle::new(&remote, limit, toy_bucket).admit(&account(1), &Budget::Login)));
            }
            let throttle = VaultThrottle::new(&remote, 10, toy_bucket);
            link.cut.set(true);
            for budget in [Budget::Login, Budget::Registration, device(1)] {
                assert!(!block_on(throttle.admit(&account(1), &budget)));
            }
            link.cut.set(false);
            for fault in [AccessError::StoreUnavailable, AccessError::StorageFull, AccessError::Throttled] {
                *link.garble.borrow_mut() = Some(AccountReply::Failed(fault).encode());
                assert!(!block_on(throttle.admit(&account(1), &Budget::Login)));
            }
            *link.garble.borrow_mut() = None;
            assert!(block_on(throttle.admit(&account(1), &Budget::Login)), "the first real attempt");
        }
    }
}
