//! What the accounts object may hold and write, so that neither its storage,
//! its memory nor the Durable Object's daily allowance can be run out by a
//! flood. The costs are the PostgreSQL row costs the accounts had before
//! (`access.row_cost`), so the ceilings hold as many rows as they did.

use access::Budget;

use super::limits::TEARDOWN_WRITES_PER_DAY;

/// What an account weighs in [`ACCOUNT_BYTES_CEILING`].
pub const ACCOUNT_COST: u64 = 512;
/// Accounts alone. Accounts do not expire, so they have a ceiling of their
/// own; keyrings have another ([`KEYRING_BYTES_CEILING`]), so that large
/// keyrings can never stop registration.
pub const ACCOUNT_BYTES_CEILING: u64 = 64 * 1024 * 1024;
/// Keyrings alone, each weighing its length. Only a keyring that grows
/// checks it.
pub const KEYRING_BYTES_CEILING: u64 = 64 * 1024 * 1024;
/// Bytes keyrings may grow by in one day (UTC), all accounts together, past
/// which no keyring grows until the next: filling [`KEYRING_BYTES_CEILING`]
/// for good takes 13 days or more. A keyring is charged only what it grows
/// by; a write that does not grow it is free.
pub const KEYRING_GROWTH_BYTES_PER_DAY: u32 = (KEYRING_BYTES_CEILING / 13) as u32;

/// What a session weighs in [`SESSION_BYTES_CEILING`].
pub const SESSION_COST: u64 = 192;
/// Fewest rows opening a session writes: the session, its two index entries
/// and the usage record (pinned by the ledger's tests).
pub const SESSION_OPEN_ROWS: u32 = 4;
/// Most sessions [`SESSION_ROWS_PER_DAY`] lets one day open.
pub const SESSIONS_PER_DAY: u32 = SESSION_ROWS_PER_DAY.div_ceil(SESSION_OPEN_ROWS);
/// Live sessions of every account together. A session lives 12 hours, so the
/// live ones were opened over two UTC days at most: the ceiling holds two
/// days of sessions, and the day's [`SESSION_ROWS_PER_DAY`] always stops a
/// flood of sign-ins before it, so self-registered accounts can never fill
/// it and lock everyone else out.
pub const SESSION_BYTES_CEILING: u64 = 96 * 1024 * 1024;
const _: () = assert!(SESSION_BYTES_CEILING >= 2 * SESSIONS_PER_DAY as u64 * SESSION_COST);
const _: () = assert!(KEYRING_GROWTH_BYTES_PER_DAY as u64 * 13 <= KEYRING_BYTES_CEILING);

/// What an attempt counter weighs in the memory pools.
pub const COUNTER_COST: u64 = 128;
/// What a login in progress weighs in the memory pools.
pub const PARKED_LOGIN_COST: u64 = 384;

/// Which allowance an attempt spends, as the accounts object knows it: an
/// [`access::Budget`] without the pass, which reaches the object only as the
/// bucket its counter is filed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// Logins without a valid pass: the one guessing spends.
    Login,
    /// Registrations of a name nobody holds.
    Registration,
    /// Logins from a device that holds a pass.
    Device,
}

impl Class {
    /// The class of the budget an attempt spends; a device's pass stays
    /// with the caller.
    pub fn of(budget: &Budget) -> Self {
        match budget {
            Budget::Login => Self::Login,
            Budget::Registration => Self::Registration,
            Budget::Device(_) => Self::Device,
        }
    }
}

/// Memory for the logins that spend the shared budget and their counters,
/// and where the two reserves overflow.
pub const SHARED_POOL: u64 = 16 * 1024 * 1024;
/// Memory for registration counters first, so a flood of logins does not
/// stop registrations.
pub const REGISTRATION_RESERVE: u64 = 1024 * 1024;
/// Memory for device logins and their counters first, so a flood of guesses
/// does not lock the owners' devices out. Each account holds at most
/// [`DEVICE_SHARE_PER_ACCOUNT`] of it.
pub const DEVICE_RESERVE: u64 = 8 * 1024 * 1024;
/// Device buckets one account may hold at once, a bucket held while its
/// counter or its parked login lives: a stolen pass takes one of them, never
/// all, and an account rotating passes holds at most this many parked logins.
pub const DEVICE_BUCKETS_PER_ACCOUNT: u8 = 16;
/// What one account may hold of [`DEVICE_RESERVE`]: one device bucket's
/// worth, its counter and its parked login. The account's other buckets are
/// charged to [`SHARED_POOL`], so accounts an attacker registers hold one
/// bucket each of the reserve, never sixteen, and a day of registrations
/// ([`ENROLLS_PER_DAY`]) cannot fill it.
pub const DEVICE_SHARE_PER_ACCOUNT: u64 = COUNTER_COST + PARKED_LOGIN_COST;
const _: () = assert!(DEVICE_RESERVE / DEVICE_SHARE_PER_ACCOUNT > ENROLLS_PER_DAY as u64);

/// How long an attempt counter counts.
pub const ATTEMPT_WINDOW_SECONDS: u32 = 60;
/// Most attempts a window may allow; anything else is a broken caller.
pub const ATTEMPT_LIMIT_CEILING: u16 = 1000;

/// Session rows written in one day (UTC) past which no session opens until
/// the next. Each class of row has its own allowance, so a flood of keyring
/// writes or registrations cannot stop sign-in. Rows past the 50 million a
/// month included cost $1 per million: together with keyrings and enrolls,
/// the accounts object adds at most about 2 million rows a day to the
/// custody vault's 2 million.
pub const SESSION_ROWS_PER_DAY: u32 = 1_000_000;
/// Keyring rows written in one day past which no keyring is written, even
/// one no larger than before, until the next.
pub const KEYRING_ROWS_PER_DAY: u32 = 250_000;
/// Accounts created in one day past which registration waits for the next:
/// filling [`ACCOUNT_BYTES_CEILING`] for good takes 13 days or more.
pub const ENROLLS_PER_DAY: u32 = 10_000;
const _: () = assert!(ENROLLS_PER_DAY as u64 * ACCOUNT_COST * 13 <= ACCOUNT_BYTES_CEILING);
/// Rows written in one day past which purging waits for the next day.
/// Closing a session or an account never waits.
pub const ACCOUNT_TEARDOWN_ROWS_PER_DAY: u32 = TEARDOWN_WRITES_PER_DAY;
/// Batches of expired sessions one purge removes at most.
pub const ACCOUNT_PURGE_BATCHES: usize = 10;
