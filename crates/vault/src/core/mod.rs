//! Core ring: how the vault lays out its records and keys, and what it may
//! hold. Pure and deterministic.

pub mod account_keys;
mod account_limits;
mod account_records;
mod account_wire;
pub mod keys;
mod limits;
mod records;
mod wire;

pub use account_limits::{
    ACCOUNT_BYTES_CEILING, ACCOUNT_COST, ACCOUNT_PURGE_BATCHES, ACCOUNT_TEARDOWN_ROWS_PER_DAY, ATTEMPT_LIMIT_CEILING,
    ATTEMPT_WINDOW_SECONDS, COUNTER_COST, Class, DEVICE_BUCKETS_PER_ACCOUNT, DEVICE_RESERVE, ENROLLS_PER_DAY,
    KEYRING_BYTES_CEILING, KEYRING_GROWTH_BYTES_PER_DAY, KEYRING_ROWS_PER_DAY, PARKED_LOGIN_COST, REGISTRATION_RESERVE,
    SESSION_BYTES_CEILING, SESSION_COST, SESSION_OPEN_ROWS, SESSION_ROWS_PER_DAY, SESSIONS_PER_DAY, SHARED_POOL,
};
pub use account_records::{AccountRecord, AccountUsage, KeyringRecord, SessionRecord, snapshot};
pub use account_wire::{AccountCall, AccountReply};
pub use limits::{
    DEPOSIT_RECORD_RESERVE, DEPOSIT_WRITES_RESERVE, ENVELOPE_BYTES_RESERVE, INCOMPLETE_FILE_SECONDS,
    OBJECT_BYTES_CEILING, PURGE_BATCH, RECORD_CEILING, REQUEST_RECORD_CEILING, REQUEST_ROWS_PER_DAY, SECONDS_PER_DAY,
    STORING_WRITES_PER_DAY, TEARDOWN_WRITES_PER_DAY,
};
pub use records::{DepositRecord, GarbageEntry, RequestRecord, Stored, Usage, chunk_len};
pub use wire::{Call, Reply};
