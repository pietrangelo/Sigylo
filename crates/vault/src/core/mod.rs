//! Core ring: how the vault lays out its records and keys, and what it may
//! hold. Pure and deterministic.

pub mod account_keys;
mod account_limits;
mod account_records;
pub mod keys;
mod limits;
mod records;
mod wire;

pub use account_limits::{
    ACCOUNT_BYTES_CEILING, ACCOUNT_COST, ACCOUNT_PURGE_BATCHES, ACCOUNT_TEARDOWN_ROWS_PER_DAY, ATTEMPT_LIMIT_CEILING,
    ATTEMPT_WINDOW_SECONDS, COUNTER_COST, Class, DEVICE_BUCKETS_PER_ACCOUNT, DEVICE_RESERVE, ENROLLS_PER_DAY,
    KEYRING_ROWS_PER_DAY, PARKED_LOGIN_COST, REGISTRATION_RESERVE, SESSION_BYTES_CEILING, SESSION_COST,
    SESSION_ROWS_PER_DAY, SHARED_POOL,
};
pub use account_records::{AccountRecord, AccountUsage, KeyringRecord, SessionRecord, snapshot};
pub use limits::{
    INCOMPLETE_FILE_SECONDS, OBJECT_BYTES_CEILING, PURGE_BATCH, RECORD_CEILING, SECONDS_PER_DAY,
    STORING_WRITES_PER_DAY, TEARDOWN_WRITES_PER_DAY,
};
pub use records::{DepositRecord, GarbageEntry, RequestRecord, Stored, Usage, chunk_len};
pub use wire::{Call, Reply};
