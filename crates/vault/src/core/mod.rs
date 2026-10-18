//! Core ring: how the vault lays out its records and keys, and what it may
//! hold. Pure and deterministic.

pub mod keys;
mod limits;
mod records;
mod wire;

pub use limits::{
    INCOMPLETE_FILE_SECONDS, OBJECT_BYTES_CEILING, PURGE_BATCH, RECORD_CEILING, SECONDS_PER_DAY, STORING_WRITES_PER_DAY,
};
pub use records::{DepositRecord, GarbageEntry, RequestRecord, Stored, Usage, chunk_len};
pub use wire::{Call, Reply};
