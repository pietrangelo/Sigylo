//! What the vault may hold and write, so that neither the object store nor
//! the Durable Object's daily allowance can be run out by a flood.

/// Bytes in the object store, payloads, chunks and garbage together: half of
/// R2's free 10 GB.
pub const OBJECT_BYTES_CEILING: u64 = 5 * 1024 * 1024 * 1024;

/// Records in the key-value store: deposits, requests and garbage entries.
/// The largest, a request, is under 1.3 KiB, so this stays near 1 GiB at most.
pub const RECORD_CEILING: u64 = 1_000_000;

/// Rows written in one day (UTC) past which nothing new is stored: half of
/// the 100,000 a Workers Free account may write each day, so opening,
/// burning, revoking and purging keep working when storing has stopped.
/// On a paid plan, where each million rows costs money, it caps the bill.
pub const STORING_WRITES_PER_DAY: u32 = 50_000;
/// Rows written in one day past which purging and collecting wait for the
/// next day: tearing a secret down costs about twice the writes of storing
/// it, so a week of floods expiring at once must not eat the 20,000 left
/// for opening, burning and revoking. Expired records are invisible anyway.
pub const TEARDOWN_WRITES_PER_DAY: u32 = 80_000;

/// Expired records one purge removes at most, so a purge fits in a request.
pub const PURGE_BATCH: usize = 500;

/// How long a file still missing chunks may wait for them.
pub const INCOMPLETE_FILE_SECONDS: u32 = 10 * 60;

pub const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
