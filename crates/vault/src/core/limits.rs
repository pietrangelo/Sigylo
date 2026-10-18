//! What the vault may hold and write, so that neither the object store nor
//! the Durable Object's daily allowance can be run out by a flood.

/// Bytes in the object store, payloads, chunks and garbage together: half of
/// R2's free 10 GB.
pub const OBJECT_BYTES_CEILING: u64 = 5 * 1024 * 1024 * 1024;

/// Records in the key-value store: deposits, requests and garbage entries.
/// The largest, a request, is under 1.3 KiB, so this stays near 1 GiB at most.
pub const RECORD_CEILING: u64 = 1_000_000;

/// Rows written in one day (UTC) past which nothing new is stored. The vault
/// runs on Workers Paid, where rows past the 50 million a month included cost
/// $1 per million and nothing is blocked: this caps what a flood can add to
/// the bill at about $1 a day, instead of switching storing off for everyone.
/// On Workers Free (100,000 rows a day, then every write fails) it must be
/// back under half of that.
pub const STORING_WRITES_PER_DAY: u32 = 1_000_000;
/// Rows written in one day past which purging and collecting wait for the
/// next day: tearing a secret down costs about twice the writes of storing
/// it, so this leaves room to clean up a full day of storing, and still caps
/// the bill. Expired records are invisible anyway.
pub const TEARDOWN_WRITES_PER_DAY: u32 = 2 * STORING_WRITES_PER_DAY;

/// Expired records one purge removes at most, so a purge fits in a request.
pub const PURGE_BATCH: usize = 500;

/// How long a file still missing chunks may wait for them.
pub const INCOMPLETE_FILE_SECONDS: u32 = 10 * 60;

pub const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
