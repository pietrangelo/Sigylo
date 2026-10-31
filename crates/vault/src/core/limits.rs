//! What the vault may hold and write, so that neither the object store nor
//! the Durable Object's daily allowance can be run out by a flood.

/// Bytes in the object store, payloads, chunks and garbage together. Past
/// R2's free 10 GB each GB costs $0.015 a month, so a full store adds about
/// $0.60 a month, while filling it takes ten times the addresses 5 GiB did.
pub const OBJECT_BYTES_CEILING: u64 = 50 * 1024 * 1024 * 1024;

/// Records in the key-value store: deposits, requests and garbage entries.
/// The largest, a request, is under 1.3 KiB, so this stays near 1 GiB at most.
pub const RECORD_CEILING: u64 = 1_000_000;

/// Rows written in one day (UTC) past which nothing new is stored. The vault
/// runs on Workers Paid, where rows past the 50 million a month included cost
/// $1 per million and nothing is blocked: this caps what a flood can add to
/// the bill at about $1 a day. Past it, storing stops for everyone, worldwide,
/// until UTC midnight (opening, burning, revoking and purging go on); the
/// per-class limits below keep one class of writes from reaching it alone and
/// starving the others. On Workers Free (100,000 rows a day, then every write
/// fails) it must be back under half of that.
pub const STORING_WRITES_PER_DAY: u32 = 1_000_000;

/// Today's rows requests and chunk reservations may never take: the last
/// fifth of [`STORING_WRITES_PER_DAY`] stays for deposits and answers (the
/// envelopes, file manifests included). Requests and chunks are the cheap
/// floods (no payload to seal, or one reservation per MiB); without this,
/// they alone could spend the day's rows and refuse every secret until
/// midnight.
pub const DEPOSIT_WRITES_RESERVE: u32 = STORING_WRITES_PER_DAY / 5;

/// Records requests and chunk reservations may never take: the last fifth of
/// [`RECORD_CEILING`] stays for deposits and answers, so a flood of requests
/// kept 7 days cannot leave the store refusing every secret for days.
pub const DEPOSIT_RECORD_RESERVE: u64 = RECORD_CEILING / 5;

/// Bytes of the object store chunk reservations may never take: they stay
/// for envelopes (plain secrets, answers and file manifests, 64 KiB at most
/// each). Ten-chunk files kept 7 days fill [`OBJECT_BYTES_CEILING`] from one
/// IPv6 /48 in about 3 hours; without this, such a flood would refuse every
/// text secret too.
pub const ENVELOPE_BYTES_RESERVE: u64 = 5 * 1024 * 1024 * 1024;

/// Live requests at most. A request costs about 3 rows, needs only a
/// 1216-byte key of any content and no object in the store, and lives up to
/// 7 days: one IPv6 /48 at its 300 POSTs a minute would otherwise fill
/// [`RECORD_CEILING`] in about 3 days. Past it only new requests are refused.
pub const REQUEST_RECORD_CEILING: u64 = 100_000;

/// Rows requests may write in one day (UTC), out of
/// [`STORING_WRITES_PER_DAY`]: one IPv6 /48 posting requests would otherwise
/// reach the daily threshold alone in about 18.5 hours. Past it only new
/// requests are refused, until midnight.
pub const REQUEST_ROWS_PER_DAY: u32 = 150_000;

// The per-class limits sit inside the global ones, and every reserve holds
// something: checked when the crate builds.
const _: () = {
    assert!(REQUEST_RECORD_CEILING <= RECORD_CEILING - DEPOSIT_RECORD_RESERVE);
    assert!(REQUEST_ROWS_PER_DAY <= STORING_WRITES_PER_DAY - DEPOSIT_WRITES_RESERVE);
    assert!(DEPOSIT_RECORD_RESERVE > 0 && DEPOSIT_WRITES_RESERVE > 0);
    assert!(ENVELOPE_BYTES_RESERVE > 0 && ENVELOPE_BYTES_RESERVE < OBJECT_BYTES_CEILING);
};

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
