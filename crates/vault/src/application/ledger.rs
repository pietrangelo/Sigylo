//! The custody rules over the ordered key-value store, one atomic step per
//! call: the bookkeeping half of the vault. It never touches a sealed byte;
//! [`super::LedgerVault`] moves those to and from the object store around
//! these steps.

use core::cell::Cell;

use custody::{
    CLAIM_WINDOW_SECONDS, ChunkCount, ChunkIndex, ChunkRef, ClaimDigest, CustodyError, DropId, GARBAGE_BATCH,
    GARBAGE_GRACE_SECONDS, Lifetime, ObjectName, PostedRequest, RESERVATION_FRESH_SECONDS, RESERVATION_SECONDS,
    Receipt, RecipientKeyBlob, Retention, RevocationDigest, UnixTime,
};

use super::ports::KeyValue;
use crate::core::keys::{self, Kind};
use crate::core::{
    DEPOSIT_RECORD_RESERVE, DEPOSIT_WRITES_RESERVE, DepositRecord, ENVELOPE_BYTES_RESERVE, GarbageEntry,
    INCOMPLETE_FILE_SECONDS, OBJECT_BYTES_CEILING, PURGE_BATCH, RECORD_CEILING, REQUEST_RECORD_CEILING,
    REQUEST_ROWS_PER_DAY, RequestRecord, SECONDS_PER_DAY, STORING_WRITES_PER_DAY, Stored, TEARDOWN_WRITES_PER_DAY,
    Usage, chunk_len,
};

/// A deposit whose payload is already in the object store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: DropId,
    pub payload: Stored,
    pub retention: Retention,
    pub lifetime: Lifetime,
    pub revocation: Option<RevocationDigest>,
    pub chunks: Option<ChunkCount>,
}

/// A deposit that can be opened: live, complete and not yet claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    pub payload: Stored,
    pub chunks: Option<ChunkCount>,
}

/// What opening did. `discard` names a burned payload, already in the
/// garbage, that may be deleted from the object store right away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    pub burned: bool,
    pub chunks: Option<ChunkCount>,
    pub discard: Option<ObjectName>,
}

/// A recipient's request as the ledger takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRequest {
    pub id: DropId,
    pub inbox: DropId,
    pub recipient_key: RecipientKeyBlob,
    pub lifetime: Lifetime,
}

/// What a storing step files, which decides how much of the room it may
/// use: the cheap kinds stop short of reserves kept for envelopes, so that a
/// flood of one kind cannot refuse every secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filing {
    /// A payload: a plain secret, an answer or a file manifest. It may use
    /// every ceiling up to the top.
    Envelope,
    /// A chunk reservation: stops short of [`ENVELOPE_BYTES_RESERVE`],
    /// [`DEPOSIT_RECORD_RESERVE`] and [`DEPOSIT_WRITES_RESERVE`].
    Chunk,
    /// A request: stops short of the record and write reserves, and has a
    /// ceiling ([`REQUEST_RECORD_CEILING`]) and a daily budget
    /// ([`REQUEST_ROWS_PER_DAY`]) of its own.
    Request,
}

impl Filing {
    /// Whether today's writes leave room for this kind.
    fn writes_left(self, usage: &Usage) -> bool {
        match self {
            Self::Envelope => usage.writes < STORING_WRITES_PER_DAY,
            Self::Chunk => usage.writes < STORING_WRITES_PER_DAY - DEPOSIT_WRITES_RESERVE,
            Self::Request => {
                usage.writes < STORING_WRITES_PER_DAY - DEPOSIT_WRITES_RESERVE
                    && usage.request_writes < REQUEST_ROWS_PER_DAY
            }
        }
    }

    /// Whether `bytes` more in the object store and `records` more records
    /// stay within what this kind may use.
    fn fits(self, usage: &Usage, bytes: u64, records: u64) -> bool {
        let byte_ceiling = match self {
            Self::Chunk => OBJECT_BYTES_CEILING - ENVELOPE_BYTES_RESERVE,
            Self::Envelope | Self::Request => OBJECT_BYTES_CEILING,
        };
        let record_ceiling = match self {
            Self::Envelope => RECORD_CEILING,
            Self::Chunk | Self::Request => RECORD_CEILING - DEPOSIT_RECORD_RESERVE,
        };
        let requests_fit = self != Self::Request || usage.requests.saturating_add(records) <= REQUEST_RECORD_CEILING;
        usage.object_bytes.saturating_add(bytes) <= byte_ceiling
            && usage.records.saturating_add(records) <= record_ceiling
            && requests_fit
    }
}

/// The custody rules on a [`KeyValue`] store.
#[derive(Debug)]
pub struct Ledger<K> {
    kv: K,
    /// Writes made by the step in progress.
    writes: Cell<u32>,
}

fn after(now: UnixTime, seconds: u32) -> UnixTime {
    UnixTime(now.0.saturating_add(i64::from(seconds)))
}

fn day(now: UnixTime) -> u32 {
    u32::try_from(now.0.div_euclid(SECONDS_PER_DAY)).unwrap_or(0)
}

/// A record that does not decode is damage, not absence: refuse to act on it.
fn damaged<T>(_: T) -> CustodyError {
    CustodyError::VaultUnavailable
}

impl<K: KeyValue> Ledger<K> {
    pub fn new(kv: K) -> Self {
        Self { kv, writes: Cell::new(0) }
    }

    // ---- storage, counting every write -------------------------------

    fn put(&self, key: &str, value: &[u8]) -> Result<(), CustodyError> {
        self.writes.set(self.writes.get() + 1);
        self.kv.put(key, value)
    }

    fn delete(&self, key: &str) -> Result<(), CustodyError> {
        self.writes.set(self.writes.get() + 1);
        self.kv.delete(key)
    }

    fn read<T>(&self, key: &str, decode: impl Fn(&[u8]) -> Option<T>) -> Result<Option<T>, CustodyError> {
        match self.kv.get(key)? {
            None => Ok(None),
            Some(bytes) => decode(&bytes).map(Some).ok_or_else(|| damaged(())),
        }
    }

    fn usage(&self, now: UnixTime) -> Result<Usage, CustodyError> {
        let mut usage = self.read(keys::USAGE, Usage::decode)?.unwrap_or_default();
        if usage.day != day(now) {
            usage.day = day(now);
            usage.writes = 0;
            usage.request_writes = 0;
        }
        Ok(usage)
    }

    /// Runs one atomic step. If it wrote anything, the usage it updated is
    /// written too, counting its own write.
    fn step<T>(&self, now: UnixTime, f: impl FnOnce(&mut Usage) -> Result<T, CustodyError>) -> Result<T, CustodyError> {
        self.kv.atomically(|| {
            self.writes.set(0);
            let mut usage = self.usage(now)?;
            let out = f(&mut usage)?;
            if self.writes.get() > 0 {
                usage.writes = usage.writes.saturating_add(self.writes.get() + 1);
                self.kv.put(keys::USAGE, &usage.encode())?;
            }
            Ok(out)
        })
    }

    /// Inside a storing step: whether there is room for `bytes` more in the
    /// object store and `records` more records, and writes left today, for
    /// what `filing` stores.
    fn ensure_room(usage: &Usage, filing: Filing, bytes: u64, records: u64) -> Result<(), CustodyError> {
        if filing.writes_left(usage) && filing.fits(usage, bytes, records) {
            Ok(())
        } else {
            Err(CustodyError::StorageFull)
        }
    }

    /// Before a storing step: whether it can fit. If a ceiling is in the
    /// way, what expired goes first (in a step of its own, so it stays gone
    /// whatever the storing step decides). Writes nothing when there is room.
    fn check_room(&self, now: UnixTime, filing: Filing, bytes: u64, records: u64) -> Result<(), CustodyError> {
        let usage = self.usage(now)?;
        if !filing.writes_left(&usage) {
            return Err(CustodyError::StorageFull);
        }
        if !filing.fits(&usage, bytes, records) {
            self.purge_batch(now)?;
            Self::ensure_room(&self.usage(now)?, filing, bytes, records)?;
        }
        Ok(())
    }

    // ---- records -------------------------------------------------------

    fn deposit_record(&self, id: &DropId) -> Result<Option<DepositRecord>, CustodyError> {
        self.read(&keys::deposit(id), DepositRecord::decode)
    }

    fn live_deposit(&self, now: UnixTime, id: &DropId) -> Result<Option<DepositRecord>, CustodyError> {
        Ok(self.deposit_record(id)?.filter(|d| d.expires_at > now))
    }

    fn request_record(&self, id: &DropId) -> Result<Option<RequestRecord>, CustodyError> {
        self.read(&keys::request(id), RequestRecord::decode)
    }

    fn save_deposit(&self, id: &DropId, record: &DepositRecord) -> Result<(), CustodyError> {
        self.put(&keys::deposit(id), &record.encode())
    }

    /// Moves the expiry index entry of a deposit.
    fn reindex(&self, id: &DropId, from: UnixTime, to: UnixTime) -> Result<(), CustodyError> {
        if from != to {
            self.delete(&keys::expiry(from, Kind::Deposit, id))?;
            self.put(&keys::expiry(to, Kind::Deposit, id), &[])?;
        }
        Ok(())
    }

    fn add_garbage(&self, usage: &mut Usage, stored: Stored, due: UnixTime) -> Result<(), CustodyError> {
        self.put(&keys::object(&stored.object), &GarbageEntry { due, len: stored.len }.encode())?;
        self.put(&keys::garbage(due, &stored.object), &[])?;
        usage.records += 1;
        Ok(())
    }

    /// Takes an object out of the garbage; its bytes stay counted.
    fn drop_garbage_entry(
        &self,
        usage: &mut Usage,
        object: &ObjectName,
        entry: GarbageEntry,
    ) -> Result<(), CustodyError> {
        self.delete(&keys::object(object))?;
        self.delete(&keys::garbage(entry.due, object))?;
        usage.records = usage.records.saturating_sub(1);
        Ok(())
    }

    /// Deletes a deposit; its objects join the garbage.
    fn remove_deposit(
        &self,
        usage: &mut Usage,
        now: UnixTime,
        id: &DropId,
        record: &DepositRecord,
    ) -> Result<(), CustodyError> {
        self.delete(&keys::deposit(id))?;
        self.delete(&keys::expiry(record.expires_at, Kind::Deposit, id))?;
        usage.records = usage.records.saturating_sub(1);
        for stored in record.objects() {
            self.add_garbage(usage, stored, after(now, GARBAGE_GRACE_SECONDS))?;
        }
        Ok(())
    }

    fn remove_request(&self, usage: &mut Usage, id: &DropId, record: &RequestRecord) -> Result<(), CustodyError> {
        self.delete(&keys::request(id))?;
        self.delete(&keys::expiry(record.expires_at, Kind::Request, id))?;
        usage.records = usage.records.saturating_sub(1);
        // Saturating: requests filed before the counter existed are not in it.
        usage.requests = usage.requests.saturating_sub(1);
        Ok(())
    }

    /// Files a new deposit under `id`, inside a storing step.
    fn insert_deposit(
        &self,
        usage: &mut Usage,
        now: UnixTime,
        id: &DropId,
        entry: &Entry,
    ) -> Result<UnixTime, CustodyError> {
        if let Some(old) = self.deposit_record(id)? {
            if old.expires_at > now {
                return Err(CustodyError::AlreadyExists);
            }
            // Expired is gone in every observable way; let the id be reused.
            self.remove_deposit(usage, now, id, &old)?;
        }
        // Its payload was reserved (and counted) before it went to the store.
        let fresh = after(now, RESERVATION_SECONDS - RESERVATION_FRESH_SECONDS);
        let reserved = self
            .read(&keys::object(&entry.payload.object), GarbageEntry::decode)?
            .filter(|r| r.len == entry.payload.len && r.due > fresh)
            .ok_or(CustodyError::VaultUnavailable)?;
        self.drop_garbage_entry(usage, &entry.payload.object, reserved)?;
        let chosen = after(now, entry.lifetime.seconds());
        let (expires_at, completes_at) = match entry.chunks {
            // Until its last chunk is in, a file expires soon.
            Some(_) => (chosen.min(after(now, INCOMPLETE_FILE_SECONDS)), Some(chosen)),
            None => (chosen, None),
        };
        let record = DepositRecord {
            retention: entry.retention,
            expires_at,
            payload: entry.payload,
            revocation: entry.revocation,
            claim: None,
            completes_at,
            chunks: entry.chunks.map(|count| vec![None; usize::from(count.get())]),
        };
        self.save_deposit(id, &record)?;
        self.put(&keys::expiry(expires_at, Kind::Deposit, id), &[])?;
        usage.records += 1;
        Ok(chosen)
    }

    // ---- use cases -----------------------------------------------------

    /// Before a payload goes to the store: counts it and puts its name in
    /// the garbage, so that if it is never filed it is still collected.
    pub fn reserve_payload(&self, now: UnixTime, stored: Stored) -> Result<(), CustodyError> {
        // Two records: the reservation now, the deposit once it is filed.
        self.check_room(now, Filing::Envelope, u64::from(stored.len), 2)?;
        self.step(now, |usage| {
            Self::ensure_room(usage, Filing::Envelope, u64::from(stored.len), 2)?;
            self.add_garbage(usage, stored, after(now, RESERVATION_SECONDS))?;
            usage.object_bytes += u64::from(stored.len);
            Ok(())
        })
    }

    /// Files a deposit whose payload was reserved and is in the store.
    pub fn deposit(&self, now: UnixTime, entry: &Entry) -> Result<UnixTime, CustodyError> {
        self.step(now, |usage| self.insert_deposit(usage, now, &entry.id, entry))
    }

    /// Whether today's writes leave room for cleaning up (see [`TEARDOWN_WRITES_PER_DAY`]).
    fn may_tear_down(&self, now: UnixTime) -> Result<bool, CustodyError> {
        Ok(self.usage(now)?.writes < TEARDOWN_WRITES_PER_DAY)
    }

    /// Whether the deposit can be opened, and where its payload is. Writes nothing.
    pub fn find(&self, now: UnixTime, id: &DropId) -> Result<Option<Found>, CustodyError> {
        let found = self.live_deposit(now, id)?.filter(|d| d.claim.is_none() && d.complete());
        Ok(found.map(|d| Found { payload: d.payload, chunks: d.count() }))
    }

    /// Opens what [`Ledger::find`] found, once its payload has been read: a
    /// burn-after-reading secret is deleted, a burn-after-reading file
    /// claimed with `claim`. `None` if it can no longer be opened (another
    /// read burned or claimed it meanwhile).
    pub fn commit_open(
        &self,
        now: UnixTime,
        id: &DropId,
        payload: &ObjectName,
        claim: &ClaimDigest,
    ) -> Result<Option<Committed>, CustodyError> {
        self.step(now, |usage| {
            let Some(mut record) = self.live_deposit(now, id)? else { return Ok(None) };
            if record.claim.is_some() || !record.complete() || record.payload.object != *payload {
                return Ok(None);
            }
            let chunks = record.count();
            Ok(Some(match (record.retention, chunks) {
                (Retention::UntilExpiry, _) => Committed { burned: false, chunks, discard: None },
                (Retention::BurnAfterReading, None) => {
                    self.remove_deposit(usage, now, id, &record)?;
                    Committed { burned: true, chunks, discard: Some(*payload) }
                }
                (Retention::BurnAfterReading, Some(_)) => {
                    // Claimed: its chunks now go only to the holder of the
                    // claim, who has a limited time to fetch them.
                    let expires_at = record.expires_at.min(after(now, CLAIM_WINDOW_SECONDS));
                    self.reindex(id, record.expires_at, expires_at)?;
                    record.expires_at = expires_at;
                    record.claim = Some(*claim);
                    self.save_deposit(id, &record)?;
                    Committed { burned: true, chunks, discard: None }
                }
            }))
        })
    }

    /// Whether chunk `index` of `len` bytes may be stored for the deposit.
    fn takes(record: &DepositRecord, now: UnixTime, index: ChunkIndex, len: u32) -> bool {
        record.expires_at > now
            && record.claim.is_none()
            && chunk_len(len as usize)
            && record.count().is_some_and(|count| count.takes(index, len as usize))
            && record.slot(index).is_none()
    }

    /// Before a chunk is stored: see [`custody::Vault::reserve_chunk`].
    pub fn reserve_chunk(
        &self,
        now: UnixTime,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        let takes = |record: Option<DepositRecord>| record.is_some_and(|r| Self::takes(&r, now, index, len));
        if !takes(self.deposit_record(id)?) {
            return Ok(false);
        }
        self.check_room(now, Filing::Chunk, u64::from(len), 1)?;
        self.step(now, |usage| {
            if !takes(self.deposit_record(id)?) {
                return Ok(false);
            }
            Self::ensure_room(usage, Filing::Chunk, u64::from(len), 1)?;
            self.add_garbage(usage, Stored { object: *object, len }, after(now, RESERVATION_SECONDS))?;
            usage.object_bytes += u64::from(len);
            Ok(true)
        })
    }

    /// After the store kept it: see [`custody::Vault::put_chunk`].
    pub fn put_chunk(
        &self,
        now: UnixTime,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        self.step(now, |usage| {
            let Some(entry) = self.read(&keys::object(object), GarbageEntry::decode)? else { return Ok(false) };
            let stale = after(now, RESERVATION_SECONDS - RESERVATION_FRESH_SECONDS);
            if entry.len != len || entry.due <= stale {
                return Ok(false);
            }
            let Some(mut record) = self.deposit_record(id)?.filter(|r| Self::takes(r, now, index, len)) else {
                return Ok(false);
            };
            self.drop_garbage_entry(usage, object, entry)?;
            if let Some(slot) = record.chunks.as_mut().and_then(|slots| slots.get_mut(usize::from(index.get()))) {
                *slot = Some(Stored { object: *object, len });
            }
            if record.complete()
                && let Some(chosen) = record.completes_at.take()
            {
                // The last chunk gives the file the lifetime chosen for it.
                self.reindex(id, record.expires_at, chosen)?;
                record.expires_at = chosen;
            }
            self.save_deposit(id, &record)?;
            Ok(true)
        })
    }

    /// Where chunk `index` is, for whoever may fetch it. Writes nothing.
    pub fn open_chunk(
        &self,
        now: UnixTime,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimDigest>,
    ) -> Result<Option<ChunkRef>, CustodyError> {
        let Some(record) = self.live_deposit(now, id)? else { return Ok(None) };
        let burns = record.retention == Retention::BurnAfterReading;
        let allowed = if burns { claim.is_some() && record.claim.as_ref() == claim } else { record.complete() };
        Ok(record.slot(index).filter(|_| allowed).map(|stored| ChunkRef { object: stored.object, burns }))
    }

    /// Burns chunk `index` of a claimed file: see [`custody::Vault::burn_chunk`].
    pub fn burn_chunk(
        &self,
        now: UnixTime,
        id: &DropId,
        index: ChunkIndex,
        claim: &ClaimDigest,
    ) -> Result<bool, CustodyError> {
        self.step(now, |usage| {
            let Some(mut record) = self.live_deposit(now, id)? else { return Ok(false) };
            if record.retention != Retention::BurnAfterReading || record.claim.as_ref() != Some(claim) {
                return Ok(false);
            }
            let Some(stored) = record.slot(index) else { return Ok(false) };
            if let Some(slot) = record.chunks.as_mut().and_then(|slots| slots.get_mut(usize::from(index.get()))) {
                *slot = None;
            }
            self.add_garbage(usage, stored, after(now, GARBAGE_GRACE_SECONDS))?;
            if record.chunks.iter().flatten().all(Option::is_none) {
                // The last chunk takes the deposit with it.
                self.remove_deposit(usage, now, id, &record)?;
            } else {
                self.save_deposit(id, &record)?;
            }
            Ok(true)
        })
    }

    /// Objects due for deletion from the store. Writes nothing.
    pub fn garbage(&self, now: UnixTime, limit: u16) -> Result<Vec<ObjectName>, CustodyError> {
        if !self.may_tear_down(now)? {
            return Ok(Vec::new());
        }
        let limit = usize::from(limit.min(GARBAGE_BATCH));
        let due = self.kv.range(keys::GARBAGE, &keys::garbage_bound(now), limit)?;
        due.iter()
            .map(|(key, _)| keys::parse_garbage(key).map(|(_, object)| object).ok_or_else(|| damaged(())))
            .collect()
    }

    /// Forgets objects the store has deleted; their bytes are free again.
    pub fn forget_garbage(&self, now: UnixTime, objects: &[ObjectName]) -> Result<(), CustodyError> {
        if !self.may_tear_down(now)? {
            return Ok(());
        }
        self.step(now, |usage| {
            for object in objects {
                if let Some(entry) = self.read(&keys::object(object), GarbageEntry::decode)? {
                    self.drop_garbage_entry(usage, object, entry)?;
                    usage.object_bytes = usage.object_bytes.saturating_sub(u64::from(entry.len));
                }
            }
            Ok(())
        })
    }

    /// Deletes a live deposit whose revocation digest matches, and names
    /// every object it had (now in the garbage).
    pub fn revoke(
        &self,
        now: UnixTime,
        id: &DropId,
        digest: &RevocationDigest,
    ) -> Result<Option<Vec<ObjectName>>, CustodyError> {
        self.step(now, |usage| {
            let Some(record) = self.live_deposit(now, id)?.filter(|r| r.revocation.as_ref() == Some(digest)) else {
                return Ok(None);
            };
            self.remove_deposit(usage, now, id, &record)?;
            Ok(Some(record.objects().iter().map(|s| s.object).collect()))
        })
    }

    pub fn post_request(&self, now: UnixTime, request: &NewRequest) -> Result<UnixTime, CustodyError> {
        self.check_room(now, Filing::Request, 0, 1)?;
        self.step(now, |usage| {
            if let Some(old) = self.request_record(&request.id)? {
                if old.expires_at > now {
                    return Err(CustodyError::AlreadyExists);
                }
                self.remove_request(usage, &request.id, &old)?;
            }
            Self::ensure_room(usage, Filing::Request, 0, 1)?;
            let expires_at = after(now, request.lifetime.seconds());
            let record =
                RequestRecord { expires_at, inbox: request.inbox, recipient_key: request.recipient_key.clone() };
            self.put(&keys::request(&request.id), &record.encode())?;
            self.put(&keys::expiry(expires_at, Kind::Request, &request.id), &[])?;
            usage.records += 1;
            usage.requests += 1;
            // Every row this step writes, the usage record's own included
            // (as `step` counts it in `writes`).
            usage.request_writes = usage.request_writes.saturating_add(self.writes.get() + 1);
            Ok(expires_at)
        })
    }

    /// Writes nothing.
    pub fn fetch_request(&self, now: UnixTime, id: &DropId) -> Result<Option<PostedRequest>, CustodyError> {
        let live = self.request_record(id)?.filter(|r| r.expires_at > now);
        Ok(live.map(|r| PostedRequest { recipient_key: r.recipient_key, expires_at: r.expires_at }))
    }

    /// Consumes the live request `entry.id` and files `entry` in its inbox,
    /// in one step. `None` when there was no live request.
    pub fn answer_request(&self, now: UnixTime, entry: &Entry) -> Result<Option<Receipt>, CustodyError> {
        self.step(now, |usage| {
            let Some(request) = self.request_record(&entry.id)?.filter(|r| r.expires_at > now) else {
                return Ok(None);
            };
            self.remove_request(usage, &entry.id, &request)?;
            let expires_at = self.insert_deposit(usage, now, &request.inbox, entry)?;
            Ok(Some(Receipt { id: request.inbox, expires_at }))
        })
    }

    /// Removes expired records, oldest first, in one step that looks at
    /// [`PURGE_BATCH`] of them at most. Says how many went, and whether more
    /// may be waiting.
    pub fn purge_batch(&self, now: UnixTime) -> Result<(u64, bool), CustodyError> {
        if !self.may_tear_down(now)? {
            return Ok((0, false));
        }
        self.step(now, |usage| {
            let expired = self.kv.range(keys::EXPIRY, &keys::expiry_bound(now), PURGE_BATCH)?;
            let more = expired.len() == PURGE_BATCH;
            let mut gone = 0;
            for (key, _) in expired {
                let (at, kind, id) = keys::parse_expiry(&key).ok_or_else(|| damaged(()))?;
                match kind {
                    Kind::Deposit => match self.deposit_record(&id)? {
                        Some(record) if record.expires_at == at => {
                            self.remove_deposit(usage, now, &id, &record)?;
                            gone += 1;
                        }
                        _ => self.delete(&key)?,
                    },
                    Kind::Request => match self.request_record(&id)? {
                        Some(record) if record.expires_at == at => {
                            self.remove_request(usage, &id, &record)?;
                            gone += 1;
                        }
                        _ => self.delete(&key)?,
                    },
                }
            }
            Ok((gone, more))
        })
    }

    /// What the vault holds right now.
    pub fn usage_now(&self, now: UnixTime) -> Result<Usage, CustodyError> {
        self.usage(now)
    }
}
