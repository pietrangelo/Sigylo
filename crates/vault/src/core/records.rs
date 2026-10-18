//! The byte layout of each record, strict and canonical: a record decodes
//! only if it is exactly what [`encode`](DepositRecord::encode) would write,
//! so a damaged store reads as missing data, never as different data.

use custody::{
    ChunkCount, ChunkIndex, ClaimDigest, DropId, MAX_CHUNK_LEN, MAX_PAYLOAD_LEN, MIN_CHUNK_LEN, MIN_PAYLOAD_LEN,
    ObjectName, RecipientKeyBlob, Retention, RevocationDigest, UnixTime,
};

const VERSION: u8 = 1;

/// A sealed object kept in the object store: its random name and its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    pub object: ObjectName,
    pub len: u32,
}

/// A deposit as the vault keeps it: everything but the sealed bytes, which
/// live in the object store under [`DepositRecord::payload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositRecord {
    pub retention: Retention,
    pub expires_at: UnixTime,
    pub payload: Stored,
    pub revocation: Option<RevocationDigest>,
    /// Set once a burn-after-reading file has been opened.
    pub claim: Option<ClaimDigest>,
    /// A file still missing chunks expires soon; its last chunk restores
    /// the expiry chosen, kept here meanwhile.
    pub completes_at: Option<UnixTime>,
    /// A file's chunks, one slot per chunk; `None` for a plain secret.
    pub chunks: Option<Vec<Option<Stored>>>,
}

impl DepositRecord {
    pub fn count(&self) -> Option<ChunkCount> {
        self.chunks.as_ref().and_then(|slots| ChunkCount::new(slots.len() as u16).ok())
    }

    /// Every chunk is in (always true of a plain secret).
    pub fn complete(&self) -> bool {
        self.chunks.as_ref().is_none_or(|slots| slots.iter().all(Option::is_some))
    }

    pub fn slot(&self, index: ChunkIndex) -> Option<Stored> {
        self.chunks.as_ref()?.get(usize::from(index.get())).copied().flatten()
    }

    /// Every object the deposit holds in the object store.
    pub fn objects(&self) -> Vec<Stored> {
        let chunks = self.chunks.iter().flatten().flatten().copied();
        core::iter::once(self.payload).chain(chunks).collect()
    }

    /// Bytes of every object, payload and chunks.
    pub fn object_bytes(&self) -> u64 {
        self.objects().iter().map(|s| u64::from(s.len)).sum()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 21 * 10);
        out.push(VERSION);
        out.push(match self.retention {
            Retention::BurnAfterReading => 0,
            Retention::UntilExpiry => 1,
        });
        let flags = u8::from(self.revocation.is_some())
            | u8::from(self.claim.is_some()) << 1
            | u8::from(self.chunks.is_some()) << 2
            | u8::from(self.completes_at.is_some()) << 3;
        out.push(flags);
        out.extend_from_slice(&self.expires_at.0.to_be_bytes());
        push_stored(&mut out, self.payload);
        if let Some(digest) = &self.revocation {
            out.extend_from_slice(digest.as_bytes());
        }
        if let Some(claim) = &self.claim {
            out.extend_from_slice(claim.as_bytes());
        }
        if let Some(at) = self.completes_at {
            out.extend_from_slice(&at.0.to_be_bytes());
        }
        if let Some(slots) = &self.chunks {
            out.push(slots.len() as u8);
            for slot in slots {
                match slot {
                    None => out.push(0),
                    Some(stored) => {
                        out.push(1);
                        push_stored(&mut out, *stored);
                    }
                }
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.byte()? != VERSION {
            return None;
        }
        let retention = match r.byte()? {
            0 => Retention::BurnAfterReading,
            1 => Retention::UntilExpiry,
            _ => return None,
        };
        let flags = r.byte()?;
        if flags & !0b1111 != 0 {
            return None;
        }
        let expires_at = UnixTime(r.i64()?);
        let payload = r.stored()?;
        if !(MIN_PAYLOAD_LEN..=MAX_PAYLOAD_LEN).contains(&(payload.len as usize)) {
            return None;
        }
        let revocation = if flags & 1 != 0 { Some(RevocationDigest::from_array(r.array()?)) } else { None };
        let claim = if flags & 2 != 0 { Some(ClaimDigest::from_array(r.array()?)) } else { None };
        let completes_at = if flags & 8 != 0 { Some(UnixTime(r.i64()?)) } else { None };
        let chunks = if flags & 4 != 0 {
            let count = ChunkCount::new(u16::from(r.byte()?)).ok()?;
            let mut slots = Vec::with_capacity(usize::from(count.get()));
            for index in 0..count.get() {
                slots.push(match r.byte()? {
                    0 => None,
                    1 => {
                        let stored = r.stored()?;
                        let index = ChunkIndex::new(index).ok()?;
                        let len = stored.len as usize;
                        (chunk_len(len) && count.takes(index, len)).then_some(stored)?;
                        Some(stored)
                    }
                    _ => return None,
                });
            }
            Some(slots)
        } else {
            None
        };
        r.end()?;
        let record = Self { retention, expires_at, payload, revocation, claim, completes_at, chunks };
        // Only a complete burn-after-reading file can be claimed, and only an
        // incomplete file waits for its expiry.
        let claimable = record.chunks.is_some() && record.retention == Retention::BurnAfterReading;
        if record.claim.is_some() && !(claimable && record.completes_at.is_none()) {
            return None;
        }
        if record.completes_at.is_some() && (record.chunks.is_none() || record.complete()) {
            return None;
        }
        Some(record)
    }
}

/// A recipient's request: their public key, and the inbox its answer goes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRecord {
    pub expires_at: UnixTime,
    pub inbox: DropId,
    pub recipient_key: RecipientKeyBlob,
}

impl RequestRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + DropId::LEN + RecipientKeyBlob::LEN);
        out.push(VERSION);
        out.extend_from_slice(&self.expires_at.0.to_be_bytes());
        out.extend_from_slice(self.inbox.as_bytes());
        out.extend_from_slice(self.recipient_key.as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.byte()? != VERSION {
            return None;
        }
        let expires_at = UnixTime(r.i64()?);
        let inbox = DropId::from_slice(r.take(DropId::LEN)?).ok()?;
        let recipient_key = RecipientKeyBlob::new(r.take(RecipientKeyBlob::LEN)?.to_vec()).ok()?;
        r.end()?;
        Some(Self { expires_at, inbox, recipient_key })
    }
}

/// An object whose record is gone (or not yet written): due for deletion
/// from the object store at `due`, and still counted until then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GarbageEntry {
    pub due: UnixTime,
    pub len: u32,
}

impl GarbageEntry {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13);
        out.push(VERSION);
        out.extend_from_slice(&self.due.0.to_be_bytes());
        out.extend_from_slice(&self.len.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.byte()? != VERSION {
            return None;
        }
        let entry = Self { due: UnixTime(r.i64()?), len: r.u32()? };
        r.end()?;
        Some(entry)
    }
}

/// What the vault holds, kept up to date by every write so that checking the
/// ceiling never scans, and how many rows it wrote today.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Bytes in the object store: payloads, chunks and garbage.
    pub object_bytes: u64,
    /// Deposits, requests and garbage entries.
    pub records: u64,
    /// The day (days since the epoch) `writes` counts.
    pub day: u32,
    pub writes: u32,
}

impl Usage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(25);
        out.push(VERSION);
        out.extend_from_slice(&self.object_bytes.to_be_bytes());
        out.extend_from_slice(&self.records.to_be_bytes());
        out.extend_from_slice(&self.day.to_be_bytes());
        out.extend_from_slice(&self.writes.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.byte()? != VERSION {
            return None;
        }
        let usage = Self { object_bytes: r.u64()?, records: r.u64()?, day: r.u32()?, writes: r.u32()? };
        r.end()?;
        Some(usage)
    }
}

/// Whether a sealed chunk could be `len` bytes long: a power of two from
/// 256 bytes to 1 MiB, plus the 16-byte tag.
pub fn chunk_len(len: usize) -> bool {
    (MIN_CHUNK_LEN..=MAX_CHUNK_LEN).contains(&len) && (len - 16).is_power_of_two()
}

fn push_stored(out: &mut Vec<u8>, stored: Stored) {
    out.extend_from_slice(stored.object.as_bytes());
    out.extend_from_slice(&stored.len.to_be_bytes());
}

/// A cursor that fails instead of panicking.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    pub(crate) fn byte(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn i64(&mut self) -> Option<i64> {
        Some(i64::from_be_bytes(self.array()?))
    }

    pub(crate) fn stored(&mut self) -> Option<Stored> {
        Some(Stored { object: ObjectName::from_array(self.array()?), len: self.u32()? })
    }

    pub(crate) fn end(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(n: u8, len: usize) -> Stored {
        Stored { object: ObjectName::from_array([n; 16]), len: len as u32 }
    }

    fn file() -> DepositRecord {
        DepositRecord {
            retention: Retention::BurnAfterReading,
            expires_at: UnixTime(1_800_000_000),
            payload: stored(1, MIN_PAYLOAD_LEN),
            revocation: Some(RevocationDigest::from_array([2; 32])),
            claim: None,
            completes_at: Some(UnixTime(1_800_000_600)),
            chunks: Some(vec![Some(stored(4, MAX_CHUNK_LEN)), None, Some(stored(5, MIN_CHUNK_LEN))]),
        }
    }

    fn claimed() -> DepositRecord {
        let mut record = DepositRecord { claim: Some(ClaimDigest::from_array([3; 32])), completes_at: None, ..file() };
        record.chunks.as_mut().unwrap()[1] = Some(stored(6, MAX_CHUNK_LEN));
        record
    }

    fn secret() -> DepositRecord {
        DepositRecord {
            retention: Retention::UntilExpiry,
            expires_at: UnixTime(1_700_000_000),
            payload: stored(9, MAX_PAYLOAD_LEN),
            revocation: None,
            claim: None,
            completes_at: None,
            chunks: None,
        }
    }

    fn request() -> RequestRecord {
        RequestRecord {
            expires_at: UnixTime(1_750_000_000),
            inbox: DropId::from_slice(&[6; 16]).unwrap(),
            recipient_key: RecipientKeyBlob::new(vec![7; RecipientKeyBlob::LEN]).unwrap(),
        }
    }

    #[test]
    fn records_round_trip() {
        for record in [file(), claimed(), secret()] {
            assert_eq!(DepositRecord::decode(&record.encode()), Some(record));
        }
        assert_eq!(RequestRecord::decode(&request().encode()), Some(request()));
        let entry = GarbageEntry { due: UnixTime(12), len: 345 };
        assert_eq!(GarbageEntry::decode(&entry.encode()), Some(entry));
        let usage = Usage { object_bytes: 1 << 40, records: 77, day: 20_000, writes: 99 };
        assert_eq!(Usage::decode(&usage.encode()), Some(usage));
    }

    #[test]
    fn a_file_knows_when_it_is_complete_and_what_it_holds() {
        let mut record = file();
        assert!(!record.complete());
        assert_eq!(record.count().map(|c| c.get()), Some(3));
        assert_eq!(record.objects().len(), 3);
        assert_eq!(record.object_bytes(), (MIN_PAYLOAD_LEN + MAX_CHUNK_LEN + MIN_CHUNK_LEN) as u64);
        record.chunks.as_mut().unwrap()[1] = Some(stored(8, MAX_CHUNK_LEN));
        assert!(record.complete());
        assert!(claimed().complete());
        assert_eq!(record.slot(ChunkIndex::new(1).unwrap()), Some(stored(8, MAX_CHUNK_LEN)));
        assert_eq!(record.slot(ChunkIndex::new(3).unwrap()), None);
        assert!(secret().complete() && secret().count().is_none());
    }

    /// The byte layout is the store's format: if this changes, existing
    /// records no longer read. Raise the version instead.
    #[test]
    fn format_pin() {
        let bytes = secret().encode();
        assert_eq!(bytes[..3], [1, 1, 0]);
        assert_eq!(bytes[3..11], 1_700_000_000i64.to_be_bytes());
        assert_eq!(bytes[11..27], [9; 16]);
        assert_eq!(bytes[27..31], (MAX_PAYLOAD_LEN as u32).to_be_bytes());
        assert_eq!(bytes.len(), 31);
        let bytes = file().encode();
        assert_eq!(bytes[..3], [1, 0, 0b1101]);
        assert_eq!(bytes.len(), 31 + 32 + 8 + 1 + (1 + 20) + 1 + (1 + 20));
        let bytes = claimed().encode();
        assert_eq!(bytes[..3], [1, 0, 0b0111]);
        assert_eq!(bytes.len(), 31 + 32 + 32 + 1 + 3 * (1 + 20));
        assert_eq!(request().encode().len(), 1 + 8 + 16 + 1216);
        assert_eq!(GarbageEntry { due: UnixTime(1), len: 2 }.encode(), [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2]);
    }

    mod adversary {
        use super::*;

        #[test]
        fn every_truncation_and_every_extra_byte_is_refused() {
            for bytes in [file().encode(), claimed().encode(), secret().encode(), request().encode()] {
                for cut in 0..bytes.len() {
                    assert_eq!(DepositRecord::decode(&bytes[..cut]), None);
                    assert_eq!(RequestRecord::decode(&bytes[..cut]), None);
                }
                let mut longer = bytes.clone();
                longer.push(0);
                assert_eq!(DepositRecord::decode(&longer), None);
                assert_eq!(RequestRecord::decode(&longer), None);
            }
            let usage = Usage::default().encode();
            assert_eq!(Usage::decode(&usage[..usage.len() - 1]), None);
            assert_eq!(GarbageEntry::decode(&[1, 0]), None);
        }

        #[test]
        fn unknown_versions_flags_and_retentions_are_refused() {
            let good = secret().encode();
            for (at, value) in [(0, 0), (0, 2), (1, 2), (2, 0b1_0000), (2, 0x80)] {
                let mut bad = good.clone();
                bad[at] = value;
                assert_eq!(DepositRecord::decode(&bad), None, "byte {at} = {value}");
            }
        }

        #[test]
        fn sizes_no_sealer_makes_are_refused() {
            for len in [0, MIN_PAYLOAD_LEN - 1, MAX_PAYLOAD_LEN + 1] {
                let record = DepositRecord { payload: stored(1, len), ..secret() };
                assert_eq!(DepositRecord::decode(&record.encode()), None, "payload {len}");
            }
            // A short chunk anywhere but last, a chunk too big or too small.
            for (index, len) in [(0, MIN_CHUNK_LEN), (2, MAX_CHUNK_LEN + 1), (2, MIN_CHUNK_LEN - 1), (2, 300)] {
                let mut record = file();
                record.chunks.as_mut().unwrap()[index] = Some(stored(4, len));
                assert_eq!(DepositRecord::decode(&record.encode()), None, "chunk {index} of {len}");
            }
            for count in [0usize, 11] {
                let record = DepositRecord { chunks: Some(vec![None; count]), ..secret() };
                assert_eq!(DepositRecord::decode(&record.encode()), None, "{count} chunks");
            }
        }

        #[test]
        fn only_a_complete_burn_after_reading_file_can_carry_a_claim() {
            let claim = Some(ClaimDigest::from_array([3; 32]));
            for record in [
                DepositRecord { claim, ..secret() },
                DepositRecord { claim, retention: Retention::BurnAfterReading, ..secret() },
                DepositRecord { retention: Retention::UntilExpiry, ..claimed() },
                DepositRecord { claim, ..file() },
            ] {
                assert_eq!(DepositRecord::decode(&record.encode()), None);
            }
        }

        #[test]
        fn only_an_incomplete_file_waits_for_its_expiry() {
            let at = Some(UnixTime(9));
            for record in
                [DepositRecord { completes_at: at, ..secret() }, DepositRecord { completes_at: at, ..claimed() }]
            {
                assert_eq!(DepositRecord::decode(&record.encode()), None);
            }
        }

        #[test]
        fn a_slot_marker_other_than_zero_or_one_is_refused() {
            let mut bytes = file().encode();
            let marker = 31 + 32 + 8 + 1 + 21;
            assert_eq!(bytes[marker], 0);
            bytes[marker] = 2;
            assert_eq!(DepositRecord::decode(&bytes), None);
        }
    }
}
