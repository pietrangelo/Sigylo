//! The byte layout of each account record, strict and canonical like the
//! custody vault's ([`super::records`]): a record decodes only if it is
//! exactly what `encode` writes, and every value goes through the Access
//! constructors again, so a damaged store reads as damage, never as another
//! account's data.

use access::{AccountId, Keyring, KeyringSnapshot, KeyringVersion, MAX_KEYRING_LEN, RegistrationRecord, UnixTime};

use super::records::Reader;

const VERSION: u8 = 1;
/// The usage record's own version: 2 since keyrings have a ceiling and a
/// daily growth of their own.
const USAGE_VERSION: u8 = 2;
/// The usage record before that, which weighed accounts and keyrings as one.
const USAGE_ONE_WEIGHT: u8 = 1;

/// An account: its OPAQUE registration record, and nothing else, so reading
/// it costs the same whatever the account keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    pub record: RegistrationRecord,
}

impl AccountRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + RegistrationRecord::LEN);
        out.push(VERSION);
        out.extend_from_slice(self.record.as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.byte()? != VERSION {
            return None;
        }
        let record = RegistrationRecord::from_slice(r.take(RegistrationRecord::LEN)?).ok()?;
        r.end()?;
        Some(Self { record })
    }
}

/// An account's keyring as stored, sealed on the device, with the version
/// it was written at (1 or more: an account with no keyring has no record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringRecord {
    pub version: KeyringVersion,
    pub keyring: Keyring,
}

impl KeyringRecord {
    pub fn encode(&self) -> Vec<u8> {
        let ring = self.keyring.as_bytes();
        let mut out = Vec::with_capacity(1 + 8 + 4 + ring.len());
        out.push(VERSION);
        out.extend_from_slice(&self.version.0.to_be_bytes());
        out.extend_from_slice(&(ring.len() as u32).to_be_bytes());
        out.extend_from_slice(ring);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.byte()? != VERSION {
            return None;
        }
        let version = KeyringVersion(r.u64()?);
        if version == KeyringVersion::NONE {
            return None;
        }
        let len = usize::try_from(r.u32()?).ok()?;
        if len > MAX_KEYRING_LEN {
            return None;
        }
        let keyring = Keyring::new(r.take(len)?.to_vec()).ok()?;
        r.end()?;
        Some(Self { version, keyring })
    }
}

/// The keyring as the account reads it: none at version 0 when the account
/// never stored one.
pub fn snapshot(record: Option<KeyringRecord>) -> KeyringSnapshot {
    match record {
        None => KeyringSnapshot { keyring: None, version: KeyringVersion::NONE },
        Some(KeyringRecord { version, keyring }) => KeyringSnapshot { keyring: Some(keyring), version },
    }
}

/// A session, filed under the keyed digest of its token: whose it is and
/// until when it lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRecord {
    pub account: AccountId,
    pub expires_at: UnixTime,
}

impl SessionRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + AccountId::LEN + 8);
        out.push(VERSION);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(&self.expires_at.0.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.byte()? != VERSION {
            return None;
        }
        let record = Self { account: AccountId::from_array(r.array()?), expires_at: UnixTime(r.i64()?) };
        r.end()?;
        Some(record)
    }
}

/// What the accounts object holds, kept up to date by every write so that
/// checking a ceiling never scans, and what it wrote today by class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountUsage {
    /// Weight of accounts ([`super::ACCOUNT_COST`] each).
    pub accounts: u64,
    /// Weight of keyrings (each its length).
    pub keyrings: u64,
    /// Weight of sessions ([`super::SESSION_COST`] each).
    pub sessions: u64,
    /// The day (days since the epoch) the counts below count.
    pub day: u32,
    /// Every row written today.
    pub rows: u32,
    pub session_rows: u32,
    pub keyring_rows: u32,
    /// Accounts created today.
    pub enrolls: u32,
    /// Bytes keyrings grew by today.
    pub keyring_growth: u32,
}

impl AccountUsage {
    /// The usage as of `day`: on a new day the daily counts start from zero,
    /// while what is held stays.
    pub fn on(self, day: u32) -> Self {
        if self.day == day {
            self
        } else {
            Self { accounts: self.accounts, keyrings: self.keyrings, sessions: self.sessions, day, ..Self::default() }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49);
        out.push(USAGE_VERSION);
        for weight in [self.accounts, self.keyrings, self.sessions] {
            out.extend_from_slice(&weight.to_be_bytes());
        }
        for count in [self.day, self.rows, self.session_rows, self.keyring_rows, self.enrolls, self.keyring_growth] {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out
    }

    /// Reads version 2, and version 1 as written before keyrings had a
    /// ceiling of their own. Version 1's one weight held accounts and
    /// keyrings together and cannot be split without a scan, so each counter
    /// takes it whole: neither ever counts less than is held, and every
    /// decrement saturates at zero. The over-count stays for good: the
    /// keyrings' bytes held when version 2 first wrote, in the accounts'
    /// weight, and the accounts' in the keyrings'. Its keyring growth starts
    /// at zero.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        let usage = match r.byte()? {
            USAGE_VERSION => Self {
                accounts: r.u64()?,
                keyrings: r.u64()?,
                sessions: r.u64()?,
                day: r.u32()?,
                rows: r.u32()?,
                session_rows: r.u32()?,
                keyring_rows: r.u32()?,
                enrolls: r.u32()?,
                keyring_growth: r.u32()?,
            },
            USAGE_ONE_WEIGHT => {
                let stored = r.u64()?;
                Self {
                    accounts: stored,
                    keyrings: stored,
                    sessions: r.u64()?,
                    day: r.u32()?,
                    rows: r.u32()?,
                    session_rows: r.u32()?,
                    keyring_rows: r.u32()?,
                    enrolls: r.u32()?,
                    keyring_growth: 0,
                }
            }
            _ => return None,
        };
        r.end()?;
        Some(usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> AccountRecord {
        AccountRecord { record: RegistrationRecord::from_slice(&[0xA5; RegistrationRecord::LEN]).unwrap() }
    }

    fn keyring() -> KeyringRecord {
        KeyringRecord { version: KeyringVersion(7), keyring: Keyring::new(vec![0x6B; 300]).unwrap() }
    }

    fn session() -> SessionRecord {
        SessionRecord { account: AccountId::from_array([0x5C; 32]), expires_at: UnixTime(1_800_000_000) }
    }

    fn usage() -> AccountUsage {
        AccountUsage {
            accounts: 1 << 26,
            keyrings: 1 << 25,
            sessions: 192 * 16,
            day: 20_000,
            rows: 1_000_001,
            session_rows: 999_999,
            keyring_rows: 1,
            enrolls: 10_000,
            keyring_growth: 73_728,
        }
    }

    /// A usage record as version 1 wrote it: accounts and keyrings in one
    /// weight, and no keyring growth.
    fn usage_v1(stored: u64, sessions: u64, counts: [u32; 5]) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&stored.to_be_bytes());
        bytes.extend_from_slice(&sessions.to_be_bytes());
        for count in counts {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn records_round_trip() {
        assert_eq!(AccountRecord::decode(&account().encode()), Some(account()));
        assert_eq!(KeyringRecord::decode(&keyring().encode()), Some(keyring()));
        assert_eq!(SessionRecord::decode(&session().encode()), Some(session()));
        assert_eq!(AccountUsage::decode(&usage().encode()), Some(usage()));
        let largest = KeyringRecord {
            version: KeyringVersion(u64::MAX),
            keyring: Keyring::new(vec![1; MAX_KEYRING_LEN]).unwrap(),
        };
        assert_eq!(KeyringRecord::decode(&largest.encode()), Some(largest));
    }

    #[test]
    fn a_missing_keyring_reads_as_version_zero() {
        assert_eq!(snapshot(None), KeyringSnapshot { keyring: None, version: KeyringVersion::NONE });
        let stored = snapshot(Some(keyring()));
        assert_eq!(stored, KeyringSnapshot { keyring: Some(keyring().keyring), version: KeyringVersion(7) });
    }

    #[test]
    fn a_new_day_counts_rows_afresh_and_keeps_what_is_held() {
        let today = usage();
        assert_eq!(today.on(20_000), today);
        let tomorrow = today.on(20_001);
        assert_eq!(
            tomorrow,
            AccountUsage {
                day: 20_001,
                rows: 0,
                session_rows: 0,
                keyring_rows: 0,
                enrolls: 0,
                keyring_growth: 0,
                ..today
            }
        );
        assert_eq!(AccountUsage::default().on(5).day, 5);
    }

    /// The byte layout is the store's format: if this changes, existing
    /// records no longer read. Raise the version instead.
    #[test]
    fn format_pin() {
        let bytes = account().encode();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1..], [0xA5; 192]);
        assert_eq!(bytes.len(), 193);
        let bytes = keyring().encode();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1..9], 7u64.to_be_bytes());
        assert_eq!(bytes[9..13], 300u32.to_be_bytes());
        assert_eq!(bytes[13..], [0x6B; 300]);
        let bytes = session().encode();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1..33], [0x5C; 32]);
        assert_eq!(bytes[33..], 1_800_000_000i64.to_be_bytes());
        assert_eq!(bytes.len(), 41);
        let small = AccountUsage {
            accounts: 1,
            keyrings: 2,
            sessions: 3,
            day: 4,
            rows: 5,
            session_rows: 6,
            keyring_rows: 7,
            enrolls: 8,
            keyring_growth: 9,
        };
        let mut expected = vec![2];
        for n in 1..=3u8 {
            expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, n]);
        }
        for n in 4..=9u8 {
            expected.extend_from_slice(&[0, 0, 0, n]);
        }
        assert_eq!(small.encode(), expected);
        assert_eq!(expected.len(), 49);
    }

    /// Usage records written before keyrings had a ceiling of their own still
    /// read. Their one weight held accounts and keyrings together, so it is
    /// taken whole for each: neither ceiling ever counts less than is held.
    #[test]
    fn a_version_one_usage_still_reads() {
        let old = usage_v1(1 << 20, 192 * 3, [20_000, 50, 12, 6, 2]);
        assert_eq!(old.len(), 37);
        let read = AccountUsage::decode(&old).unwrap();
        assert_eq!(
            read,
            AccountUsage {
                accounts: 1 << 20,
                keyrings: 1 << 20,
                sessions: 192 * 3,
                day: 20_000,
                rows: 50,
                session_rows: 12,
                keyring_rows: 6,
                enrolls: 2,
                keyring_growth: 0,
            }
        );
        assert_eq!(read.encode()[0], 2, "written back as version 2");
        assert_eq!(AccountUsage::decode(&read.encode()), Some(read));
        for cut in 0..old.len() {
            assert!(AccountUsage::decode(&old[..cut]).is_none(), "cut at {cut}");
        }
        let mut longer = old;
        longer.extend_from_slice(&[0; 12]);
        assert!(AccountUsage::decode(&longer).is_none(), "a version 1 with version 2's length");
    }

    mod adversary {
        use super::*;

        #[test]
        fn every_truncation_and_every_extra_byte_is_refused() {
            fn refused<T>(bytes: Vec<u8>, decode: impl Fn(&[u8]) -> Option<T>) {
                for cut in 0..bytes.len() {
                    assert!(decode(&bytes[..cut]).is_none(), "cut at {cut}");
                }
                let mut longer = bytes;
                longer.push(0);
                assert!(decode(&longer).is_none());
            }
            refused(account().encode(), AccountRecord::decode);
            refused(keyring().encode(), KeyringRecord::decode);
            refused(session().encode(), SessionRecord::decode);
            refused(usage().encode(), AccountUsage::decode);
        }

        #[test]
        fn unknown_versions_are_refused() {
            fn refused<T>(mut bytes: Vec<u8>, decode: impl Fn(&[u8]) -> Option<T>, versions: &[u8]) {
                for &version in versions {
                    bytes[0] = version;
                    assert!(decode(&bytes).is_none(), "version {version}");
                }
            }
            refused(account().encode(), AccountRecord::decode, &[0, 2, 0xFF]);
            refused(keyring().encode(), KeyringRecord::decode, &[0, 2, 0xFF]);
            refused(session().encode(), SessionRecord::decode, &[0, 2, 0xFF]);
            // Version 1 is the old usage layout, shorter: a version 2 record
            // relabelled as 1 does not read as one.
            refused(usage().encode(), AccountUsage::decode, &[0, 1, 3, 0xFF]);
            refused(usage_v1(1, 2, [3, 4, 5, 6, 7]), AccountUsage::decode, &[0, 2, 3, 0xFF]);
        }

        #[test]
        fn a_stored_keyring_is_never_at_version_zero() {
            let unwritten = KeyringRecord { version: KeyringVersion::NONE, ..keyring() };
            assert_eq!(KeyringRecord::decode(&unwritten.encode()), None);
        }

        #[test]
        fn keyring_lengths_no_device_writes_are_refused() {
            let header = |len: u32| {
                let mut bytes = vec![1];
                bytes.extend_from_slice(&1u64.to_be_bytes());
                bytes.extend_from_slice(&len.to_be_bytes());
                bytes
            };
            let empty = header(0);
            assert_eq!(KeyringRecord::decode(&empty), None);
            let too_large = MAX_KEYRING_LEN + 1;
            let mut bytes = header(too_large as u32);
            bytes.resize(bytes.len() + too_large, 1);
            assert_eq!(KeyringRecord::decode(&bytes), None);
            // The declared length must be the length that follows.
            for (declared, actual) in [(10, 9), (10, 11), (u32::MAX, 10)] {
                let mut bytes = header(declared);
                bytes.resize(bytes.len() + actual, 1);
                assert_eq!(KeyringRecord::decode(&bytes), None, "{declared} declared, {actual} there");
            }
        }

        #[test]
        fn debug_prints_no_record_keyring_or_account_bytes() {
            let rendered = format!("{:?} {:?} {:?}", account(), keyring(), session());
            // An account id shows its first two bytes, as everywhere in Access.
            for leak in ["a5a5", "165, 165", "6b6b", "107, 107", "5c5c5c", "92, 92"] {
                assert!(!rendered.to_lowercase().contains(leak), "{leak}");
            }
        }
    }
}
