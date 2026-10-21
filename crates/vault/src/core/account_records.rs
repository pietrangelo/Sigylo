//! The byte layout of each account record, strict and canonical like the
//! custody vault's ([`super::records`]): a record decodes only if it is
//! exactly what `encode` writes, and every value goes through the Access
//! constructors again, so a damaged store reads as damage, never as another
//! account's data.

use access::{AccountId, Keyring, KeyringSnapshot, KeyringVersion, MAX_KEYRING_LEN, RegistrationRecord, UnixTime};

use super::records::Reader;

const VERSION: u8 = 1;

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
/// checking a ceiling never scans, and the rows it wrote today by class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountUsage {
    /// Weight of accounts and keyrings ([`super::ACCOUNT_COST`] each, plus
    /// the keyring's length).
    pub stored: u64,
    /// Weight of sessions ([`super::SESSION_COST`] each).
    pub sessions: u64,
    /// The day (days since the epoch) the row counts below count.
    pub day: u32,
    /// Every row written today.
    pub rows: u32,
    pub session_rows: u32,
    pub keyring_rows: u32,
    /// Accounts created today.
    pub enrolls: u32,
}

impl AccountUsage {
    /// The usage as of `day`: on a new day the row counts start from zero,
    /// while what is held stays.
    pub fn on(self, day: u32) -> Self {
        if self.day == day {
            self
        } else {
            Self { stored: self.stored, sessions: self.sessions, day, ..Self::default() }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(37);
        out.push(VERSION);
        out.extend_from_slice(&self.stored.to_be_bytes());
        out.extend_from_slice(&self.sessions.to_be_bytes());
        for count in [self.day, self.rows, self.session_rows, self.keyring_rows, self.enrolls] {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.byte()? != VERSION {
            return None;
        }
        let usage = Self {
            stored: r.u64()?,
            sessions: r.u64()?,
            day: r.u32()?,
            rows: r.u32()?,
            session_rows: r.u32()?,
            keyring_rows: r.u32()?,
            enrolls: r.u32()?,
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
            stored: 1 << 26,
            sessions: 192 * 16,
            day: 20_000,
            rows: 1_000_001,
            session_rows: 999_999,
            keyring_rows: 1,
            enrolls: 10_000,
        }
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
            AccountUsage { day: 20_001, rows: 0, session_rows: 0, keyring_rows: 0, enrolls: 0, ..today }
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
        let small =
            AccountUsage { stored: 1, sessions: 2, day: 3, rows: 4, session_rows: 5, keyring_rows: 6, enrolls: 7 };
        let mut expected = vec![1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2];
        for n in 3..=7u8 {
            expected.extend_from_slice(&[0, 0, 0, n]);
        }
        assert_eq!(small.encode(), expected);
        assert_eq!(expected.len(), 37);
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
            fn refused<T>(mut bytes: Vec<u8>, decode: impl Fn(&[u8]) -> Option<T>) {
                for version in [0, 2, 0xFF] {
                    bytes[0] = version;
                    assert!(decode(&bytes).is_none(), "version {version}");
                }
            }
            refused(account().encode(), AccountRecord::decode);
            refused(keyring().encode(), KeyringRecord::decode);
            refused(session().encode(), SessionRecord::decode);
            refused(usage().encode(), AccountUsage::decode);
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
