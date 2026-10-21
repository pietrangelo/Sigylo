//! The calls the relay makes to the accounts object in its Durable Object,
//! and the replies, as bytes: one [`AccountCall`] per Access store method,
//! and one for the attempt counters. Strict like the custody vault's wire
//! ([`super::wire`]): a message decodes only if it is exactly what `encode`
//! writes, and every value goes through the Access constructors again.
//!
//! The tags (calls `0x41..=0x4C`, replies `0xC0..=0xC8`) are apart from the
//! custody vault's (calls 1 to 13, replies 0 to 10), so no message of one
//! kind ever decodes as the other's. No call lists, scans or ranges: each
//! names the one account, login or session it is about, and only the purge
//! names none, and hears back a count.

use core::fmt;

use access::{
    AccessError, AccountId, Keyring, KeyringSnapshot, KeyringVersion, KeyringWrite, LOGIN_WINDOW_SECONDS, LoginHandle,
    LoginState, RegistrationRecord, SESSION_SECONDS, SessionDigest, UnixTime,
};

use super::account_limits::{ATTEMPT_LIMIT_CEILING, Class};
use super::records::Reader;
use super::wire::Writer;

#[derive(Clone, PartialEq, Eq)]
pub enum AccountCall {
    Enroll {
        account: AccountId,
        record: RegistrationRecord,
    },
    Record {
        account: AccountId,
    },
    /// A login in progress for `lifetime` seconds (1 to
    /// [`LOGIN_WINDOW_SECONDS`]), under the shared budget (no bucket) or a
    /// device's (its bucket). Registrations park nothing.
    Park {
        handle: LoginHandle,
        account: AccountId,
        state: LoginState,
        lifetime: u32,
        bucket: Option<[u8; 32]>,
    },
    Take {
        handle: LoginHandle,
    },
    /// `lifetime` is 1 to [`SESSION_SECONDS`].
    OpenSession {
        digest: SessionDigest,
        account: AccountId,
        record: RegistrationRecord,
        lifetime: u32,
    },
    CloseSession {
        digest: SessionDigest,
    },
    CloseSessions {
        digest: SessionDigest,
    },
    Keyring {
        digest: SessionDigest,
    },
    StoreKeyring {
        digest: SessionDigest,
        keyring: Keyring,
        expected: KeyringVersion,
    },
    CloseAccount {
        digest: SessionDigest,
    },
    Purge,
    /// `limit` is 1 to [`ATTEMPT_LIMIT_CEILING`]; only the bucket reaches
    /// the object, never a pass.
    Admit {
        account: AccountId,
        bucket: [u8; 32],
        class: Class,
        limit: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountReply {
    Failed(AccessError),
    /// `enroll`, `close_sessions`, `close_account`, `admit`.
    Flag(bool),
    Record(Option<RegistrationRecord>),
    /// `park_login`, `close_session`.
    Done,
    Login(Option<(AccountId, LoginState)>),
    /// `open_session`.
    Expires(Option<UnixTime>),
    Keyring(Option<KeyringSnapshot>),
    /// `store_keyring`.
    Written(KeyringWrite),
    Purged(u64),
}

/// In the order [`AccessError`] declares them.
const ACCESS_ERRORS: [AccessError; 14] = [
    AccessError::InvalidUsername,
    AccessError::InvalidPassword,
    AccessError::MalformedMessage,
    AccessError::KeyringEmpty,
    AccessError::KeyringTooLarge,
    AccessError::AlreadyRegistered,
    AccessError::NotAuthentic,
    AccessError::Unauthorized,
    AccessError::Conflict,
    AccessError::Throttled,
    AccessError::StoreUnavailable,
    AccessError::StorageFull,
    AccessError::NotConfigured,
    AccessError::RandomnessUnavailable,
];

/// Where [`AccessError::StoreUnavailable`] sits in [`ACCESS_ERRORS`].
const STORE_UNAVAILABLE: u8 = 10;

fn class_code(class: Class) -> u8 {
    match class {
        Class::Login => 0,
        Class::Registration => 1,
        Class::Device => 2,
    }
}

/// `n` if it is 1 to `max`.
fn within<T: PartialOrd + From<u8>>(n: T, max: T) -> Option<T> {
    (n >= T::from(1) && n <= max).then_some(n)
}

impl Writer {
    fn snapshot(&mut self, snapshot: &KeyringSnapshot) -> &mut Self {
        // No keyring is a length of 0, which no keyring has.
        let ring = snapshot.keyring.as_ref().map_or(&[][..], Keyring::as_bytes);
        self.bytes(&snapshot.version.0.to_be_bytes()).sized(ring)
    }
}

impl Reader<'_> {
    fn account_id(&mut self) -> Option<AccountId> {
        Some(AccountId::from_array(self.array()?))
    }

    fn session_digest(&mut self) -> Option<SessionDigest> {
        Some(SessionDigest::from_array(self.array()?))
    }

    fn login_handle(&mut self) -> Option<LoginHandle> {
        LoginHandle::from_slice(self.take(LoginHandle::LEN)?).ok()
    }

    fn login_state(&mut self) -> Option<LoginState> {
        LoginState::from_slice(self.take(LoginState::LEN)?).ok()
    }

    fn registration_record(&mut self) -> Option<RegistrationRecord> {
        RegistrationRecord::from_slice(self.take(RegistrationRecord::LEN)?).ok()
    }

    fn keyring(&mut self) -> Option<Keyring> {
        Keyring::new(self.sized()?.to_vec()).ok()
    }

    fn class(&mut self) -> Option<Class> {
        match self.byte()? {
            0 => Some(Class::Login),
            1 => Some(Class::Registration),
            2 => Some(Class::Device),
            _ => None,
        }
    }

    /// A keyring and its version: none at version 0 and only there.
    fn snapshot(&mut self) -> Option<KeyringSnapshot> {
        let version = KeyringVersion(self.u64()?);
        let ring = self.sized()?;
        let keyring = if ring.is_empty() { None } else { Some(Keyring::new(ring.to_vec()).ok()?) };
        ((version == KeyringVersion::NONE) == keyring.is_none()).then_some(KeyringSnapshot { keyring, version })
    }
}

impl AccountCall {
    pub fn encode(&self) -> Vec<u8> {
        let mut w;
        match self {
            Self::Enroll { account, record } => {
                w = Writer::new(0x41);
                w.bytes(account.as_bytes()).bytes(record.as_bytes());
            }
            Self::Record { account } => {
                w = Writer::new(0x42);
                w.bytes(account.as_bytes());
            }
            Self::Park { handle, account, state, lifetime, bucket } => {
                w = Writer::new(0x43);
                w.bytes(handle.expose()).bytes(account.as_bytes()).bytes(state.expose()).u32(*lifetime);
                match bucket {
                    None => w.byte(class_code(Class::Login)),
                    Some(bucket) => w.byte(class_code(Class::Device)).bytes(bucket),
                };
            }
            Self::Take { handle } => {
                w = Writer::new(0x44);
                w.bytes(handle.expose());
            }
            Self::OpenSession { digest, account, record, lifetime } => {
                w = Writer::new(0x45);
                w.bytes(digest.as_bytes()).bytes(account.as_bytes()).bytes(record.as_bytes()).u32(*lifetime);
            }
            Self::CloseSession { digest } => {
                w = Writer::new(0x46);
                w.bytes(digest.as_bytes());
            }
            Self::CloseSessions { digest } => {
                w = Writer::new(0x47);
                w.bytes(digest.as_bytes());
            }
            Self::Keyring { digest } => {
                w = Writer::new(0x48);
                w.bytes(digest.as_bytes());
            }
            Self::StoreKeyring { digest, keyring, expected } => {
                w = Writer::new(0x49);
                w.bytes(digest.as_bytes()).sized(keyring.as_bytes()).bytes(&expected.0.to_be_bytes());
            }
            Self::CloseAccount { digest } => {
                w = Writer::new(0x4A);
                w.bytes(digest.as_bytes());
            }
            Self::Purge => w = Writer::new(0x4B),
            Self::Admit { account, bucket, class, limit } => {
                w = Writer::new(0x4C);
                w.bytes(account.as_bytes()).bytes(bucket).byte(class_code(*class)).u16(*limit);
            }
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        let call = match r.byte()? {
            0x41 => Self::Enroll { account: r.account_id()?, record: r.registration_record()? },
            0x42 => Self::Record { account: r.account_id()? },
            0x43 => {
                let (handle, account, state) = (r.login_handle()?, r.account_id()?, r.login_state()?);
                let lifetime = within(r.u32()?, LOGIN_WINDOW_SECONDS)?;
                let bucket = match r.class()? {
                    Class::Login => None,
                    Class::Device => Some(r.array()?),
                    Class::Registration => return None,
                };
                Self::Park { handle, account, state, lifetime, bucket }
            }
            0x44 => Self::Take { handle: r.login_handle()? },
            0x45 => Self::OpenSession {
                digest: r.session_digest()?,
                account: r.account_id()?,
                record: r.registration_record()?,
                lifetime: within(r.u32()?, SESSION_SECONDS)?,
            },
            0x46 => Self::CloseSession { digest: r.session_digest()? },
            0x47 => Self::CloseSessions { digest: r.session_digest()? },
            0x48 => Self::Keyring { digest: r.session_digest()? },
            0x49 => Self::StoreKeyring {
                digest: r.session_digest()?,
                keyring: r.keyring()?,
                expected: KeyringVersion(r.u64()?),
            },
            0x4A => Self::CloseAccount { digest: r.session_digest()? },
            0x4B => Self::Purge,
            0x4C => Self::Admit {
                account: r.account_id()?,
                bucket: r.array()?,
                class: r.class()?,
                limit: within(r.u16()?, ATTEMPT_LIMIT_CEILING)?,
            },
            _ => return None,
        };
        r.end()?;
        Some(call)
    }
}

impl fmt::Debug for AccountCall {
    // The call and its numbers only: never a login state, a record, a
    // keyring's bytes, a handle, a digest or a bucket.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enroll { .. } => f.debug_struct("Enroll").finish_non_exhaustive(),
            Self::Record { .. } => f.debug_struct("Record").finish_non_exhaustive(),
            Self::Park { lifetime, bucket, .. } => f
                .debug_struct("Park")
                .field("lifetime", lifetime)
                .field("device", &bucket.is_some())
                .finish_non_exhaustive(),
            Self::Take { .. } => f.debug_struct("Take").finish_non_exhaustive(),
            Self::OpenSession { lifetime, .. } => {
                f.debug_struct("OpenSession").field("lifetime", lifetime).finish_non_exhaustive()
            }
            Self::CloseSession { .. } => f.debug_struct("CloseSession").finish_non_exhaustive(),
            Self::CloseSessions { .. } => f.debug_struct("CloseSessions").finish_non_exhaustive(),
            Self::Keyring { .. } => f.debug_struct("Keyring").finish_non_exhaustive(),
            Self::StoreKeyring { keyring, expected, .. } => f
                .debug_struct("StoreKeyring")
                .field("keyring", keyring)
                .field("expected", expected)
                .finish_non_exhaustive(),
            Self::CloseAccount { .. } => f.debug_struct("CloseAccount").finish_non_exhaustive(),
            Self::Purge => f.write_str("Purge"),
            Self::Admit { class, limit, .. } => {
                f.debug_struct("Admit").field("class", class).field("limit", limit).finish_non_exhaustive()
            }
        }
    }
}

impl AccountReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut w;
        match self {
            Self::Failed(error) => {
                w = Writer::new(0xC0);
                let index = ACCESS_ERRORS.iter().position(|e| e == error).map_or(STORE_UNAVAILABLE, |i| i as u8);
                w.byte(index);
            }
            Self::Flag(flag) => {
                w = Writer::new(0xC1);
                w.flag(*flag);
            }
            Self::Record(record) => {
                w = Writer::new(0xC2);
                w.flag(record.is_some());
                if let Some(record) = record {
                    w.bytes(record.as_bytes());
                }
            }
            Self::Done => w = Writer::new(0xC3),
            Self::Login(login) => {
                w = Writer::new(0xC4);
                w.flag(login.is_some());
                if let Some((account, state)) = login {
                    w.bytes(account.as_bytes()).bytes(state.expose());
                }
            }
            Self::Expires(at) => {
                w = Writer::new(0xC5);
                w.flag(at.is_some());
                if let Some(at) = at {
                    w.i64(at.0);
                }
            }
            Self::Keyring(snapshot) => {
                w = Writer::new(0xC6);
                w.flag(snapshot.is_some());
                if let Some(snapshot) = snapshot {
                    w.snapshot(snapshot);
                }
            }
            Self::Written(write) => {
                w = Writer::new(0xC7);
                match write {
                    KeyringWrite::Stored(version) => w.byte(0).bytes(&version.0.to_be_bytes()),
                    KeyringWrite::Stale => w.byte(1),
                    KeyringWrite::Unauthorized => w.byte(2),
                };
            }
            Self::Purged(n) => {
                w = Writer::new(0xC8);
                w.bytes(&n.to_be_bytes());
            }
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        let reply = match r.byte()? {
            0xC0 => Self::Failed(*ACCESS_ERRORS.get(usize::from(r.byte()?))?),
            0xC1 => Self::Flag(r.flag()?),
            0xC2 => Self::Record(if r.flag()? { Some(r.registration_record()?) } else { None }),
            0xC3 => Self::Done,
            0xC4 => Self::Login(if r.flag()? { Some((r.account_id()?, r.login_state()?)) } else { None }),
            0xC5 => Self::Expires(if r.flag()? { Some(UnixTime(r.i64()?)) } else { None }),
            0xC6 => Self::Keyring(if r.flag()? { Some(r.snapshot()?) } else { None }),
            0xC7 => Self::Written(match r.byte()? {
                // A write that stored is at version 1 or more.
                0 => KeyringWrite::Stored(KeyringVersion(within(r.u64()?, u64::MAX)?)),
                1 => KeyringWrite::Stale,
                2 => KeyringWrite::Unauthorized,
                _ => return None,
            }),
            0xC8 => Self::Purged(r.u64()?),
            _ => return None,
        };
        r.end()?;
        Some(reply)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use access::MAX_KEYRING_LEN;

    use super::*;
    use crate::core::{Call, Reply};

    fn account(n: u8) -> AccountId {
        AccountId::from_array([n; 32])
    }

    fn digest(n: u8) -> SessionDigest {
        SessionDigest::from_array([n; 32])
    }

    fn handle(n: u8) -> LoginHandle {
        LoginHandle::from_array([n; 16])
    }

    fn record(n: u8) -> RegistrationRecord {
        RegistrationRecord::from_slice(&[n; RegistrationRecord::LEN]).unwrap()
    }

    fn state(n: u8) -> LoginState {
        LoginState::from_slice(&[n; LoginState::LEN]).unwrap()
    }

    fn ring(len: usize, n: u8) -> Keyring {
        Keyring::new(vec![n; len]).unwrap()
    }

    fn calls() -> Vec<AccountCall> {
        vec![
            AccountCall::Enroll { account: account(1), record: record(2) },
            AccountCall::Record { account: account(1) },
            AccountCall::Park {
                handle: handle(3),
                account: account(1),
                state: state(4),
                lifetime: LOGIN_WINDOW_SECONDS,
                bucket: None,
            },
            AccountCall::Park {
                handle: handle(3),
                account: account(1),
                state: state(4),
                lifetime: 1,
                bucket: Some([5; 32]),
            },
            AccountCall::Take { handle: handle(3) },
            AccountCall::OpenSession {
                digest: digest(6),
                account: account(1),
                record: record(2),
                lifetime: SESSION_SECONDS,
            },
            AccountCall::OpenSession { digest: digest(6), account: account(1), record: record(2), lifetime: 1 },
            AccountCall::CloseSession { digest: digest(6) },
            AccountCall::CloseSessions { digest: digest(6) },
            AccountCall::Keyring { digest: digest(6) },
            AccountCall::StoreKeyring {
                digest: digest(6),
                keyring: ring(MAX_KEYRING_LEN, 7),
                expected: KeyringVersion::NONE,
            },
            AccountCall::StoreKeyring { digest: digest(6), keyring: ring(1, 7), expected: KeyringVersion(u64::MAX) },
            AccountCall::CloseAccount { digest: digest(6) },
            AccountCall::Purge,
            AccountCall::Admit { account: account(1), bucket: [8; 32], class: Class::Login, limit: 1 },
            AccountCall::Admit { account: account(1), bucket: [8; 32], class: Class::Registration, limit: 10 },
            AccountCall::Admit {
                account: account(1),
                bucket: [8; 32],
                class: Class::Device,
                limit: ATTEMPT_LIMIT_CEILING,
            },
        ]
    }

    fn replies() -> Vec<AccountReply> {
        let mut replies: Vec<AccountReply> = ACCESS_ERRORS.iter().map(|e| AccountReply::Failed(*e)).collect();
        replies.extend([
            AccountReply::Flag(true),
            AccountReply::Flag(false),
            AccountReply::Record(None),
            AccountReply::Record(Some(record(2))),
            AccountReply::Done,
            AccountReply::Login(None),
            AccountReply::Login(Some((account(1), state(4)))),
            AccountReply::Expires(None),
            AccountReply::Expires(Some(UnixTime(1_800_043_200))),
            AccountReply::Keyring(None),
            AccountReply::Keyring(Some(KeyringSnapshot { keyring: None, version: KeyringVersion::NONE })),
            AccountReply::Keyring(Some(KeyringSnapshot {
                keyring: Some(ring(MAX_KEYRING_LEN, 7)),
                version: KeyringVersion(u64::MAX),
            })),
            AccountReply::Written(KeyringWrite::Stored(KeyringVersion(1))),
            AccountReply::Written(KeyringWrite::Stale),
            AccountReply::Written(KeyringWrite::Unauthorized),
            AccountReply::Purged(u64::MAX),
        ]);
        replies
    }

    #[test]
    fn every_call_and_reply_round_trips_under_its_own_tags() {
        for call in calls() {
            assert_eq!(AccountCall::decode(&call.encode()), Some(call.clone()), "{call:?}");
        }
        for reply in replies() {
            assert_eq!(AccountReply::decode(&reply.encode()), Some(reply.clone()), "{reply:?}");
        }
        let tags: BTreeSet<u8> = calls().iter().map(|c| c.encode()[0]).collect();
        assert_eq!(tags, (0x41..=0x4C).collect());
        let tags: BTreeSet<u8> = replies().iter().map(|r| r.encode()[0]).collect();
        assert_eq!(tags, (0xC0..=0xC8).collect());
    }

    #[test]
    fn every_access_error_travels_as_its_place_in_the_enum() {
        // Fails to build when a variant is added, so the table follows.
        fn place(error: AccessError) -> u8 {
            match error {
                AccessError::InvalidUsername => 0,
                AccessError::InvalidPassword => 1,
                AccessError::MalformedMessage => 2,
                AccessError::KeyringEmpty => 3,
                AccessError::KeyringTooLarge => 4,
                AccessError::AlreadyRegistered => 5,
                AccessError::NotAuthentic => 6,
                AccessError::Unauthorized => 7,
                AccessError::Conflict => 8,
                AccessError::Throttled => 9,
                AccessError::StoreUnavailable => 10,
                AccessError::StorageFull => 11,
                AccessError::NotConfigured => 12,
                AccessError::RandomnessUnavailable => 13,
            }
        }
        for (i, error) in ACCESS_ERRORS.iter().enumerate() {
            assert_eq!(usize::from(place(*error)), i, "{error:?}");
            let bytes = AccountReply::Failed(*error).encode();
            assert_eq!(bytes, [0xC0, place(*error)]);
            assert_eq!(AccountReply::decode(&bytes), Some(AccountReply::Failed(*error)));
        }
        assert_eq!(ACCESS_ERRORS[usize::from(STORE_UNAVAILABLE)], AccessError::StoreUnavailable);
    }

    mod adversary {
        use super::*;

        #[test]
        fn every_truncation_and_every_extra_byte_is_refused() {
            for bytes in calls().iter().map(AccountCall::encode) {
                for cut in 0..bytes.len() {
                    assert_eq!(AccountCall::decode(&bytes[..cut]), None);
                }
                assert_eq!(AccountCall::decode(&[bytes.as_slice(), &[0]].concat()), None);
            }
            for bytes in replies().iter().map(AccountReply::encode) {
                for cut in 0..bytes.len() {
                    assert_eq!(AccountReply::decode(&bytes[..cut]), None);
                }
                assert_eq!(AccountReply::decode(&[bytes.as_slice(), &[0]].concat()), None);
            }
        }

        #[test]
        fn a_flipped_bit_is_refused_or_reads_back_as_exactly_those_bytes() {
            // Not a checksum (the wire is the platform's), but canonical:
            // whatever decodes encodes to the very bytes it came from.
            for bytes in calls().iter().map(AccountCall::encode) {
                for bit in 0..bytes.len().min(300) * 8 {
                    let mut flipped = bytes.clone();
                    flipped[bit / 8] ^= 1 << (bit % 8);
                    if let Some(call) = AccountCall::decode(&flipped) {
                        assert_eq!(call.encode(), flipped, "{call:?}");
                    }
                }
            }
            for bytes in replies().iter().map(AccountReply::encode) {
                for bit in 0..bytes.len().min(300) * 8 {
                    let mut flipped = bytes.clone();
                    flipped[bit / 8] ^= 1 << (bit % 8);
                    if let Some(reply) = AccountReply::decode(&flipped) {
                        assert_eq!(reply.encode(), flipped, "{reply:?}");
                    }
                }
            }
        }

        #[test]
        fn unknown_tags_and_values_outside_their_range_are_refused() {
            for tag in [0x00, 0x01, 0x0D, 0x40, 0x4D, 0xBF, 0xC0, 0xFF] {
                assert_eq!(AccountCall::decode(&[tag]), None, "{tag:#x}");
            }
            for tag in [0x00, 0x0A, 0x41, 0xBF, 0xC9, 0xFF] {
                assert_eq!(AccountReply::decode(&[tag]), None, "{tag:#x}");
            }
            assert_eq!(AccountReply::decode(&[0xC0, 14]), None);
            // A boolean that is neither 0 nor 1.
            assert_eq!(AccountReply::decode(&[0xC1, 2]), None);
            assert_eq!(AccountReply::decode(&[0xC5, 2]), None);
            let park = |lifetime: u32, class: u8| {
                let mut bytes = AccountCall::Park {
                    handle: handle(3),
                    account: account(1),
                    state: state(4),
                    lifetime: 1,
                    bucket: Some([5; 32]),
                }
                .encode();
                let at = 1 + 16 + 32 + LoginState::LEN;
                bytes[at..at + 4].copy_from_slice(&lifetime.to_be_bytes());
                bytes[at + 4] = class;
                AccountCall::decode(&bytes)
            };
            assert!(park(LOGIN_WINDOW_SECONDS, 2).is_some());
            // A login for no time or past the window, under a registration
            // budget or no class at all.
            assert_eq!(park(0, 2), None);
            assert_eq!(park(LOGIN_WINDOW_SECONDS + 1, 2), None);
            assert_eq!(park(1, 1), None);
            assert_eq!(park(1, 3), None);
            let open = |lifetime: u32| {
                let mut bytes =
                    AccountCall::OpenSession { digest: digest(6), account: account(1), record: record(2), lifetime: 1 }
                        .encode();
                let at = bytes.len() - 4;
                bytes[at..].copy_from_slice(&lifetime.to_be_bytes());
                AccountCall::decode(&bytes)
            };
            assert!(open(SESSION_SECONDS).is_some());
            assert_eq!(open(0), None);
            assert_eq!(open(SESSION_SECONDS + 1), None);
            let admit = |class: u8, limit: u16| {
                let mut bytes =
                    AccountCall::Admit { account: account(1), bucket: [8; 32], class: Class::Login, limit: 1 }.encode();
                bytes[65] = class;
                bytes[66..].copy_from_slice(&limit.to_be_bytes());
                AccountCall::decode(&bytes)
            };
            assert!(admit(2, ATTEMPT_LIMIT_CEILING).is_some());
            assert_eq!(admit(3, 1), None);
            assert_eq!(admit(0, 0), None);
            assert_eq!(admit(0, ATTEMPT_LIMIT_CEILING + 1), None);
            // A keyring that is empty or too large.
            let mut store =
                AccountCall::StoreKeyring { digest: digest(6), keyring: ring(1, 7), expected: KeyringVersion(1) }
                    .encode();
            store[33..37].copy_from_slice(&0u32.to_be_bytes());
            store.remove(37);
            assert_eq!(AccountCall::decode(&store), None);
            let mut store = AccountCall::StoreKeyring {
                digest: digest(6),
                keyring: ring(MAX_KEYRING_LEN, 7),
                expected: KeyringVersion(1),
            }
            .encode();
            store[33..37].copy_from_slice(&(MAX_KEYRING_LEN as u32 + 1).to_be_bytes());
            store.insert(37, 7);
            assert_eq!(AccountCall::decode(&store), None);
            // A stored write at version 0; a write that is none of the three.
            assert_eq!(AccountReply::decode(&[[0xC7, 0].as_slice(), &0u64.to_be_bytes()].concat()), None);
            assert_eq!(AccountReply::decode(&[0xC7, 3]), None);
            // A keyring at version 0, and a version with no keyring.
            let snapshot = |version: u64, ring: &[u8]| {
                let mut bytes = vec![0xC6, 1];
                bytes.extend_from_slice(&version.to_be_bytes());
                bytes.extend_from_slice(&(ring.len() as u32).to_be_bytes());
                bytes.extend_from_slice(ring);
                AccountReply::decode(&bytes)
            };
            assert!(snapshot(0, &[]).is_some() && snapshot(1, &[7]).is_some());
            assert_eq!(snapshot(0, &[7]), None);
            assert_eq!(snapshot(1, &[]), None);
        }

        #[test]
        fn a_length_prefix_that_lies_is_refused() {
            let store =
                AccountCall::StoreKeyring { digest: digest(6), keyring: ring(10, 7), expected: KeyringVersion(1) };
            let reply =
                AccountReply::Keyring(Some(KeyringSnapshot { keyring: Some(ring(10, 7)), version: KeyringVersion(1) }));
            for (bytes, at, decodes) in [
                (store.encode(), 33, (|b: &[u8]| AccountCall::decode(b).is_some()) as fn(&[u8]) -> bool),
                (reply.encode(), 10, |b: &[u8]| AccountReply::decode(b).is_some()),
            ] {
                assert!(decodes(&bytes));
                for len in [9u32, 11, u32::MAX] {
                    let mut lying = bytes.clone();
                    lying[at..at + 4].copy_from_slice(&len.to_be_bytes());
                    assert!(!decodes(&lying), "{len}");
                }
            }
        }

        #[test]
        fn no_account_message_reads_as_a_custody_one_or_the_other_way_round() {
            let custody_calls = crate::core::wire::tests::calls();
            let custody_replies = crate::core::wire::tests::replies();
            for bytes in calls().iter().map(AccountCall::encode) {
                assert_eq!(Call::decode(&bytes), None);
                assert_eq!(Reply::decode(&bytes), None);
                assert_eq!(AccountReply::decode(&bytes), None);
            }
            for bytes in replies().iter().map(AccountReply::encode) {
                assert_eq!(Call::decode(&bytes), None);
                assert_eq!(Reply::decode(&bytes), None);
                assert_eq!(AccountCall::decode(&bytes), None);
            }
            for bytes in custody_calls.iter().map(Call::encode).chain(custody_replies.iter().map(Reply::encode)) {
                assert_eq!(AccountCall::decode(&bytes), None);
                assert_eq!(AccountReply::decode(&bytes), None);
            }
            // An older vault's fault is never an account's answer.
            assert_eq!(AccountReply::decode(&Reply::Failed(custody::CustodyError::VaultUnavailable).encode()), None);
        }

        #[test]
        fn debug_never_shows_a_state_a_record_a_keyring_a_digest_or_a_bucket() {
            let secrets = [
                AccountCall::Enroll { account: account(0xA1), record: record(0xA2) },
                AccountCall::Park {
                    handle: handle(0xA3),
                    account: account(0xA1),
                    state: state(0xA4),
                    lifetime: 300,
                    bucket: Some([0xA5; 32]),
                },
                AccountCall::Take { handle: handle(0xA3) },
                AccountCall::OpenSession {
                    digest: digest(0xA6),
                    account: account(0xA1),
                    record: record(0xA2),
                    lifetime: 300,
                },
                AccountCall::StoreKeyring {
                    digest: digest(0xA6),
                    keyring: ring(64, 0xA7),
                    expected: KeyringVersion(2),
                },
                AccountCall::Admit { account: account(0xA1), bucket: [0xA5; 32], class: Class::Device, limit: 10 },
            ];
            let replies = [
                AccountReply::Record(Some(record(0xA2))),
                AccountReply::Login(Some((account(0xA1), state(0xA4)))),
                AccountReply::Keyring(Some(KeyringSnapshot {
                    keyring: Some(ring(64, 0xA7)),
                    version: KeyringVersion(2),
                })),
            ];
            let rendered: Vec<String> =
                secrets.iter().map(|c| format!("{c:?}")).chain(replies.iter().map(|r| format!("{r:?}"))).collect();
            for text in &rendered {
                for byte in [0xA2u8, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7] {
                    let hex = format!("{byte:02x}{byte:02x}");
                    assert!(!text.to_lowercase().contains(&hex), "{text}");
                    assert!(!text.contains(&format!("{byte}, {byte}")), "{text}");
                }
            }
        }

        #[test]
        fn every_call_names_the_one_thing_it_is_about_and_none_lists() {
            // Fails to build when a call is added: say what it names.
            fn names(call: &AccountCall) -> Option<&[u8]> {
                match call {
                    AccountCall::Enroll { account, .. }
                    | AccountCall::Record { account }
                    | AccountCall::Admit { account, .. } => Some(account.as_bytes()),
                    AccountCall::Park { handle, .. } | AccountCall::Take { handle } => Some(handle.expose()),
                    AccountCall::OpenSession { digest, .. }
                    | AccountCall::CloseSession { digest }
                    | AccountCall::CloseSessions { digest }
                    | AccountCall::Keyring { digest }
                    | AccountCall::StoreKeyring { digest, .. }
                    | AccountCall::CloseAccount { digest } => Some(digest.as_bytes()),
                    AccountCall::Purge => None,
                }
            }
            // Fails to build when a reply is added: say how much it carries.
            fn records(reply: &AccountReply) -> usize {
                match reply {
                    AccountReply::Failed(_)
                    | AccountReply::Flag(_)
                    | AccountReply::Done
                    | AccountReply::Expires(_)
                    | AccountReply::Written(_)
                    | AccountReply::Purged(_) => 0,
                    AccountReply::Record(found) => usize::from(found.is_some()),
                    AccountReply::Login(found) => usize::from(found.is_some()),
                    AccountReply::Keyring(found) => usize::from(found.is_some()),
                }
            }
            for call in calls() {
                let named = names(&call);
                assert_eq!(named.is_none(), call == AccountCall::Purge, "{call:?}");
                if let Some(key) = named {
                    let bytes = call.encode();
                    assert!(bytes.windows(key.len()).any(|w| w == key), "{call:?} carries its key");
                }
            }
            assert!(replies().iter().all(|r| records(r) <= 1));
        }
    }
}
