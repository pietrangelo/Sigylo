//! Where the accounts live in their own Durable Object's ordered key-value
//! store, laid out like the custody vault's keys ([`super::keys`]): one
//! ASCII letter, then lowercase hex, times as fixed-width hex so a prefix
//! lists in time order.
//!
//! | key                                | value                       |
//! |------------------------------------|-----------------------------|
//! | `a` account                        | [`AccountRecord`]           |
//! | `k` account                        | [`KeyringRecord`]           |
//! | `s` session digest                 | [`SessionRecord`]           |
//! | `m` account expiry session digest  | empty: an account's sessions, by expiry |
//! | `e` expiry session digest          | empty: expiry index         |
//! | `w`                                | [`AccountUsage`]            |
//!
//! The letters differ from the custody vault's, so a key never means both.
//!
//! [`AccountRecord`]: super::AccountRecord
//! [`KeyringRecord`]: super::KeyringRecord
//! [`SessionRecord`]: super::SessionRecord
//! [`AccountUsage`]: super::AccountUsage

use access::{AccountId, SessionDigest, UnixTime};

use super::keys::{keyed, parse_hex, push_hex, push_time};

const TIME_HEX: usize = 16;
const ID_HEX: usize = 2 * AccountId::LEN;

fn push_at(key: &mut String, at: UnixTime) {
    push_time(key, custody::UnixTime(at.0));
}

fn parse_at(text: &str) -> Option<UnixTime> {
    Some(UnixTime(i64::try_from(u64::from_be_bytes(parse_hex::<8>(text)?)).ok()?))
}

fn hex_keyed(tag: char, bytes: &[u8; 32]) -> String {
    let mut key = keyed(tag, ID_HEX);
    push_hex(&mut key, bytes);
    key
}

pub fn account(account: &AccountId) -> String {
    hex_keyed('a', account.as_bytes())
}

pub fn keyring(account: &AccountId) -> String {
    hex_keyed('k', account.as_bytes())
}

pub fn session(digest: &SessionDigest) -> String {
    hex_keyed('s', digest.as_bytes())
}

pub fn member_session(account: &AccountId, expires_at: UnixTime, digest: &SessionDigest) -> String {
    let mut key = keyed('m', ID_HEX + TIME_HEX + ID_HEX);
    push_hex(&mut key, account.as_bytes());
    push_at(&mut key, expires_at);
    push_hex(&mut key, digest.as_bytes());
    key
}

/// The range `start <= key < end` that holds exactly one account's
/// sessions, earliest expiry first, then lowest digest.
pub fn sessions_of(account: &AccountId) -> (String, String) {
    let start = hex_keyed('m', account.as_bytes());
    // `g` sorts after every hex digit.
    let end = format!("{start}g");
    (start, end)
}

/// Reads an account's session entry back.
pub fn parse_member_session(key: &str) -> Option<(AccountId, UnixTime, SessionDigest)> {
    let rest = key.strip_prefix('m')?;
    if rest.len() != ID_HEX + TIME_HEX + ID_HEX || !rest.is_ascii() {
        return None;
    }
    let account = AccountId::from_array(parse_hex(&rest[..ID_HEX])?);
    let at = parse_at(&rest[ID_HEX..ID_HEX + TIME_HEX])?;
    let digest = SessionDigest::from_array(parse_hex(&rest[ID_HEX + TIME_HEX..])?);
    Some((account, at, digest))
}

/// Prefix of every session expiry index entry.
pub const SESSION_EXPIRY: &str = "e";

pub fn session_expiry(expires_at: UnixTime, digest: &SessionDigest) -> String {
    let mut key = keyed('e', TIME_HEX + ID_HEX);
    push_at(&mut key, expires_at);
    push_hex(&mut key, digest.as_bytes());
    key
}

/// The first session expiry key after every session that expired at or
/// before `now` (a session is dead at its expiry second).
pub fn session_expiry_bound(now: UnixTime) -> String {
    let mut key = keyed('e', TIME_HEX);
    push_at(&mut key, UnixTime(now.0.saturating_add(1)));
    key
}

/// Reads a session expiry index key back.
pub fn parse_session_expiry(key: &str) -> Option<(UnixTime, SessionDigest)> {
    let rest = key.strip_prefix('e')?;
    if rest.len() != TIME_HEX + ID_HEX || !rest.is_ascii() {
        return None;
    }
    let at = parse_at(&rest[..TIME_HEX])?;
    Some((at, SessionDigest::from_array(parse_hex(&rest[TIME_HEX..])?)))
}

pub const ACCOUNT_USAGE: &str = "w";

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> AccountId {
        AccountId::from_array([n; 32])
    }

    fn digest(n: u8) -> SessionDigest {
        SessionDigest::from_array([n; 32])
    }

    #[test]
    fn keys_carry_the_random_bytes_in_lowercase_hex_and_read_back() {
        assert_eq!(account(&id(0xAB)), format!("a{}", "ab".repeat(32)));
        assert_eq!(keyring(&id(0x01)), format!("k{}", "01".repeat(32)));
        assert_eq!(session(&digest(0xF0)), format!("s{}", "f0".repeat(32)));
        let at = UnixTime(1_234_567);
        let member = member_session(&id(3), at, &digest(4));
        assert_eq!(member, format!("m{}{:016x}{}", "03".repeat(32), 1_234_567, "04".repeat(32)));
        assert_eq!(parse_member_session(&member), Some((id(3), at, digest(4))));
        let expiry = session_expiry(at, &digest(5));
        assert_eq!(expiry, format!("e{:016x}{}", 1_234_567, "05".repeat(32)));
        assert_eq!(parse_session_expiry(&expiry), Some((at, digest(5))));
    }

    #[test]
    fn time_keys_sort_in_time_order() {
        let times = [0, 1, 255, 256, 1_700_000_000, 1_700_000_001, i64::MAX];
        let expiries: Vec<String> = times.iter().map(|t| session_expiry(UnixTime(*t), &digest(9))).collect();
        assert!(expiries.windows(2).all(|w| w[0] < w[1]));
        let members: Vec<String> = times.iter().map(|t| member_session(&id(1), UnixTime(*t), &digest(9))).collect();
        assert!(members.windows(2).all(|w| w[0] < w[1]));
        // Same expiry: the lower digest first, which is the eviction order.
        assert!(member_session(&id(1), UnixTime(7), &digest(1)) < member_session(&id(1), UnixTime(7), &digest(2)));
    }

    #[test]
    fn sessions_of_an_account_bound_exactly_its_own_entries() {
        let (start, end) = sessions_of(&id(0x10));
        for (n, inside) in [(0x0F, false), (0x10, true), (0x11, false)] {
            for at in [0, 1_700_000_000, i64::MAX] {
                for d in [0x00, 0xFF] {
                    let key = member_session(&id(n), UnixTime(at), &digest(d));
                    assert_eq!(start <= key && key < end, inside, "{key}");
                }
            }
        }
        let mut lowest = [0x10; 32];
        lowest[31] = 0x0F;
        assert!(member_session(&AccountId::from_array(lowest), UnixTime(i64::MAX), &digest(0xFF)) < start);
    }

    #[test]
    fn the_purge_bound_splits_what_expired_from_what_did_not() {
        let now = UnixTime(1_000);
        assert!(session_expiry(now, &digest(0xFF)) < session_expiry_bound(now));
        assert!(session_expiry_bound(now) < session_expiry(UnixTime(1_001), &digest(0)));
        assert!(session_expiry(UnixTime(0), &digest(0)).starts_with(SESSION_EXPIRY));
        assert_eq!(session_expiry_bound(UnixTime(i64::MAX)), format!("e{}", "7fffffffffffffff"));
    }

    mod adversary {
        use super::*;

        #[test]
        fn malformed_index_keys_are_rejected() {
            let good = member_session(&id(1), UnixTime(5), &digest(2));
            for bad in [
                String::new(),
                "m".into(),
                good[..good.len() - 1].to_string(),
                format!("{good}0"),
                good.to_uppercase(),
                format!("e{}", &good[1..]),
                format!("m{}", "g".repeat(good.len() - 1)),
                format!("m{}8000000000000000{}", "01".repeat(32), "02".repeat(32)),
                format!("m{}0000000000000005{}é", "01".repeat(32), "02".repeat(31)),
            ] {
                assert_eq!(parse_member_session(&bad), None, "{bad}");
            }
            let good = session_expiry(UnixTime(5), &digest(2));
            for bad in [
                "e".into(),
                good[..good.len() - 1].to_string(),
                format!("{good}0"),
                good.to_uppercase(),
                format!("m{}", &good[1..]),
                format!("x{}", &good[1..]),
                format!("e8000000000000000{}", "02".repeat(32)),
                session(&digest(2)),
            ] {
                assert_eq!(parse_session_expiry(&bad), None, "{bad}");
            }
        }

        #[test]
        fn every_key_starts_with_one_of_the_accounts_letters() {
            let keys = [
                account(&id(1)),
                keyring(&id(1)),
                session(&digest(1)),
                member_session(&id(1), UnixTime(1), &digest(1)),
                session_expiry(UnixTime(1), &digest(1)),
                session_expiry_bound(UnixTime(1)),
                sessions_of(&id(1)).0,
                sessions_of(&id(1)).1,
                ACCOUNT_USAGE.to_string(),
                SESSION_EXPIRY.to_string(),
            ];
            for key in keys {
                assert!(matches!(key.as_bytes()[0], b'a' | b'k' | b's' | b'm' | b'e' | b'w'), "{key}");
                assert!(key.is_ascii() && !key.bytes().any(|b| b.is_ascii_uppercase()), "{key}");
            }
        }
    }
}
