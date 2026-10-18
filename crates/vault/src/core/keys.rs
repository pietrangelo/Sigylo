//! Where each record lives in the ordered key-value store.
//!
//! Keys are short ASCII strings whose byte order is the order the vault
//! needs: times are fixed-width hex, so listing a prefix walks them in time
//! order (expiry, garbage due). Ids and object names are lowercase hex, so a
//! key says nothing more than the random bytes it carries.
//!
//! | key                         | value                     |
//! |-----------------------------|---------------------------|
//! | `d` id                      | [`DepositRecord`]         |
//! | `r` id                      | [`RequestRecord`]         |
//! | `x` expiry `d`/`r` id       | empty: expiry index       |
//! | `g` due object              | empty: garbage, by due    |
//! | `o` object                  | [`GarbageEntry`]          |
//! | `u`                         | [`Usage`]                 |
//!
//! [`DepositRecord`]: super::DepositRecord
//! [`RequestRecord`]: super::RequestRecord
//! [`GarbageEntry`]: super::GarbageEntry
//! [`Usage`]: super::Usage

use custody::{DropId, ObjectName, UnixTime};

/// What kind of record an expiry index entry points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Deposit,
    Request,
}

impl Kind {
    fn tag(self) -> char {
        match self {
            Self::Deposit => 'd',
            Self::Request => 'r',
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(key: &mut String, bytes: &[u8]) {
    for byte in bytes {
        key.push(char::from(HEX[usize::from(byte >> 4)]));
        key.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
}

/// Times before the epoch never occur; they sort first rather than wrap.
fn push_time(key: &mut String, at: UnixTime) {
    push_hex(key, &u64::try_from(at.0).unwrap_or(0).to_be_bytes());
}

fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != 2 * N {
        return None;
    }
    let nibble = |d: u8| match d {
        b'0'..=b'9' => Some(d - b'0'),
        b'a'..=b'f' => Some(d - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, [high, low]) in digits.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Some(out)
}

fn keyed(tag: char, capacity: usize) -> String {
    let mut key = String::with_capacity(1 + capacity);
    key.push(tag);
    key
}

pub fn deposit(id: &DropId) -> String {
    let mut key = keyed('d', 32);
    push_hex(&mut key, id.as_bytes());
    key
}

pub fn request(id: &DropId) -> String {
    let mut key = keyed('r', 32);
    push_hex(&mut key, id.as_bytes());
    key
}

/// Prefix of every expiry index entry.
pub const EXPIRY: &str = "x";

pub fn expiry(at: UnixTime, kind: Kind, id: &DropId) -> String {
    let mut key = keyed('x', 16 + 1 + 32);
    push_time(&mut key, at);
    key.push(kind.tag());
    push_hex(&mut key, id.as_bytes());
    key
}

/// The first expiry key after everything that expired at or before `now`.
pub fn expiry_bound(now: UnixTime) -> String {
    let mut key = keyed('x', 17);
    push_time(&mut key, UnixTime(now.0.saturating_add(1)));
    key
}

/// Reads an expiry index key back.
pub fn parse_expiry(key: &str) -> Option<(UnixTime, Kind, DropId)> {
    let rest = key.strip_prefix('x')?;
    if rest.len() != 16 + 1 + 32 || !rest.is_ascii() {
        return None;
    }
    let at = i64::try_from(u64::from_be_bytes(parse_hex::<8>(&rest[..16])?)).ok()?;
    let kind = match &rest[16..17] {
        "d" => Kind::Deposit,
        "r" => Kind::Request,
        _ => return None,
    };
    let id = DropId::from_slice(&parse_hex::<{ DropId::LEN }>(&rest[17..])?).ok()?;
    Some((UnixTime(at), kind, id))
}

/// Prefix of every garbage entry in due order.
pub const GARBAGE: &str = "g";

pub fn garbage(due: UnixTime, object: &ObjectName) -> String {
    let mut key = keyed('g', 16 + 32);
    push_time(&mut key, due);
    push_hex(&mut key, object.as_bytes());
    key
}

/// The first garbage key after everything due at or before `now`.
pub fn garbage_bound(now: UnixTime) -> String {
    let mut key = keyed('g', 16);
    push_time(&mut key, UnixTime(now.0.saturating_add(1)));
    key
}

/// Reads a garbage key back.
pub fn parse_garbage(key: &str) -> Option<(UnixTime, ObjectName)> {
    let rest = key.strip_prefix('g')?;
    if rest.len() != 16 + 32 || !rest.is_ascii() {
        return None;
    }
    let due = i64::try_from(u64::from_be_bytes(parse_hex::<8>(&rest[..16])?)).ok()?;
    Some((UnixTime(due), ObjectName::from_array(parse_hex(&rest[16..])?)))
}

pub fn object(object: &ObjectName) -> String {
    let mut key = keyed('o', 32);
    push_hex(&mut key, object.as_bytes());
    key
}

pub const USAGE: &str = "u";

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> DropId {
        DropId::from_slice(&[n; DropId::LEN]).unwrap()
    }

    #[test]
    fn keys_carry_the_random_bytes_in_lowercase_hex_and_nothing_else() {
        assert_eq!(deposit(&id(0xAB)), format!("d{}", "ab".repeat(16)));
        assert_eq!(request(&id(0x01)), format!("r{}", "01".repeat(16)));
        assert_eq!(object(&ObjectName::from_array([0xF0; 16])), format!("o{}", "f0".repeat(16)));
    }

    #[test]
    fn time_keys_sort_in_time_order() {
        let times = [0, 1, 255, 256, 1_700_000_000, 1_700_000_001, i64::MAX];
        let keys: Vec<String> = times.iter().map(|t| expiry(UnixTime(*t), Kind::Deposit, &id(9))).collect();
        assert!(keys.windows(2).all(|w| w[0] < w[1]));
        let due: Vec<String> = times.iter().map(|t| garbage(UnixTime(*t), &ObjectName::from_array([0; 16]))).collect();
        assert!(due.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn bounds_split_what_is_due_from_what_is_not() {
        let now = UnixTime(1_000);
        assert!(expiry(now, Kind::Request, &id(0xFF)) < expiry_bound(now));
        assert!(expiry_bound(now) < expiry(UnixTime(1_001), Kind::Deposit, &id(0)));
        let object = ObjectName::from_array([0xFF; 16]);
        assert!(garbage(now, &object) < garbage_bound(now));
        assert!(garbage_bound(now) < garbage(UnixTime(1_001), &ObjectName::from_array([0; 16])));
    }

    #[test]
    fn index_keys_read_back() {
        let key = expiry(UnixTime(1_234_567), Kind::Request, &id(7));
        assert_eq!(parse_expiry(&key), Some((UnixTime(1_234_567), Kind::Request, id(7))));
        let object = ObjectName::from_array([0x5A; 16]);
        assert_eq!(parse_garbage(&garbage(UnixTime(42), &object)), Some((UnixTime(42), object)));
    }

    mod adversary {
        use super::*;

        #[test]
        fn malformed_index_keys_are_rejected() {
            let good = expiry(UnixTime(5), Kind::Deposit, &id(1));
            for bad in [
                String::new(),
                "x".into(),
                good[..good.len() - 1].to_string(),
                format!("{good}0"),
                good.replacen('d', "q", 1),
                good.to_uppercase(),
                format!("y{}", &good[1..]),
                format!("x{}", "g".repeat(49)),
                format!("x8000000000000000d{}", "01".repeat(16)),
                format!("x0000000000000005d{}é", "01".repeat(15)),
            ] {
                assert_eq!(parse_expiry(&bad), None, "{bad}");
            }
            let object = ObjectName::from_array([1; 16]);
            let good = garbage(UnixTime(5), &object);
            for bad in [good[..good.len() - 1].to_string(), format!("{good}0"), good.to_uppercase(), deposit(&id(1))] {
                assert_eq!(parse_garbage(&bad), None, "{bad}");
            }
        }

        #[test]
        fn times_before_the_epoch_sort_first_instead_of_wrapping() {
            assert!(expiry(UnixTime(-1), Kind::Deposit, &id(1)) < expiry(UnixTime(1), Kind::Deposit, &id(1)));
            assert_eq!(expiry_bound(UnixTime(i64::MAX)), format!("x{}", "7fffffffffffffff"));
        }
    }
}
