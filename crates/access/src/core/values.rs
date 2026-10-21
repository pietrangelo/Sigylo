use core::fmt;

use super::AccessError;
use super::secrets::{DevicePass, SessionToken};

/// Largest keyring the relay keeps: a sealed 64 KiB envelope with its header.
pub const MAX_KEYRING_LEN: usize = 72 * 1024;
/// How long a session lasts. It lives in the tab's memory only, so a reload
/// or a closed tab ends it sooner.
pub const SESSION_SECONDS: u32 = 12 * 60 * 60;
/// How long a login may take between its two round trips.
pub const LOGIN_WINDOW_SECONDS: u32 = 5 * 60;
/// HKDF info that turns the export key into the keyring key.
pub const KEYRING_INFO: &[u8] = b"sigylo/v1/keyring";

/// A login name, case-insensitive: stored lowercase.
///
/// The relay never stores it: the account is filed under a keyed hash of it
/// ([`AccountId`]). The client NFC-normalizes it before sending.
#[derive(Clone, PartialEq, Eq)]
pub struct Username(String);

impl Username {
    pub const MIN_CHARS: usize = 3;
    pub const MAX_CHARS: usize = 64;

    pub fn new(text: &str) -> Result<Self, AccessError> {
        let name = text.to_lowercase();
        let chars = name.chars().count();
        let clean = name.chars().all(|c| !c.is_whitespace() && !c.is_control());
        if clean && (Self::MIN_CHARS..=Self::MAX_CHARS).contains(&chars) {
            Ok(Self(name))
        } else {
            Err(AccessError::InvalidUsername)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Username {
    // Personal data: never in a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Username(redacted)")
    }
}

/// Where an account is filed: a keyed hash of the username, so a copy of the
/// store does not reveal who has an account, not even by guessing names.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountId([u8; 32]);

impl AccountId {
    pub const LEN: usize = 32;

    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AccessError> {
        Ok(Self(bytes.try_into().map_err(|_| AccessError::MalformedMessage)?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({:02x}{:02x}…)", self.0[0], self.0[1])
    }
}

/// What the store keeps instead of a session token: SHA-256 of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionDigest([u8; 32]);

impl SessionDigest {
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Most live sessions one account keeps: opening one more ends the one
/// that expires first, so a stolen password cannot pile up sessions and
/// the person's own logins always get in.
pub const MAX_SESSIONS: u32 = 16;

/// How long a [`DevicePass`] lets a device skip the shared login budget.
pub const PASS_SECONDS: u32 = 90 * 24 * 60 * 60;

/// Which allowance a login or registration attempt spends. Each account has
/// one per kind, so exhausting one never blocks another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Budget {
    /// Logins without a valid pass: the one guessing spends.
    Login,
    /// Registrations of a name nobody holds.
    Registration,
    /// Logins from the device that holds this pass.
    Device(DevicePass),
}

/// Seconds since the Unix epoch, as decided by the store's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(pub i64);

/// A live session, as handed to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub token: SessionToken,
    pub expires_at: UnixTime,
    /// For this device's next logins.
    pub pass: DevicePass,
}

/// The account's keyring: an envelope sealed on the device with the
/// [`crate::KeyringKey`]. Opaque bytes to the relay.
#[derive(Clone, PartialEq, Eq)]
pub struct Keyring(Vec<u8>);

impl Keyring {
    pub fn new(bytes: Vec<u8>) -> Result<Self, AccessError> {
        match bytes.len() {
            0 => Err(AccessError::KeyringEmpty),
            n if n > MAX_KEYRING_LEN => Err(AccessError::KeyringTooLarge),
            _ => Ok(Self(bytes)),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyring({} bytes)", self.0.len())
    }
}

/// Counts the writes of a keyring; 0 means none yet. A write names the
/// version it read, so two devices never silently overwrite each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyringVersion(pub u64);

impl KeyringVersion {
    pub const NONE: Self = Self(0);
}

/// The keyring as last stored, with its version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringSnapshot {
    pub keyring: Option<Keyring>,
    pub version: KeyringVersion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_case_insensitive() {
        assert_eq!(Username::new("Pietrangelo").unwrap(), Username::new("pietrangelo").unwrap());
        assert_eq!(Username::new("ÉLODIE").unwrap().as_bytes(), "élodie".as_bytes());
    }

    #[test]
    fn username_bounds() {
        assert_eq!(Username::new("ab"), Err(AccessError::InvalidUsername));
        assert!(Username::new("abc").is_ok());
        assert!(Username::new(&"é".repeat(64)).is_ok());
        assert_eq!(Username::new(&"é".repeat(65)), Err(AccessError::InvalidUsername));
        assert!(Username::new("ada@example.org").is_ok());
    }

    #[test]
    fn keyring_bounds() {
        assert_eq!(Keyring::new(vec![]), Err(AccessError::KeyringEmpty));
        assert!(Keyring::new(vec![1; MAX_KEYRING_LEN]).is_ok());
        assert_eq!(Keyring::new(vec![1; MAX_KEYRING_LEN + 1]), Err(AccessError::KeyringTooLarge));
    }

    mod adversary {
        use super::*;

        #[test]
        fn usernames_cannot_hide_spaces_or_control_characters() {
            for name in ["ada lovelace", " ada", "ada\n", "ada\u{0}x", "ada\u{2028}", "ada\u{00A0}x", "ad\ta"] {
                assert_eq!(Username::new(name), Err(AccessError::InvalidUsername), "{name:?}");
            }
        }

        #[test]
        fn debug_prints_neither_usernames_nor_whole_ids() {
            let rendered = format!("{:?} {:?}", Username::new("ada").unwrap(), AccountId::from_array([0xAB; 32]));
            assert!(!rendered.contains("ada"));
            assert!(!rendered.contains("abababab"));
        }
    }
}
