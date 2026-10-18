//! Secret value objects. Each one wipes its memory on drop and never prints
//! its bytes in `Debug`.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::AccessError;

/// Shortest password accepted, in UTF-8 bytes.
pub const MIN_PASSWORD_LEN: usize = 8;
/// Longest password accepted, in UTF-8 bytes.
pub const MAX_PASSWORD_LEN: usize = 1024;

macro_rules! secret_array {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            /// Takes ownership of the array (the caller's copy is moved, not left behind).
            pub fn from_array(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub fn from_slice(bytes: &[u8]) -> Result<Self, AccessError> {
                let mut array: [u8; $len] = bytes.try_into().map_err(|_| AccessError::MalformedMessage)?;
                let value = Self(array);
                array.zeroize();
                Ok(value)
            }

            pub fn expose(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(redacted)"))
            }
        }
    };
}

secret_array!(
    /// OPAQUE's export key: known to the client only, the same at every
    /// login, and the root of every key the account keeps on the device.
    ExportKey, 64
);
secret_array!(
    /// Seals and opens the account's keyring. Derived from the export key on
    /// the device; the relay never sees it.
    KeyringKey, 32
);
secret_array!(
    /// Bearer capability for one session. The relay stores only its digest.
    SessionToken, 32
);
secret_array!(
    /// Proof that a device logged in to the account before, issued by the
    /// relay at each login and kept by the device. It opens nothing; it only
    /// lets the device's logins spend an allowance of their own, so a flood
    /// of guesses for the name cannot lock its owner out. Bound to the
    /// account's record and dated by the relay.
    DevicePass, 56
);
secret_array!(
    /// Names a login between its two round trips. Single use, five minutes.
    LoginHandle, 16
);

/// The password, on the device only. OPAQUE never sends it anywhere.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Password(Vec<u8>);

impl Password {
    /// Takes ownership of the UTF-8 bytes (NFC-normalized by the client).
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, AccessError> {
        if (MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            bytes.zeroize();
            Err(AccessError::InvalidPassword)
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(redacted)")
    }
}

/// The relay's half of a login between KE2 and KE3 (it holds the session
/// key and the expected client MAC), sealed by the relay to the account it
/// belongs to: 128 bytes of state, a 24-byte nonce and a 16-byte tag.
/// Parked in the store for five minutes.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LoginState(Vec<u8>);

impl LoginState {
    pub const LEN: usize = 168;

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AccessError> {
        if bytes.len() == Self::LEN { Ok(Self(bytes.to_vec())) } else { Err(AccessError::MalformedMessage) }
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for LoginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginState(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_bounds() {
        assert_eq!(Password::new(b"1234567".to_vec()), Err(AccessError::InvalidPassword));
        assert!(Password::new(b"12345678".to_vec()).is_ok());
        assert!(Password::new(vec![b'a'; MAX_PASSWORD_LEN]).is_ok());
        assert_eq!(Password::new(vec![b'a'; MAX_PASSWORD_LEN + 1]), Err(AccessError::InvalidPassword));
    }

    #[test]
    fn fixed_sizes() {
        assert_eq!(SessionToken::from_slice(&[0; 31]), Err(AccessError::MalformedMessage));
        assert_eq!(LoginHandle::from_slice(&[0; 17]), Err(AccessError::MalformedMessage));
        assert_eq!(LoginState::from_slice(&[0; 167]), Err(AccessError::MalformedMessage));
        assert!(ExportKey::from_slice(&[0; 64]).is_ok());
    }

    mod adversary {
        use super::*;

        #[test]
        fn debug_never_prints_secret_bytes() {
            let rendered = format!(
                "{:?} {:?} {:?} {:?} {:?} {:?}",
                Password::new(b"hunter2hunter2".to_vec()).unwrap(),
                ExportKey::from_array([0xAB; 64]),
                KeyringKey::from_array([0xAB; 32]),
                SessionToken::from_array([0xAB; 32]),
                LoginHandle::from_array([0xAB; 16]),
                LoginState::from_slice(&[0xAB; LoginState::LEN]).unwrap(),
            );
            assert!(!rendered.contains("hunter2"));
            assert!(!rendered.to_lowercase().contains("ab,") && !rendered.contains("171"));
            assert_eq!(rendered.matches("redacted").count(), 6);
        }
    }
}
