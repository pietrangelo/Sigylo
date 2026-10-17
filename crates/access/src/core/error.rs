use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    /// A username is shorter than 3 or longer than 64 characters, or holds
    /// spaces or control characters.
    InvalidUsername,
    /// A password is shorter than 8 bytes or longer than 1024.
    InvalidPassword,
    /// A protocol message, handle or token has the wrong size or encoding.
    MalformedMessage,
    /// A keyring is empty.
    KeyringEmpty,
    /// A keyring exceeds [`crate::MAX_KEYRING_LEN`].
    KeyringTooLarge,
    /// The username is taken.
    AlreadyRegistered,
    /// The login failed: wrong password, unknown user, tampered message,
    /// expired or reused login. These cases are deliberately indistinguishable.
    NotAuthentic,
    /// No live session: never opened, expired, signed out or account closed.
    Unauthorized,
    /// The keyring changed since it was read: read it again and merge.
    Conflict,
    /// Too many login attempts for this account: wait a minute.
    Throttled,
    /// The account store could not be reached.
    StoreUnavailable,
    /// The relay has no OPAQUE key configured.
    NotConfigured,
    /// A random source failed.
    RandomnessUnavailable,
}

impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidUsername => "invalid username",
            Self::InvalidPassword => "invalid password",
            Self::MalformedMessage => "malformed message",
            Self::KeyringEmpty => "empty keyring",
            Self::KeyringTooLarge => "keyring too large",
            Self::AlreadyRegistered => "username already registered",
            Self::NotAuthentic => "login failed",
            Self::Unauthorized => "no live session",
            Self::Conflict => "keyring changed meanwhile",
            Self::Throttled => "too many login attempts",
            Self::StoreUnavailable => "account store unavailable",
            Self::NotConfigured => "login not configured",
            Self::RandomnessUnavailable => "randomness unavailable",
        })
    }
}

impl std::error::Error for AccessError {}
