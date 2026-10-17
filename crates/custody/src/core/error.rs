use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyError {
    /// An identifier is not exactly 16 bytes.
    InvalidId,
    /// A payload is empty.
    PayloadEmpty,
    /// A payload is shorter than any envelope ([`crate::MIN_PAYLOAD_LEN`]).
    PayloadTooSmall,
    /// A payload exceeds [`crate::MAX_PAYLOAD_LEN`].
    PayloadTooLarge,
    /// A lifetime is outside the 5 minutes to 7 days window.
    LifetimeOutOfRange,
    /// A recipient public key blob has the wrong size.
    InvalidRecipientKey,
    /// A revocation or claim token is not 32 bytes.
    InvalidToken,
    /// A chunk count or index is outside what a file can have.
    InvalidChunk,
    /// Something already lives under this identifier.
    AlreadyExists,
    /// Nothing to give: never existed, expired, already read, revoked or
    /// answered. These cases are deliberately indistinguishable.
    NotFound,
    /// The vault could not be reached.
    VaultUnavailable,
    /// The vault has no room for anything new right now (sealed bytes or
    /// chunks); opening, revoking and purging still work.
    StorageFull,
    /// No fresh id could be drawn: the random source failed.
    RandomnessUnavailable,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidId => "invalid identifier",
            Self::PayloadEmpty => "empty payload",
            Self::PayloadTooSmall => "payload too small",
            Self::PayloadTooLarge => "payload too large",
            Self::LifetimeOutOfRange => "lifetime out of range",
            Self::InvalidRecipientKey => "invalid recipient key",
            Self::InvalidToken => "invalid token",
            Self::InvalidChunk => "invalid chunk count or index",
            Self::AlreadyExists => "identifier already in use",
            Self::NotFound => "not found, expired or already read",
            Self::VaultUnavailable => "vault unavailable",
            Self::StorageFull => "storage full",
            Self::RandomnessUnavailable => "randomness unavailable",
        })
    }
}

impl std::error::Error for CustodyError {}
