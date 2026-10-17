use core::fmt;

/// Everything that can go wrong while sealing or opening.
///
/// Opening failures are collapsed on purpose: a wrong link key, a wrong
/// passphrase, a wrong recipient and a tampered envelope all surface as
/// [`SealError::NotAuthentic`], so an attacker learns nothing from which
/// check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The device's random number generator failed.
    RandomnessUnavailable,
    /// The plaintext exceeds [`crate::MAX_PLAINTEXT_LEN`].
    PlaintextTooLarge,
    /// The plaintext or file is empty: there is nothing to seal.
    PlaintextEmpty,
    /// The file exceeds [`crate::MAX_FILE_LEN`].
    FileTooLarge,
    /// The file name is empty, too long, or contains separators, control or
    /// invisible characters.
    InvalidFileName,
    /// A passphrase is empty or longer than [`crate::MAX_PASSPHRASE_LEN`].
    InvalidPassphrase,
    /// Bytes that should be a key, seed, fingerprint or public key have the wrong shape.
    InvalidKeyMaterial,
    /// Argon2id costs outside the accepted range.
    KdfCostOutOfRange,
    /// The envelope is truncated, from an unknown version, or malformed.
    MalformedEnvelope,
    /// The envelope was sealed for the other mode (link key vs recipient).
    WrongMode,
    /// The envelope needs a passphrase and none was given, or the reverse.
    PassphraseExpectationMismatch,
    /// The recipient public key does not match the fingerprint in the request link.
    FingerprintMismatch,
    /// Authentication failed.
    NotAuthentic,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RandomnessUnavailable => "randomness unavailable",
            Self::PlaintextTooLarge => "secret too large",
            Self::PlaintextEmpty => "secret is empty",
            Self::FileTooLarge => "file too large",
            Self::InvalidFileName => "invalid file name",
            Self::InvalidPassphrase => "invalid passphrase",
            Self::InvalidKeyMaterial => "invalid key material",
            Self::KdfCostOutOfRange => "key derivation cost out of range",
            Self::MalformedEnvelope => "malformed envelope",
            Self::WrongMode => "envelope sealed for another mode",
            Self::PassphraseExpectationMismatch => "passphrase required or unexpected",
            Self::FingerprintMismatch => "recipient key fingerprint mismatch",
            Self::NotAuthentic => "cannot open: wrong key, wrong passphrase or tampered",
        })
    }
}

impl std::error::Error for SealError {}
