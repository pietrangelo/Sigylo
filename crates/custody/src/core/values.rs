use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::CustodyError;

/// Largest payload the relay keeps: a 64 KiB padded secret plus envelope header.
pub const MAX_PAYLOAD_LEN: usize = 72 * 1024;

/// An unguessable 128-bit identifier, chosen by the client.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DropId([u8; DropId::LEN]);

impl DropId {
    pub const LEN: usize = 16;

    pub fn from_slice(bytes: &[u8]) -> Result<Self, CustodyError> {
        Ok(Self(bytes.try_into().map_err(|_| CustodyError::InvalidId)?))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for DropId {
    // Ids are bearer capabilities in a link: never print them whole.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DropId({:02x}{:02x}…)", self.0[0], self.0[1])
    }
}

/// Opaque ciphertext. The relay stores and returns it, nothing more.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPayload(Vec<u8>);

impl SealedPayload {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CustodyError> {
        match bytes.len() {
            0 => Err(CustodyError::PayloadEmpty),
            n if n > MAX_PAYLOAD_LEN => Err(CustodyError::PayloadTooLarge),
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

impl fmt::Debug for SealedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedPayload({} bytes)", self.0.len())
    }
}

/// What happens after a successful read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Destroyed atomically by the first read (and in any case at expiry).
    BurnAfterReading,
    /// Readable any number of times until it expires.
    UntilExpiry,
}

/// How long something may stay in custody: 5 minutes to 7 days.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lifetime(u32);

impl Lifetime {
    pub const MIN: Self = Self(5 * 60);
    pub const ONE_HOUR: Self = Self(60 * 60);
    pub const ONE_DAY: Self = Self(24 * 60 * 60);
    pub const MAX: Self = Self(7 * 24 * 60 * 60);

    pub fn from_seconds(seconds: u32) -> Result<Self, CustodyError> {
        if (Self::MIN.0..=Self::MAX.0).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(CustodyError::LifetimeOutOfRange)
        }
    }

    pub fn seconds(&self) -> u32 {
        self.0
    }
}

/// Seconds since the Unix epoch, as decided by the vault's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(pub i64);

/// The sender's secret for revoking a deposit before it is read.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RevocationToken([u8; 32]);

impl RevocationToken {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CustodyError> {
        Ok(Self(bytes.try_into().map_err(|_| CustodyError::InvalidToken)?))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RevocationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RevocationToken(redacted)")
    }
}

/// What the vault stores instead of the token: SHA-256 of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationDigest([u8; 32]);

impl RevocationDigest {
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, CustodyError> {
        Ok(Self(bytes.try_into().map_err(|_| CustodyError::InvalidToken)?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A recipient's public key as the relay sees it: 1216 opaque bytes
/// (X25519 32 + ML-KEM-768 1184).
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientKeyBlob(Vec<u8>);

impl RecipientKeyBlob {
    pub const LEN: usize = 1216;

    pub fn new(bytes: Vec<u8>) -> Result<Self, CustodyError> {
        if bytes.len() == Self::LEN { Ok(Self(bytes)) } else { Err(CustodyError::InvalidRecipientKey) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RecipientKeyBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientKeyBlob(1216 bytes)")
    }
}

/// A sealed secret handed over for safekeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposit {
    pub id: DropId,
    pub payload: SealedPayload,
    pub retention: Retention,
    pub lifetime: Lifetime,
    pub revocation: Option<RevocationDigest>,
}

/// The result of a successful read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub payload: SealedPayload,
    /// True when this read destroyed the deposit.
    pub burned: bool,
}

/// A recipient asking for one secret to be sealed to their public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: DropId,
    pub recipient_key: RecipientKeyBlob,
    pub lifetime: Lifetime,
}

/// A request as a sender sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostedRequest {
    pub recipient_key: RecipientKeyBlob,
    pub expires_at: UnixTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_window_is_five_minutes_to_seven_days() {
        assert_eq!(Lifetime::from_seconds(299), Err(CustodyError::LifetimeOutOfRange));
        assert_eq!(Lifetime::from_seconds(300), Ok(Lifetime::MIN));
        assert_eq!(Lifetime::from_seconds(604_800), Ok(Lifetime::MAX));
        assert_eq!(Lifetime::from_seconds(604_801), Err(CustodyError::LifetimeOutOfRange));
        assert_eq!(Lifetime::from_seconds(0), Err(CustodyError::LifetimeOutOfRange));
    }

    #[test]
    fn payload_bounds() {
        assert_eq!(SealedPayload::new(vec![]), Err(CustodyError::PayloadEmpty));
        assert!(SealedPayload::new(vec![1; MAX_PAYLOAD_LEN]).is_ok());
        assert_eq!(SealedPayload::new(vec![1; MAX_PAYLOAD_LEN + 1]), Err(CustodyError::PayloadTooLarge));
    }

    #[test]
    fn fixed_sizes() {
        assert_eq!(DropId::from_slice(&[0; 15]), Err(CustodyError::InvalidId));
        assert_eq!(RecipientKeyBlob::new(vec![0; 1215]), Err(CustodyError::InvalidRecipientKey));
        assert_eq!(RevocationToken::from_slice(&[0; 31]), Err(CustodyError::InvalidToken));
        assert!(RecipientKeyBlob::new(vec![0; 1216]).is_ok());
    }

    mod adversary {
        use super::*;

        #[test]
        fn debug_never_prints_capabilities_or_ciphertext() {
            let id = DropId::from_slice(&[0xAB; 16]).unwrap();
            let rendered = format!(
                "{id:?} {:?} {:?}",
                RevocationToken::from_slice(&[0xCD; 32]).unwrap(),
                SealedPayload::new(vec![0xEF; 40]).unwrap(),
            );
            assert!(!rendered.contains("abababab"));
            assert!(!rendered.to_lowercase().contains("cd") && !rendered.to_lowercase().contains("ef"));
        }
    }
}
