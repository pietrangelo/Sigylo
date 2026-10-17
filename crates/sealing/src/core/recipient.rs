//! Public material of the recipient (request) mode.

use core::fmt;

use super::SealError;

/// X25519 public key / ciphertext length.
pub const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const MLKEM768_PUBLIC_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// A recipient's hybrid public key: `pk_x25519 || ek_mlkem768`.
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientPublicKey(Box<[u8; RecipientPublicKey::LEN]>);

impl RecipientPublicKey {
    pub const LEN: usize = X25519_LEN + MLKEM768_PUBLIC_LEN;

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
        let array: [u8; Self::LEN] = bytes.try_into().map_err(|_| SealError::InvalidKeyMaterial)?;
        Ok(Self(Box::new(array)))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    pub fn x25519_part(&self) -> &[u8] {
        &self.0[..X25519_LEN]
    }

    pub fn mlkem_part(&self) -> &[u8] {
        &self.0[X25519_LEN..]
    }
}

impl fmt::Debug for RecipientPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecipientPublicKey({:02x?}…)", &self.0[..4])
    }
}

/// A short commitment to a public key. It travels in the request link so the
/// sender can tell when a relay serves a different key than the recipient made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; Fingerprint::LEN]);

impl Fingerprint {
    pub const LEN: usize = 32;

    pub fn from_array(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
        Ok(Self(bytes.try_into().map_err(|_| SealError::InvalidKeyMaterial)?))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// What the sender transmits so the recipient can recover the shared secret:
/// `ct_x25519 || ct_mlkem768`.
#[derive(Clone, PartialEq, Eq)]
pub struct Encapsulation(Box<[u8; Encapsulation::LEN]>);

impl Encapsulation {
    pub const LEN: usize = X25519_LEN + MLKEM768_CIPHERTEXT_LEN;

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
        let array: [u8; Self::LEN] = bytes.try_into().map_err(|_| SealError::MalformedEnvelope)?;
        Ok(Self(Box::new(array)))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    pub fn x25519_part(&self) -> &[u8] {
        &self.0[..X25519_LEN]
    }

    pub fn mlkem_part(&self) -> &[u8] {
        &self.0[X25519_LEN..]
    }
}

impl fmt::Debug for Encapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Encapsulation({:02x?}…)", &self.0[..4])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_follow_fips_203_and_x25519() {
        assert_eq!(RecipientPublicKey::LEN, 1216);
        assert_eq!(Encapsulation::LEN, 1120);
    }

    #[test]
    fn parts_split_at_the_x25519_boundary() {
        let mut bytes = vec![1u8; RecipientPublicKey::LEN];
        bytes[..X25519_LEN].fill(9);
        let pk = RecipientPublicKey::from_slice(&bytes).unwrap();
        assert!(pk.x25519_part().iter().all(|&b| b == 9));
        assert_eq!(pk.mlkem_part().len(), MLKEM768_PUBLIC_LEN);
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert_eq!(RecipientPublicKey::from_slice(&[0; 1215]), Err(SealError::InvalidKeyMaterial));
        assert_eq!(Fingerprint::from_slice(&[0; 16]), Err(SealError::InvalidKeyMaterial));
        assert_eq!(Encapsulation::from_slice(&[0; 1121]), Err(SealError::MalformedEnvelope));
    }
}
