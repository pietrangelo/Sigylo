//! Public material of a sender's signing identity.
//!
//! A sender signs every answer to a request with a hybrid Ed25519 +
//! ML-DSA-65 (FIPS 204) key. The recipient learns the sender's
//! [`SenderFingerprint`] when opening, and its [`SenderFingerprint::code`]
//! is what the two compare out of band: someone who raced the legitimate
//! sender to the request link cannot make the codes match.

use core::fmt;

use super::SealError;

/// Ed25519 public key length.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-65 verifying key length (FIPS 204).
pub const MLDSA65_PUBLIC_LEN: usize = 1952;
/// ML-DSA-65 signature length (FIPS 204).
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;

/// A sender's hybrid verifying key: `pk_ed25519 || vk_mldsa65`.
#[derive(Clone, PartialEq, Eq)]
pub struct SenderPublicKey(Box<[u8; SenderPublicKey::LEN]>);

impl SenderPublicKey {
    pub const LEN: usize = ED25519_PUBLIC_LEN + MLDSA65_PUBLIC_LEN;

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
        let array: [u8; Self::LEN] = bytes.try_into().map_err(|_| SealError::InvalidKeyMaterial)?;
        Ok(Self(Box::new(array)))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    pub fn ed25519_part(&self) -> &[u8] {
        &self.0[..ED25519_PUBLIC_LEN]
    }

    pub fn mldsa_part(&self) -> &[u8] {
        &self.0[ED25519_PUBLIC_LEN..]
    }
}

impl fmt::Debug for SenderPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SenderPublicKey({:02x?}…)", &self.0[..4])
    }
}

/// A hybrid signature: `sig_ed25519 || sig_mldsa65`. It verifies only if
/// both halves do, so it holds as long as either scheme is unbroken.
#[derive(Clone, PartialEq, Eq)]
pub struct SenderSignature(Box<[u8; SenderSignature::LEN]>);

impl SenderSignature {
    pub const LEN: usize = ED25519_SIGNATURE_LEN + MLDSA65_SIGNATURE_LEN;

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
        let array: [u8; Self::LEN] = bytes.try_into().map_err(|_| SealError::MalformedEnvelope)?;
        Ok(Self(Box::new(array)))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    pub fn ed25519_part(&self) -> &[u8] {
        &self.0[..ED25519_SIGNATURE_LEN]
    }

    pub fn mldsa_part(&self) -> &[u8] {
        &self.0[ED25519_SIGNATURE_LEN..]
    }
}

impl fmt::Debug for SenderSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SenderSignature({:02x?}…)", &self.0[..4])
    }
}

/// A domain-separated hash of a [`SenderPublicKey`]: the sender's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderFingerprint([u8; SenderFingerprint::LEN]);

/// Crockford's base32 alphabet: no I, L, O or U, so a code read aloud or
/// copied by hand is hard to get wrong.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

impl SenderFingerprint {
    pub const LEN: usize = 32;
    /// Characters in a [`Self::code`], without separators: 100 bits, far
    /// beyond what grinding keys for a look-alike code could reach.
    pub const CODE_CHARS: usize = 20;

    pub fn from_array(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The code people compare: the first 100 bits in base32, in groups of
    /// four, e.g. `7KQ2-M9DX-…`.
    pub fn code(&self) -> String {
        let mut out = String::with_capacity(Self::CODE_CHARS + Self::CODE_CHARS / 4 - 1);
        for i in 0..Self::CODE_CHARS {
            let bit = i * 5;
            let pair = u16::from_be_bytes([self.0[bit / 8], self.0[bit / 8 + 1]]);
            let index = (pair >> (11 - bit % 8)) & 0x1F;
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(CODE_ALPHABET[usize::from(index)]));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_follow_fips_204_and_ed25519() {
        assert_eq!(SenderPublicKey::LEN, 1984);
        assert_eq!(SenderSignature::LEN, 3373);
    }

    #[test]
    fn parts_split_at_the_ed25519_boundary() {
        let mut bytes = vec![1u8; SenderSignature::LEN];
        bytes[..ED25519_SIGNATURE_LEN].fill(9);
        let sig = SenderSignature::from_slice(&bytes).unwrap();
        assert!(sig.ed25519_part().iter().all(|&b| b == 9));
        assert_eq!(sig.mldsa_part().len(), MLDSA65_SIGNATURE_LEN);
        let pk = SenderPublicKey::from_slice(&[2; SenderPublicKey::LEN]).unwrap();
        assert_eq!((pk.ed25519_part().len(), pk.mldsa_part().len()), (32, 1952));
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert_eq!(SenderPublicKey::from_slice(&[0; 1983]), Err(SealError::InvalidKeyMaterial));
        assert_eq!(SenderSignature::from_slice(&[0; 3374]), Err(SealError::MalformedEnvelope));
    }

    #[test]
    fn code_is_crockford_base32_in_groups_of_four() {
        assert_eq!(SenderFingerprint::from_array([0; 32]).code(), "0000-0000-0000-0000-0000");
        assert_eq!(SenderFingerprint::from_array([0xFF; 32]).code(), "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ");
        // 0x08 0x86 0x42 = 00001 00010 00011 00100 0010…: 1, 2, 3, 4.
        let mut bytes = [0u8; 32];
        bytes[..3].copy_from_slice(&[0x08, 0x86, 0x42]);
        assert!(SenderFingerprint::from_array(bytes).code().starts_with("1234-"));
    }

    #[test]
    fn code_uses_exactly_the_first_100_bits() {
        let mut bytes = [0u8; 32];
        bytes[12] = 0xF0; // bits 96..100
        assert!(SenderFingerprint::from_array(bytes).code().ends_with("-000F"));
        bytes[12] = 0x0F; // bits 100..104: not part of the code
        bytes[13..].fill(0xFF);
        assert_eq!(SenderFingerprint::from_array(bytes).code(), "0000-0000-0000-0000-0000");
    }

    mod adversary {
        use super::*;

        #[test]
        fn a_single_bit_inside_the_code_changes_it() {
            let base = SenderFingerprint::from_array([0x5A; 32]).code();
            for bit in 0..100 {
                let mut bytes = [0x5A; 32];
                bytes[bit / 8] ^= 0x80 >> (bit % 8);
                assert_ne!(SenderFingerprint::from_array(bytes).code(), base, "bit {bit}");
            }
        }

        #[test]
        fn code_never_uses_look_alike_letters() {
            for fill in 0..=255u8 {
                let code = SenderFingerprint::from_array([fill; 32]).code();
                assert!(!code.contains(['I', 'L', 'O', 'U']), "{code}");
            }
        }
    }
}
