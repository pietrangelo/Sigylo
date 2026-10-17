//! Secret value objects. Each one wipes its memory on drop and never prints
//! its bytes in `Debug`, so a stray log line cannot leak a key.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::SealError;

/// Largest plaintext accepted (it fits the 64 KiB padding bucket with its frame).
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024 - 4;
/// Largest passphrase accepted, in UTF-8 bytes.
pub const MAX_PASSPHRASE_LEN: usize = 1024;
/// Length of every symmetric key in Sigylo.
pub const KEY_LEN: usize = 32;

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

            pub fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
                let mut array: [u8; $len] =
                    bytes.try_into().map_err(|_| SealError::InvalidKeyMaterial)?;
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
    /// A 256-bit symmetric key: AEAD keys, KEM shared secrets, stretched passphrases.
    SymmetricKey,
    KEY_LEN
);

secret_array!(
    /// The random key of a link-mode secret. It lives only in the URL fragment,
    /// which browsers never send to any server.
    LinkKey,
    KEY_LEN
);

secret_array!(
    /// The random key of one file: it seals the file's chunks and travels
    /// only inside the file's sealed manifest.
    FileKey,
    KEY_LEN
);

secret_array!(
    /// The recipient's whole private key: one 32-byte seed from which the
    /// X25519 and ML-KEM-768 secrets are expanded.
    RecipientSeed,
    32
);

/// A passphrase shared out of band as a second factor.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Passphrase(Vec<u8>);

impl Passphrase {
    /// Accepts 1 to [`MAX_PASSPHRASE_LEN`] bytes. The shell is expected to
    /// normalize text to Unicode NFC before handing it over.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SealError> {
        let value = Self(bytes);
        if value.0.is_empty() || value.0.len() > MAX_PASSPHRASE_LEN {
            return Err(SealError::InvalidPassphrase);
        }
        Ok(value)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(redacted)")
    }
}

/// The secret itself, before sealing or after opening.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SealError> {
        let value = Self(bytes);
        if value.0.is_empty() {
            return Err(SealError::PlaintextEmpty);
        }
        if value.0.len() > MAX_PLAINTEXT_LEN {
            return Err(SealError::PlaintextTooLarge);
        }
        Ok(value)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Hand the bytes over (for example to copy them into a JS buffer).
    pub fn into_zeroizing(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut self.0))
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext(redacted, {} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_require_exact_length() {
        assert!(LinkKey::from_slice(&[1; 32]).is_ok());
        assert_eq!(LinkKey::from_slice(&[1; 31]), Err(SealError::InvalidKeyMaterial));
        assert_eq!(RecipientSeed::from_slice(&[1; 33]), Err(SealError::InvalidKeyMaterial));
    }

    #[test]
    fn passphrase_bounds() {
        assert_eq!(Passphrase::new(vec![]), Err(SealError::InvalidPassphrase));
        assert!(Passphrase::new(vec![b'a'; MAX_PASSPHRASE_LEN]).is_ok());
        assert_eq!(Passphrase::new(vec![b'a'; MAX_PASSPHRASE_LEN + 1]), Err(SealError::InvalidPassphrase));
    }

    #[test]
    fn plaintext_bounds() {
        assert_eq!(Plaintext::new(vec![]), Err(SealError::PlaintextEmpty));
        assert!(Plaintext::new(vec![0; MAX_PLAINTEXT_LEN]).is_ok());
        assert_eq!(Plaintext::new(vec![0; MAX_PLAINTEXT_LEN + 1]), Err(SealError::PlaintextTooLarge));
    }

    mod adversary {
        use super::*;

        #[test]
        fn debug_output_never_contains_secret_bytes() {
            let rendered = format!(
                "{:?} {:?} {:?} {:?} {:?} {:?}",
                SymmetricKey::from_array([0x41; 32]),
                FileKey::from_array([0x41; 32]),
                LinkKey::from_array([0x41; 32]),
                RecipientSeed::from_array([0x41; 32]),
                Passphrase::new(b"hunter2".to_vec()).unwrap(),
                Plaintext::new(b"AAAA top secret".to_vec()).unwrap(),
            );
            assert!(!rendered.contains("65") && !rendered.contains("hunter2"));
            assert!(!rendered.contains("top secret") && !rendered.contains("AAAA"));
            assert_eq!(rendered.matches("redacted").count(), 6);
        }
    }
}
