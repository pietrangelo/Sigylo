//! The OPAQUE messages as the domain sees them: opaque bytes of the exact
//! length the Sigylo v1 suite (ristretto255 + SHA-512) produces. A parser
//! that accepts only these lengths gives the adapters nothing odd to chew on;
//! `access-adapters` pins the lengths against the real library.

use core::fmt;

use super::AccessError;

macro_rules! message {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub const LEN: usize = $len;

            pub fn from_slice(bytes: &[u8]) -> Result<Self, AccessError> {
                if bytes.len() == Self::LEN { Ok(Self(bytes.to_vec())) } else { Err(AccessError::MalformedMessage) }
            }

            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            // Records are about as sensitive as a password hash; never print them.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({} bytes)"), self.0.len())
            }
        }
    };
}

message!(
    /// Registration, client → relay: the blinded password.
    RegistrationRequest, 32
);
message!(
    /// Registration, relay → client: the OPRF evaluation and the relay's public key.
    RegistrationResponse, 64
);
message!(
    /// Registration, client → relay: what the relay keeps for the account
    /// (client public key, masking key, envelope). Useless without the password.
    RegistrationRecord, 192
);
message!(
    /// Login, client → relay (KE1): blinded password and ephemeral key share.
    CredentialRequest, 96
);
message!(
    /// Login, relay → client (KE2): OPRF evaluation, masked envelope, key share and MAC.
    CredentialResponse, 320
);
message!(
    /// Login, client → relay (KE3): the client's MAC. Proves the password.
    CredentialFinalization, 64
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_length_parses() {
        assert!(RegistrationRequest::from_slice(&[0; 32]).is_ok());
        for len in [0, 31, 33, 64] {
            assert_eq!(RegistrationRequest::from_slice(&vec![0; len]), Err(AccessError::MalformedMessage));
        }
        assert!(CredentialResponse::from_slice(&[1; CredentialResponse::LEN]).is_ok());
        assert_eq!(CredentialFinalization::from_slice(&[1; 63]), Err(AccessError::MalformedMessage));
    }

    mod adversary {
        use super::*;

        #[test]
        fn debug_prints_no_record_bytes() {
            let record = RegistrationRecord::from_slice(&[0xAB; RegistrationRecord::LEN]).unwrap();
            let rendered = format!("{record:?}");
            assert_eq!(rendered, "RegistrationRecord(192 bytes)");
        }
    }
}
