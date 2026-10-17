//! A signed answer, as it sits inside the sealed (padded, encrypted) plaintext.
//!
//! ```text
//! offset  size  field
//! 0       1984  sender public key (pk_ed25519 || vk_mldsa65)
//! 1984    3373  signature (sig_ed25519 || sig_mldsa65)
//! 5357    ≥ 1   the secret
//! ```
//!
//! The block travels inside the AEAD, so the relay sees neither who signed
//! nor that the same sender answered two requests. The signature covers
//! [`signed_message`]: the recipient's fingerprint, the whole envelope header
//! and the secret. A recipient therefore cannot re-seal a signed secret to
//! someone else and pass it off as sent to them, and nothing in the envelope
//! can be swapped without the signature failing.

use zeroize::Zeroizing;

use super::{Fingerprint, MAX_PLAINTEXT_LEN, Plaintext, SealError, SenderPublicKey, SenderSignature};

/// Bytes a signature adds to the sealed plaintext.
pub const SIGNATURE_BLOCK_LEN: usize = SenderPublicKey::LEN + SenderSignature::LEN;
/// Largest secret that still fits once signed.
pub const MAX_SIGNED_PLAINTEXT_LEN: usize = MAX_PLAINTEXT_LEN - SIGNATURE_BLOCK_LEN;

const SIGNED_MESSAGE_LABEL: &[u8] = b"sigylo/v1/signed-answer";

/// The exact bytes a sender signs: `label || recipient fingerprint || header || secret`.
/// The header already fixes its own length, so the concatenation is unambiguous.
pub fn signed_message(recipient: &Fingerprint, header: &[u8], plaintext: &Plaintext) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        SIGNED_MESSAGE_LABEL.len() + Fingerprint::LEN + header.len() + plaintext.expose().len(),
    ));
    out.extend_from_slice(SIGNED_MESSAGE_LABEL);
    out.extend_from_slice(recipient.as_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(plaintext.expose());
    out
}

/// A secret together with who signed it and the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPlaintext {
    pub sender: SenderPublicKey,
    pub signature: SenderSignature,
    pub plaintext: Plaintext,
}

impl SignedPlaintext {
    /// The block as one plaintext, ready to be padded and sealed.
    pub fn to_plaintext(&self) -> Result<Plaintext, SealError> {
        if self.plaintext.expose().len() > MAX_SIGNED_PLAINTEXT_LEN {
            return Err(SealError::PlaintextTooLarge);
        }
        let mut out = Vec::with_capacity(SIGNATURE_BLOCK_LEN + self.plaintext.expose().len());
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(self.signature.as_bytes());
        out.extend_from_slice(self.plaintext.expose());
        Plaintext::new(out)
    }

    /// Splits an opened plaintext back into its parts. Nothing is verified here.
    pub fn parse(inner: &Plaintext) -> Result<Self, SealError> {
        let bytes = inner.expose();
        if bytes.len() <= SIGNATURE_BLOCK_LEN {
            return Err(SealError::MalformedEnvelope);
        }
        let (sender, rest) = bytes.split_at(SenderPublicKey::LEN);
        let (signature, secret) = rest.split_at(SenderSignature::LEN);
        Ok(Self {
            sender: SenderPublicKey::from_slice(sender).map_err(|_| SealError::MalformedEnvelope)?,
            signature: SenderSignature::from_slice(signature)?,
            plaintext: Plaintext::new(secret.to_vec()).map_err(|_| SealError::MalformedEnvelope)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(secret: &[u8]) -> SignedPlaintext {
        SignedPlaintext {
            sender: SenderPublicKey::from_slice(&[1; SenderPublicKey::LEN]).unwrap(),
            signature: SenderSignature::from_slice(&[2; SenderSignature::LEN]).unwrap(),
            plaintext: Plaintext::new(secret.to_vec()).unwrap(),
        }
    }

    #[test]
    fn roundtrips_and_lays_out_the_parts_in_order() {
        let signed = block(b"hunter2");
        let inner = signed.to_plaintext().unwrap();
        assert_eq!(inner.expose().len(), SIGNATURE_BLOCK_LEN + 7);
        assert_eq!(inner.expose()[0], 1);
        assert_eq!(inner.expose()[SenderPublicKey::LEN], 2);
        assert_eq!(&inner.expose()[SIGNATURE_BLOCK_LEN..], b"hunter2");
        assert_eq!(SignedPlaintext::parse(&inner).unwrap(), signed);
    }

    #[test]
    fn signed_secrets_have_a_smaller_limit() {
        assert!(block(&vec![7; MAX_SIGNED_PLAINTEXT_LEN]).to_plaintext().is_ok());
        assert_eq!(block(&vec![7; MAX_SIGNED_PLAINTEXT_LEN + 1]).to_plaintext(), Err(SealError::PlaintextTooLarge));
    }

    #[test]
    fn signed_message_binds_recipient_header_and_secret() {
        let plaintext = Plaintext::new(b"s".to_vec()).unwrap();
        let fpr = Fingerprint::from_array([3; 32]);
        let base = signed_message(&fpr, b"header", &plaintext);
        assert!(base.starts_with(SIGNED_MESSAGE_LABEL));
        assert_ne!(*signed_message(&Fingerprint::from_array([4; 32]), b"header", &plaintext), *base);
        assert_ne!(*signed_message(&fpr, b"headex", &plaintext), *base);
        assert_ne!(*signed_message(&fpr, b"header", &Plaintext::new(b"t".to_vec()).unwrap()), *base);
    }

    mod adversary {
        use super::*;

        #[test]
        fn a_block_without_a_secret_or_truncated_is_rejected() {
            let inner = block(b"x").to_plaintext().unwrap();
            for len in [1, SenderPublicKey::LEN, SIGNATURE_BLOCK_LEN - 1, SIGNATURE_BLOCK_LEN] {
                let cut = Plaintext::new(inner.expose()[..len].to_vec()).unwrap();
                assert_eq!(SignedPlaintext::parse(&cut), Err(SealError::MalformedEnvelope), "len {len}");
            }
        }

        #[test]
        fn debug_never_prints_the_secret() {
            let rendered = format!("{:?}", block(b"top secret"));
            assert!(!rendered.contains("top secret") && rendered.contains("redacted"));
        }
    }
}
