use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Payload},
};
use sealing::{SealError, SymmetricKey, application::Aead, core::Nonce};
use zeroize::Zeroizing;

/// XChaCha20-Poly1305: 256-bit key, 192-bit random nonce, 128-bit tag.
#[derive(Debug, Clone, Copy, Default)]
pub struct XChaCha20Poly1305Aead;

fn cipher(key: &SymmetricKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&(*key.expose()).into())
}

impl Aead for XChaCha20Poly1305Aead {
    fn seal(&self, key: &SymmetricKey, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        cipher(key)
            .encrypt(&XNonce::from(*nonce.as_bytes()), Payload { msg: plaintext, aad })
            // Only fails for messages beyond 256 GiB; Plaintext caps far below.
            .expect("plaintext within XChaCha20-Poly1305 limits")
    }

    fn open(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        cipher(key)
            .decrypt(&XNonce::from(*nonce.as_bytes()), Payload { msg: ciphertext, aad })
            .map(Zeroizing::new)
            .map_err(|_| SealError::NotAuthentic)
    }
}
