use access::{ExportKey, KeyringKdf, KeyringKey};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

/// HKDF-SHA-512 (RFC 5869) from the 64-byte export key.
#[derive(Debug, Clone, Copy, Default)]
pub struct HkdfKeyringKdf;

impl KeyringKdf for HkdfKeyringKdf {
    fn derive(&self, export_key: &ExportKey, info: &[u8]) -> KeyringKey {
        let mut out = Zeroizing::new([0u8; KeyringKey::LEN]);
        Hkdf::<Sha512>::new(None, export_key.expose())
            .expand(info, &mut *out)
            .expect("32 bytes is a valid HKDF-SHA-512 output length");
        KeyringKey::from_array(*out)
    }
}
