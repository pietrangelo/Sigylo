//! Browser shell. Wires the Sealing use cases to the RustCrypto suite and
//! exposes them to JavaScript. No logic of its own beyond translating types.
//!
//! Errors reach JavaScript as `Error` objects whose message is the stable
//! code of the [`SealError`] variant (e.g. `"NotAuthentic"`), which the UI
//! localizes.
//!
//! Known browser limit: once bytes are copied into a JS `Uint8Array` or
//! string, the garbage collector may keep copies we cannot wipe. Inside
//! Wasm memory every key and plaintext is zeroized on drop.
#![forbid(unsafe_code)]

use sealing::{
    Envelope, Fingerprint, LinkKey, Passphrase, Plaintext, RecipientPublicKey, RecipientSeed, SealError, Sealer,
};
use sealing_adapters::rustcrypto_suite;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn sealer() -> Sealer<'static> {
    Sealer::new(rustcrypto_suite())
}

fn js_error(error: SealError) -> JsError {
    JsError::new(&format!("{error:?}"))
}

fn passphrase(bytes: Option<Vec<u8>>) -> Result<Option<Passphrase>, SealError> {
    bytes.map(Passphrase::new).transpose()
}

/// A link-mode secret: the envelope goes to the relay, the key into the fragment.
#[wasm_bindgen]
#[derive(Debug)]
pub struct SealedLink {
    envelope: Vec<u8>,
    key: LinkKey,
}

#[wasm_bindgen]
impl SealedLink {
    #[wasm_bindgen(getter)]
    pub fn envelope(&self) -> Vec<u8> {
        self.envelope.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Vec<u8> {
        self.key.expose().to_vec()
    }
}

/// A fresh recipient key pair for request mode.
#[wasm_bindgen]
#[derive(Debug)]
pub struct NewRecipient {
    seed: RecipientSeed,
    public_key: RecipientPublicKey,
    fingerprint: Fingerprint,
}

#[wasm_bindgen]
impl NewRecipient {
    /// The private seed: stays in the recipient's own link.
    #[wasm_bindgen(getter)]
    pub fn seed(&self) -> Vec<u8> {
        self.seed.expose().to_vec()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> Vec<u8> {
        self.fingerprint.as_bytes().to_vec()
    }
}

#[wasm_bindgen(js_name = sealForLink)]
pub fn seal_for_link(plaintext: Vec<u8>, passphrase_utf8: Option<Vec<u8>>) -> Result<SealedLink, JsError> {
    let plaintext = Plaintext::new(plaintext).map_err(js_error)?;
    let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
    let (envelope, key) = sealer().seal_for_link(&plaintext, passphrase.as_ref()).map_err(js_error)?;
    Ok(SealedLink { envelope: envelope.to_bytes(), key })
}

#[wasm_bindgen(js_name = openLink)]
pub fn open_link(envelope: &[u8], key: Vec<u8>, passphrase_utf8: Option<Vec<u8>>) -> Result<Vec<u8>, JsError> {
    let key = Zeroizing::new(key);
    let key = LinkKey::from_slice(&key).map_err(js_error)?;
    let envelope = Envelope::parse(envelope).map_err(js_error)?;
    let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
    let plaintext = sealer().open_link(&envelope, &key, passphrase.as_ref()).map_err(js_error)?;
    Ok(plaintext.into_zeroizing().to_vec())
}

/// Lets the UI ask for the passphrase before the (possibly burning) read is used.
#[wasm_bindgen(js_name = envelopeNeedsPassphrase)]
pub fn envelope_needs_passphrase(envelope: &[u8]) -> Result<bool, JsError> {
    Ok(Envelope::parse(envelope).map_err(js_error)?.needs_passphrase())
}

#[wasm_bindgen(js_name = newRecipient)]
pub fn new_recipient() -> Result<NewRecipient, JsError> {
    let r = sealer().new_recipient().map_err(js_error)?;
    Ok(NewRecipient { seed: r.seed, public_key: r.public_key, fingerprint: r.fingerprint })
}

#[wasm_bindgen(js_name = sealForRecipient)]
pub fn seal_for_recipient(
    plaintext: Vec<u8>,
    public_key: &[u8],
    fingerprint: &[u8],
    passphrase_utf8: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let plaintext = Plaintext::new(plaintext).map_err(js_error)?;
    let public_key = RecipientPublicKey::from_slice(public_key).map_err(js_error)?;
    let fingerprint = Fingerprint::from_slice(fingerprint).map_err(js_error)?;
    let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
    let envelope =
        sealer().seal_for_recipient(&plaintext, &public_key, &fingerprint, passphrase.as_ref()).map_err(js_error)?;
    Ok(envelope.to_bytes())
}

#[wasm_bindgen(js_name = openAsRecipient)]
pub fn open_as_recipient(envelope: &[u8], seed: Vec<u8>, passphrase_utf8: Option<Vec<u8>>) -> Result<Vec<u8>, JsError> {
    let seed = Zeroizing::new(seed);
    let seed = RecipientSeed::from_slice(&seed).map_err(js_error)?;
    let envelope = Envelope::parse(envelope).map_err(js_error)?;
    let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
    let plaintext = sealer().open_as_recipient(&envelope, &seed, passphrase.as_ref()).map_err(js_error)?;
    Ok(plaintext.into_zeroizing().to_vec())
}

/// A random 128-bit id for a new secret or request.
#[wasm_bindgen(js_name = randomId)]
pub fn random_id() -> Result<Vec<u8>, JsError> {
    let mut id = vec![0u8; 16];
    sealing::application::Randomness::fill(&sealing_adapters::SystemRandomness, &mut id).map_err(js_error)?;
    Ok(id)
}
