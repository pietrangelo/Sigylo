//! Browser shell. Wires the Sealing use cases to the RustCrypto suite and
//! exposes them to JavaScript. No logic of its own beyond translating types.
//!
//! Errors reach JavaScript as `Error` objects whose message is the stable
//! code of the [`SealError`] variant (e.g. `"NotAuthentic"`), which the UI
//! localizes.
//!
//! Nothing secret stays in Wasm memory once a call returns:
//!
//! * keys, seeds (recipient and sender), passphrases and plaintexts are
//!   zeroizing types, wiped on drop;
//! * they reach JavaScript through [`hand_over`], copied straight into a JS
//!   array, never as a `Vec<u8>` or a field of an exported struct, which
//!   wasm-bindgen would move or free without wiping;
//! * every export runs [`scrubbed`], which overwrites the dead stack frames
//!   where moving a key type leaves copies that `Zeroize` cannot reach.
//!
//! Known browser limit: once bytes are in a JS `Uint8Array` or string, the
//! garbage collector may keep copies we cannot wipe.
#![forbid(unsafe_code)]

use js_sys::Uint8Array;
use sealing::{
    Envelope, Fingerprint, LinkKey, Passphrase, Plaintext, RecipientPublicKey, RecipientSeed, SealError, Sealer,
    SenderCode, SenderPin, SenderSeed,
};
use sealing_adapters::rustcrypto_suite;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

/// Stack overwritten after each call. The deepest call (ML-DSA-65 key
/// expansion, whose secret vectors live on the stack) reaches about 290 KiB;
/// the rest is margin, well inside the 1 MiB Wasm stack.
/// `web/tests/engine-memory.test.ts` fails if a call ever outgrows it.
const SCRUB_LEN: usize = 512 * 1024;

fn sealer() -> Sealer<'static> {
    Sealer::new(rustcrypto_suite())
}

/// Runs `work` in its own stack frame, then overwrites the stack it used.
fn scrubbed<T>(work: impl FnOnce() -> T) -> T {
    let out = run(work);
    scrub_stack();
    out
}

#[inline(never)]
fn run<T>(work: impl FnOnce() -> T) -> T {
    work()
}

#[inline(never)]
fn scrub_stack() {
    let mut used = [0u8; SCRUB_LEN];
    used.zeroize();
    core::hint::black_box(&used);
}

/// Copies secret bytes straight from Wasm memory into a new JS array. The
/// Wasm side stays owned by a zeroizing type, which wipes it on drop.
fn hand_over(secret: &[u8]) -> Uint8Array {
    Uint8Array::from(secret)
}

fn js_error(error: SealError) -> JsError {
    JsError::new(&format!("{error:?}"))
}

fn passphrase(bytes: Option<Vec<u8>>) -> Result<Option<Passphrase>, SealError> {
    bytes.map(Passphrase::new).transpose()
}

fn sender_identity(bytes: Option<Vec<u8>>) -> Result<Option<SenderSeed>, SealError> {
    bytes.map(|bytes| SenderSeed::from_slice(&Zeroizing::new(bytes))).transpose()
}

/// A link-mode secret: the envelope goes to the relay, the key into the fragment.
#[wasm_bindgen]
#[derive(Debug)]
pub struct SealedLink {
    envelope: Vec<u8>,
    key: Uint8Array,
}

#[wasm_bindgen]
impl SealedLink {
    #[wasm_bindgen(getter)]
    pub fn envelope(&self) -> Vec<u8> {
        self.envelope.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Uint8Array {
        self.key.clone()
    }
}

/// A fresh recipient key pair for request mode.
#[wasm_bindgen]
#[derive(Debug)]
pub struct NewRecipient {
    seed: Uint8Array,
    public_key: Vec<u8>,
    fingerprint: Vec<u8>,
}

#[wasm_bindgen]
impl NewRecipient {
    /// The private seed: stays in the recipient's own link.
    #[wasm_bindgen(getter)]
    pub fn seed(&self) -> Uint8Array {
        self.seed.clone()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> Vec<u8> {
        self.fingerprint.clone()
    }
}

/// A fresh sender identity for signing answers to requests.
#[wasm_bindgen]
#[derive(Debug)]
pub struct NewSender {
    seed: Uint8Array,
    code: String,
}

#[wasm_bindgen]
impl NewSender {
    /// The private seed: stays on the sender's device.
    #[wasm_bindgen(getter)]
    pub fn seed(&self) -> Uint8Array {
        self.seed.clone()
    }

    /// The code the sender reads out to the recipient.
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }
}

/// An opened answer to a request.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Received {
    plaintext: Uint8Array,
    sender_code: Option<String>,
}

#[wasm_bindgen]
impl Received {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Uint8Array {
        self.plaintext.clone()
    }

    /// The code of the sender whose signature verified, or `undefined` if unsigned.
    #[wasm_bindgen(getter, js_name = senderCode)]
    pub fn sender_code(&self) -> Option<String> {
        self.sender_code.clone()
    }
}

#[wasm_bindgen(js_name = sealForLink)]
pub fn seal_for_link(plaintext: Vec<u8>, passphrase_utf8: Option<Vec<u8>>) -> Result<SealedLink, JsError> {
    scrubbed(|| {
        let plaintext = Plaintext::new(plaintext).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let (envelope, key) = sealer().seal_for_link(&plaintext, passphrase.as_ref()).map_err(js_error)?;
        Ok(SealedLink { envelope: envelope.to_bytes(), key: hand_over(key.expose()) })
    })
}

#[wasm_bindgen(js_name = openLink)]
pub fn open_link(envelope: &[u8], key: Vec<u8>, passphrase_utf8: Option<Vec<u8>>) -> Result<Uint8Array, JsError> {
    scrubbed(|| {
        let key = Zeroizing::new(key);
        let key = LinkKey::from_slice(&key).map_err(js_error)?;
        let envelope = Envelope::parse(envelope).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let plaintext = sealer().open_link(&envelope, &key, passphrase.as_ref()).map_err(js_error)?;
        Ok(hand_over(plaintext.expose()))
    })
}

/// Lets the UI ask for the passphrase before the (possibly burning) read is used.
#[wasm_bindgen(js_name = envelopeNeedsPassphrase)]
pub fn envelope_needs_passphrase(envelope: &[u8]) -> Result<bool, JsError> {
    Ok(Envelope::parse(envelope).map_err(js_error)?.needs_passphrase())
}

#[wasm_bindgen(js_name = newRecipient)]
pub fn new_recipient() -> Result<NewRecipient, JsError> {
    scrubbed(|| {
        let r = sealer().new_recipient().map_err(js_error)?;
        Ok(NewRecipient {
            seed: hand_over(r.seed.expose()),
            public_key: r.public_key.as_bytes().to_vec(),
            fingerprint: r.fingerprint.as_bytes().to_vec(),
        })
    })
}

#[wasm_bindgen(js_name = newSender)]
pub fn new_sender() -> Result<NewSender, JsError> {
    scrubbed(|| {
        let s = sealer().new_sender().map_err(js_error)?;
        Ok(NewSender { seed: hand_over(s.seed.expose()), code: s.fingerprint.code() })
    })
}

/// The code of a stored sender identity.
#[wasm_bindgen(js_name = senderCode)]
pub fn sender_code(seed: Vec<u8>) -> Result<String, JsError> {
    scrubbed(|| {
        let seed = SenderSeed::from_slice(&Zeroizing::new(seed)).map_err(js_error)?;
        Ok(sealer().sender_fingerprint(&seed).code())
    })
}

fn expected_sender(bytes: Option<Vec<u8>>) -> Result<Option<SenderPin>, SealError> {
    bytes.map(|bytes| SenderPin::from_slice(&bytes)).transpose()
}

/// The pin that makes a request accept only the sender with this `code`.
#[wasm_bindgen(js_name = senderPin)]
pub fn sender_pin(recipient_fingerprint: &[u8], code: &str) -> Result<Vec<u8>, JsError> {
    let recipient = Fingerprint::from_slice(recipient_fingerprint).map_err(js_error)?;
    let code = SenderCode::parse(code).map_err(js_error)?;
    Ok(sealer().sender_pin(&recipient, &code).as_bytes().to_vec())
}

/// Whether the sender with `sender_seed` is the one a request's pin expects.
#[wasm_bindgen(js_name = isExpectedSender)]
pub fn is_expected_sender(recipient_fingerprint: &[u8], pin: &[u8], sender_seed: Vec<u8>) -> Result<bool, JsError> {
    scrubbed(|| {
        let recipient = Fingerprint::from_slice(recipient_fingerprint).map_err(js_error)?;
        let pin = SenderPin::from_slice(pin).map_err(js_error)?;
        let seed = SenderSeed::from_slice(&Zeroizing::new(sender_seed)).map_err(js_error)?;
        Ok(sealer().is_expected_sender(&recipient, &pin, &seed))
    })
}

/// Seals an answer to a request; signed when `sender_seed` is given, and
/// refused with `UnexpectedSender` if `expected_sender` names someone else.
#[wasm_bindgen(js_name = sealForRecipient)]
pub fn seal_for_recipient(
    plaintext: Vec<u8>,
    public_key: &[u8],
    fingerprint: &[u8],
    passphrase_utf8: Option<Vec<u8>>,
    sender_seed: Option<Vec<u8>>,
    expected_sender: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    scrubbed(|| {
        let plaintext = Plaintext::new(plaintext).map_err(js_error)?;
        let public_key = RecipientPublicKey::from_slice(public_key).map_err(js_error)?;
        let fingerprint = Fingerprint::from_slice(fingerprint).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let sender = sender_identity(sender_seed).map_err(js_error)?;
        let pin = self::expected_sender(expected_sender).map_err(js_error)?;
        let envelope = sealer()
            .seal_for_recipient(
                &plaintext,
                &public_key,
                &fingerprint,
                passphrase.as_ref(),
                sender.as_ref(),
                pin.as_ref(),
            )
            .map_err(js_error)?;
        Ok(envelope.to_bytes())
    })
}

#[wasm_bindgen(js_name = openAsRecipient)]
pub fn open_as_recipient(
    envelope: &[u8],
    seed: Vec<u8>,
    passphrase_utf8: Option<Vec<u8>>,
    expected_sender: Option<Vec<u8>>,
) -> Result<Received, JsError> {
    scrubbed(|| {
        let pin = self::expected_sender(expected_sender).map_err(js_error)?;
        let seed = Zeroizing::new(seed);
        let seed = RecipientSeed::from_slice(&seed).map_err(js_error)?;
        let envelope = Envelope::parse(envelope).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let received =
            sealer().open_as_recipient(&envelope, &seed, passphrase.as_ref(), pin.as_ref()).map_err(js_error)?;
        Ok(Received {
            plaintext: hand_over(received.plaintext.expose()),
            sender_code: received.sender.map(|sender| sender.code()),
        })
    })
}
