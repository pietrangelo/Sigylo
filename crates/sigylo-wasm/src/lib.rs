//! Browser shell. Wires the Sealing use cases to the RustCrypto suite and
//! the Access member use cases to OPAQUE, and exposes them to JavaScript.
//! No logic of its own beyond translating types.
//!
//! Errors reach JavaScript as `Error` objects whose message is the stable
//! code of the [`SealError`] or [`AccessError`] variant (e.g.
//! `"NotAuthentic"`), which the UI localizes.
//!
//! Nothing secret stays in Wasm memory once a call returns:
//!
//! * keys, seeds, passphrases, passwords and plaintexts are zeroizing types,
//!   wiped on drop; a registration or login in progress keeps its password
//!   and OPAQUE state only until it is finished or freed;
//! * they reach JavaScript through [`hand_over`], copied straight into a JS
//!   array, never as a `Vec<u8>` or a field of an exported struct, which
//!   wasm-bindgen would move or free without wiping;
//! * every export runs [`scrubbed`], which overwrites the dead stack frames
//!   where moving a key type leaves copies that `Zeroize` cannot reach.
//!
//! Known browser limit: once bytes are in a JS `Uint8Array` or string, the
//! garbage collector may keep copies we cannot wipe.
#![forbid(unsafe_code)]

use access::{
    AccessError, CredentialResponse, Member, Password, PendingLogin, PendingRegistration, RegistrationResponse,
};
use access_adapters::{HkdfKeyringKdf, OpaqueDevice};
use js_sys::Uint8Array;
use sealing::{
    Envelope, Fingerprint, LinkKey, Passphrase, Plaintext, RecipientPublicKey, RecipientSeed, SealError, Sealer,
};
use sealing_adapters::rustcrypto_suite;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

/// Stack overwritten after each call. The deepest call (ML-KEM-768 key
/// generation) uses about 10 KiB; the rest is margin.
const SCRUB_LEN: usize = 64 * 1024;

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

#[wasm_bindgen(js_name = sealForRecipient)]
pub fn seal_for_recipient(
    plaintext: Vec<u8>,
    public_key: &[u8],
    fingerprint: &[u8],
    passphrase_utf8: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    scrubbed(|| {
        let plaintext = Plaintext::new(plaintext).map_err(js_error)?;
        let public_key = RecipientPublicKey::from_slice(public_key).map_err(js_error)?;
        let fingerprint = Fingerprint::from_slice(fingerprint).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let envelope = sealer()
            .seal_for_recipient(&plaintext, &public_key, &fingerprint, passphrase.as_ref())
            .map_err(js_error)?;
        Ok(envelope.to_bytes())
    })
}

#[wasm_bindgen(js_name = openAsRecipient)]
pub fn open_as_recipient(
    envelope: &[u8],
    seed: Vec<u8>,
    passphrase_utf8: Option<Vec<u8>>,
) -> Result<Uint8Array, JsError> {
    scrubbed(|| {
        let seed = Zeroizing::new(seed);
        let seed = RecipientSeed::from_slice(&seed).map_err(js_error)?;
        let envelope = Envelope::parse(envelope).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let plaintext = sealer().open_as_recipient(&envelope, &seed, passphrase.as_ref()).map_err(js_error)?;
        Ok(hand_over(plaintext.expose()))
    })
}

#[wasm_bindgen(js_name = sealWithKey)]
pub fn seal_with_key(plaintext: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, JsError> {
    scrubbed(|| {
        let plaintext = Plaintext::new(plaintext).map_err(js_error)?;
        let key = Zeroizing::new(key);
        let key = LinkKey::from_slice(&key).map_err(js_error)?;
        Ok(sealer().seal_with_link_key(&plaintext, &key).map_err(js_error)?.to_bytes())
    })
}

// --- Accounts (OPAQUE). The password never leaves this module.

type Device = Member<OpaqueDevice, HkdfKeyringKdf>;

fn device() -> Device {
    Member::new(OpaqueDevice, HkdfKeyringKdf)
}

fn access_error(error: AccessError) -> JsError {
    JsError::new(&format!("{error:?}"))
}

/// A registration waiting for the relay's answer.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Registration {
    request: Vec<u8>,
    pending: Option<PendingRegistration<<OpaqueDevice as access::OpaqueClient>::Registration>>,
}

/// What a finished registration or login hands back: the message for the
/// relay, and the keyring key that stays on this device.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Admission {
    message: Vec<u8>,
    keyring_key: Uint8Array,
}

#[wasm_bindgen]
impl Admission {
    /// The registration record, or KE3: goes to the relay.
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    #[wasm_bindgen(getter, js_name = keyringKey)]
    pub fn keyring_key(&self) -> Uint8Array {
        self.keyring_key.clone()
    }
}

#[wasm_bindgen]
impl Registration {
    /// The blinded password: goes to the relay.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    pub fn finish(&mut self, response: &[u8]) -> Result<Admission, JsError> {
        let pending = self.pending.take().ok_or_else(|| access_error(AccessError::NotAuthentic))?;
        scrubbed(|| {
            let response = RegistrationResponse::from_slice(response).map_err(access_error)?;
            let (record, key) = device().finish_registration(pending, &response).map_err(access_error)?;
            Ok(Admission { message: record.as_bytes().to_vec(), keyring_key: hand_over(key.expose()) })
        })
    }
}

#[wasm_bindgen(js_name = beginRegistration)]
pub fn begin_registration(password_utf8: Vec<u8>) -> Result<Registration, JsError> {
    scrubbed(|| {
        let password = Password::new(password_utf8).map_err(access_error)?;
        let (request, pending) = device().begin_registration(password).map_err(access_error)?;
        Ok(Registration { request: request.as_bytes().to_vec(), pending: Some(pending) })
    })
}

/// A login waiting for the relay's answer.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Login {
    request: Vec<u8>,
    pending: Option<PendingLogin<<OpaqueDevice as access::OpaqueClient>::Login>>,
}

#[wasm_bindgen]
impl Login {
    /// KE1: goes to the relay.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    /// Fails with `NotAuthentic` on a wrong password or an unknown user.
    pub fn finish(&mut self, response: &[u8]) -> Result<Admission, JsError> {
        let pending = self.pending.take().ok_or_else(|| access_error(AccessError::NotAuthentic))?;
        scrubbed(|| {
            let response = CredentialResponse::from_slice(response).map_err(access_error)?;
            let (finalization, key) = device().finish_login(pending, &response).map_err(access_error)?;
            Ok(Admission { message: finalization.as_bytes().to_vec(), keyring_key: hand_over(key.expose()) })
        })
    }
}

#[wasm_bindgen(js_name = beginLogin)]
pub fn begin_login(password_utf8: Vec<u8>) -> Result<Login, JsError> {
    scrubbed(|| {
        let password = Password::new(password_utf8).map_err(access_error)?;
        let (request, pending) = device().begin_login(password).map_err(access_error)?;
        Ok(Login { request: request.as_bytes().to_vec(), pending: Some(pending) })
    })
}
