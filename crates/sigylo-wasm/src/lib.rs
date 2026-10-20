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
//! * keys, seeds (recipient and sender), passphrases, passwords and
//!   plaintexts are zeroizing types, wiped on drop; a registration or login
//!   in progress keeps its password and OPAQUE state only until it is
//!   finished or freed;
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
use js_sys::{Array, Uint8Array};
use sealing::{
    Envelope, FileBytes, FileManifest, FileName, Fingerprint, LinkKey, Passphrase, Plaintext, RecipientPublicKey,
    RecipientSeed, SealError, SealedChunk, SealedFile, Sealer, SenderCode, SenderPin, SenderSeed,
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

/// A secret argument under a wiping owner. Every export guards all of its
/// secret arguments first: refusing any argument then drops the others
/// through `Zeroizing`, never as a plain `Vec` freed unwiped.
fn guarded(bytes: Vec<u8>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes)
}

/// Moves a guarded buffer, without copying it, into a value object that
/// wipes it from then on.
fn release(guarded: &mut Zeroizing<Vec<u8>>) -> Vec<u8> {
    core::mem::take(&mut **guarded)
}

fn passphrase(bytes: Option<Zeroizing<Vec<u8>>>) -> Result<Option<Passphrase>, SealError> {
    bytes.map(|mut bytes| Passphrase::new(release(&mut bytes))).transpose()
}

fn sender_identity(bytes: Option<Zeroizing<Vec<u8>>>) -> Result<Option<SenderSeed>, SealError> {
    bytes.map(|bytes| SenderSeed::from_slice(&bytes)).transpose()
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
        let (mut plaintext, passphrase_utf8) = (guarded(plaintext), passphrase_utf8.map(guarded));
        let plaintext = Plaintext::new(release(&mut plaintext)).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let (envelope, key) = sealer().seal_for_link(&plaintext, passphrase.as_ref()).map_err(js_error)?;
        Ok(SealedLink { envelope: envelope.to_bytes(), key: hand_over(key.expose()) })
    })
}

#[wasm_bindgen(js_name = openLink)]
pub fn open_link(envelope: &[u8], key: Vec<u8>, passphrase_utf8: Option<Vec<u8>>) -> Result<Uint8Array, JsError> {
    scrubbed(|| {
        let (key, passphrase_utf8) = (guarded(key), passphrase_utf8.map(guarded));
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
        let seed = SenderSeed::from_slice(&guarded(seed)).map_err(js_error)?;
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
        let sender_seed = guarded(sender_seed);
        let recipient = Fingerprint::from_slice(recipient_fingerprint).map_err(js_error)?;
        let pin = SenderPin::from_slice(pin).map_err(js_error)?;
        let seed = SenderSeed::from_slice(&sender_seed).map_err(js_error)?;
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
        let (mut plaintext, passphrase_utf8, sender_seed) =
            (guarded(plaintext), passphrase_utf8.map(guarded), sender_seed.map(guarded));
        let plaintext = Plaintext::new(release(&mut plaintext)).map_err(js_error)?;
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
        let (seed, passphrase_utf8) = (guarded(seed), passphrase_utf8.map(guarded));
        let pin = self::expected_sender(expected_sender).map_err(js_error)?;
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

#[wasm_bindgen(js_name = sealWithKey)]
pub fn seal_with_key(plaintext: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, JsError> {
    scrubbed(|| {
        let (mut plaintext, key) = (guarded(plaintext), guarded(key));
        let plaintext = Plaintext::new(release(&mut plaintext)).map_err(js_error)?;
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

/// An OPAQUE state between two round trips. It lives on the heap from the
/// moment it is made, inside [`scrubbed`], so only a pointer moves through
/// the outer frames; taking it overwrites it there with zeros, because
/// wasm-bindgen frees the exported struct without wiping it and a move
/// leaves the old bytes behind. `N` words cover the state (checked below).
enum Slot<S, const N: usize> {
    Ready(S),
    Wiped([u64; N]),
}

struct Pending<S, const N: usize>(Box<Slot<S, N>>);

impl<S, const N: usize> Pending<S, N> {
    const COVERS_THE_STATE: () = assert!(N * 8 >= core::mem::size_of::<S>());

    fn new(state: S) -> Self {
        let () = Self::COVERS_THE_STATE;
        Self(Box::new(Slot::Ready(state)))
    }

    /// The state, once: the slot is left all zeros.
    fn take(&mut self) -> Option<S> {
        match core::mem::replace(&mut *self.0, Slot::Wiped([0; N])) {
            Slot::Ready(state) => Some(state),
            Slot::Wiped(_) => None,
        }
    }

    #[cfg(test)]
    fn is_wiped(&self) -> bool {
        matches!(&*self.0, Slot::Wiped(words) if words.iter().all(|w| *w == 0))
    }
}

impl<S, const N: usize> core::fmt::Debug for Pending<S, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Pending(redacted)")
    }
}

type RegistrationState = PendingRegistration<<OpaqueDevice as access::OpaqueClient>::Registration>;
type LoginState = PendingLogin<<OpaqueDevice as access::OpaqueClient>::Login>;
type PendingRegistrationSlot = Pending<RegistrationState, { core::mem::size_of::<RegistrationState>().div_ceil(8) }>;
type PendingLoginSlot = Pending<LoginState, { core::mem::size_of::<LoginState>().div_ceil(8) }>;

/// A registration waiting for the relay's answer.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Registration {
    request: Vec<u8>,
    pending: PendingRegistrationSlot,
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
        scrubbed(|| {
            let pending = self.pending.take().ok_or_else(|| access_error(AccessError::NotAuthentic))?;
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
        Ok(Registration { request: request.as_bytes().to_vec(), pending: Pending::new(pending) })
    })
}

/// A login waiting for the relay's answer.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Login {
    request: Vec<u8>,
    pending: PendingLoginSlot,
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
        scrubbed(|| {
            let pending = self.pending.take().ok_or_else(|| access_error(AccessError::NotAuthentic))?;
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
        Ok(Login { request: request.as_bytes().to_vec(), pending: Pending::new(pending) })
    })
}

/// A file sealed for a link: the manifest envelope is deposited first, then
/// each chunk in order; the key goes into the fragment.
#[wasm_bindgen]
#[derive(Debug)]
pub struct SealedFileLink {
    envelope: Vec<u8>,
    key: Uint8Array,
    chunks: Array,
}

#[wasm_bindgen]
impl SealedFileLink {
    #[wasm_bindgen(getter)]
    pub fn envelope(&self) -> Vec<u8> {
        self.envelope.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Uint8Array {
        self.key.clone()
    }

    /// The sealed chunks, in order, as `Uint8Array`s.
    #[wasm_bindgen(getter)]
    pub fn chunks(&self) -> Array {
        self.chunks.clone()
    }
}

/// A file sealed to a recipient's public key.
#[wasm_bindgen]
#[derive(Debug)]
pub struct SealedFileForRecipient {
    envelope: Vec<u8>,
    chunks: Array,
}

#[wasm_bindgen]
impl SealedFileForRecipient {
    #[wasm_bindgen(getter)]
    pub fn envelope(&self) -> Vec<u8> {
        self.envelope.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn chunks(&self) -> Array {
        self.chunks.clone()
    }
}

/// What an opened secret says about the file it stands for.
#[wasm_bindgen]
#[derive(Debug)]
pub struct FileInfo {
    name: String,
    size: u32,
    chunks: u32,
}

#[wasm_bindgen]
impl FileInfo {
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> u32 {
        self.size
    }

    #[wasm_bindgen(getter)]
    pub fn chunks(&self) -> u32 {
        self.chunks
    }
}

fn chunk_array(chunks: Vec<SealedChunk>) -> Array {
    chunks.into_iter().map(|chunk| JsValue::from(Uint8Array::from(chunk.as_bytes()))).collect()
}

fn file_parts(name: String, mut contents: Zeroizing<Vec<u8>>) -> Result<(FileName, FileBytes), SealError> {
    let contents = FileBytes::new(release(&mut contents))?;
    Ok((FileName::new(name)?, contents))
}

/// The manifest inside an opened secret, `None` for a text. Takes the bytes
/// by value so they are wiped once read.
fn manifest(plaintext: Vec<u8>) -> Result<Option<FileManifest>, SealError> {
    FileManifest::recognize(&Plaintext::new(plaintext)?)
}

/// `name` must be NFC-normalized by the caller.
#[wasm_bindgen(js_name = sealFileForLink)]
pub fn seal_file_for_link(
    name: String,
    contents: Vec<u8>,
    passphrase_utf8: Option<Vec<u8>>,
) -> Result<SealedFileLink, JsError> {
    scrubbed(|| {
        let (contents, passphrase_utf8) = (guarded(contents), passphrase_utf8.map(guarded));
        let (name, contents) = file_parts(name, contents).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let (file, key) = sealer().seal_file_for_link(name, &contents, passphrase.as_ref()).map_err(js_error)?;
        let SealedFile { manifest, chunks } = file;
        Ok(SealedFileLink { envelope: manifest.to_bytes(), key: hand_over(key.expose()), chunks: chunk_array(chunks) })
    })
}

#[wasm_bindgen(js_name = sealFileForRecipient)]
pub fn seal_file_for_recipient(
    name: String,
    contents: Vec<u8>,
    public_key: &[u8],
    fingerprint: &[u8],
    passphrase_utf8: Option<Vec<u8>>,
    sender_seed: Option<Vec<u8>>,
    expected_sender: Option<Vec<u8>>,
) -> Result<SealedFileForRecipient, JsError> {
    scrubbed(|| {
        let (contents, passphrase_utf8, sender_seed) =
            (guarded(contents), passphrase_utf8.map(guarded), sender_seed.map(guarded));
        let (name, contents) = file_parts(name, contents).map_err(js_error)?;
        let public_key = RecipientPublicKey::from_slice(public_key).map_err(js_error)?;
        let fingerprint = Fingerprint::from_slice(fingerprint).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let sender = sender_identity(sender_seed).map_err(js_error)?;
        let pin = self::expected_sender(expected_sender).map_err(js_error)?;
        let file = sealer()
            .seal_file_for_recipient(
                name,
                &contents,
                &public_key,
                &fingerprint,
                passphrase.as_ref(),
                sender.as_ref(),
                pin.as_ref(),
            )
            .map_err(js_error)?;
        Ok(SealedFileForRecipient { envelope: file.manifest.to_bytes(), chunks: chunk_array(file.chunks) })
    })
}

/// Name, size and chunk count of the file an opened secret stands for, or
/// `undefined` when the secret is a text.
#[wasm_bindgen(js_name = fileInfo)]
pub fn file_info(plaintext: Vec<u8>) -> Result<Option<FileInfo>, JsError> {
    scrubbed(|| {
        Ok(manifest(plaintext).map_err(js_error)?.map(|m| FileInfo {
            name: m.name().as_str().to_owned(),
            // MAX_FILE_LEN fits in u32.
            size: m.size().bytes() as u32,
            chunks: m.size().chunk_count(),
        }))
    })
}

/// Opens the chunks of a file with the manifest from its opened secret.
#[wasm_bindgen(js_name = openFile)]
pub fn open_file(plaintext: Vec<u8>, chunks: Array) -> Result<Uint8Array, JsError> {
    scrubbed(|| {
        let manifest = manifest(plaintext).map_err(js_error)?.ok_or(SealError::MalformedEnvelope).map_err(js_error)?;
        let chunks = chunks
            .iter()
            .map(|chunk| {
                SealedChunk::new(chunk.dyn_into::<Uint8Array>().map_err(|_| SealError::MalformedEnvelope)?.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(js_error)?;
        let contents = sealer().open_file(&manifest, &chunks).map_err(js_error)?;
        Ok(hand_over(contents.expose()))
    })
}

#[cfg(test)]
mod tests {
    mod adversary {
        use crate::{begin_login, begin_registration};

        // wasm-bindgen keeps an exported struct in a heap cell that it frees
        // without wiping, and a move leaves the old bytes behind: the OPRF
        // blind and the ephemeral key must not stay there once taken.

        #[test]
        fn a_taken_login_state_is_overwritten_where_it_was_kept() {
            let mut login = begin_login(b"correct horse battery".to_vec()).unwrap();
            assert!(login.pending.take().is_some());
            assert!(login.pending.is_wiped());
            assert!(login.pending.take().is_none(), "a login state works once");
        }

        #[test]
        fn a_taken_registration_state_is_overwritten_where_it_was_kept() {
            let mut registration = begin_registration(b"correct horse battery".to_vec()).unwrap();
            assert!(registration.pending.take().is_some());
            assert!(registration.pending.is_wiped());
            assert!(registration.pending.take().is_none());
        }
    }
}
