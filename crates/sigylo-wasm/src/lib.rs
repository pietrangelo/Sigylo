//! Browser shell. Wires the Sealing use cases to the RustCrypto suite and
//! exposes them to JavaScript. No logic of its own beyond translating types.
//!
//! Errors reach JavaScript as `Error` objects whose message is the stable
//! code of the [`SealError`] variant (e.g. `"NotAuthentic"`), which the UI
//! localizes.
//!
//! Nothing secret stays in Wasm memory once a call returns:
//!
//! * keys, seeds, passphrases and plaintexts are zeroizing types, wiped on drop;
//! * they reach JavaScript through [`hand_over`], copied straight into a JS
//!   array, never as a `Vec<u8>` or a field of an exported struct, which
//!   wasm-bindgen would move or free without wiping;
//! * every export runs [`scrubbed`], which overwrites the dead stack frames
//!   where moving a key type leaves copies that `Zeroize` cannot reach.
//!
//! Known browser limit: once bytes are in a JS `Uint8Array` or string, the
//! garbage collector may keep copies we cannot wipe.
#![forbid(unsafe_code)]

use js_sys::{Array, Uint8Array};
use sealing::{
    Envelope, FileBytes, FileManifest, FileName, Fingerprint, LinkKey, Passphrase, Plaintext, RecipientPublicKey,
    RecipientSeed, SealError, SealedChunk, SealedFile, Sealer,
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

fn file_parts(name: String, contents: Vec<u8>) -> Result<(FileName, FileBytes), SealError> {
    let contents = FileBytes::new(contents)?;
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
) -> Result<SealedFileForRecipient, JsError> {
    scrubbed(|| {
        let (name, contents) = file_parts(name, contents).map_err(js_error)?;
        let public_key = RecipientPublicKey::from_slice(public_key).map_err(js_error)?;
        let fingerprint = Fingerprint::from_slice(fingerprint).map_err(js_error)?;
        let passphrase = passphrase(passphrase_utf8).map_err(js_error)?;
        let file = sealer()
            .seal_file_for_recipient(name, &contents, &public_key, &fingerprint, passphrase.as_ref())
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
