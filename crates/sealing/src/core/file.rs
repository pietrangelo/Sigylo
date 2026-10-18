//! Files, sealed in chunks.
//!
//! A file travels as two things. The **manifest** is an ordinary secret,
//! sealed in a v1 [`super::Envelope`] by link or by request, with or without
//! a passphrase, exactly like a text. It carries a fresh random key for this
//! one file, the file's size and its name. The **chunks** are the file itself,
//! cut in pieces of [`CHUNK_LEN`] and sealed with that key, so the relay can
//! take and hand them out one request at a time.
//!
//! ```text
//! manifest plaintext
//! offset  size  field
//! 0       5     magic 0xFF "SGYF" (0xFF never occurs in UTF-8: no text starts like this)
//! 5       1     version (1)
//! 6       32    file key
//! 38      8     file size in bytes, u64 BE (1 ..= MAX_FILE_LEN)
//! 46      1     name length n (1 ..= 255)
//! 47      n     name, UTF-8
//!
//! chunk i of n   XChaCha20-Poly1305, key = HKDF-SHA3-256(salt "sigylo/v1", file key, "sigylo/v1/chunk")
//! nonce          "SGYC" || i (u32 BE) || 16 zero bytes   (one key per file: positions never repeat)
//! aad            "SGYC" || version 1 || i (u32 BE) || n (u32 BE)
//! plaintext      CHUNK_LEN bytes of the file; the last chunk is zero-padded to
//!                a power of two of at least 256 bytes
//! ```
//!
//! Index and count are authenticated in every chunk, so the relay cannot
//! reorder, drop, duplicate or truncate chunks, nor swap in a chunk of
//! another file (which has another key), without opening failing.

use core::fmt;
use core::ops::Range;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{FileKey, Nonce, Plaintext, SealError, TAG_LEN};

/// Plaintext bytes in every chunk but the last.
pub const CHUNK_LEN: usize = 1024 * 1024;
/// Largest file accepted: 10 MiB, so at most [`MAX_CHUNKS`] chunks.
pub const MAX_FILE_LEN: usize = 10 * CHUNK_LEN;
/// Most chunks a file can have.
pub const MAX_CHUNKS: u32 = (MAX_FILE_LEN / CHUNK_LEN) as u32;
/// Longest file name, in UTF-8 bytes.
pub const MAX_NAME_LEN: usize = 255;

const MANIFEST_MAGIC: &[u8; 5] = b"\xFFSGYF";
const CHUNK_MAGIC: &[u8; 4] = b"SGYC";
const VERSION: u8 = 1;
const MIN_PADDED: usize = 256;
const FIXED_LEN: usize = MANIFEST_MAGIC.len() + 1 + FileKey::LEN + 8 + 1;

/// The name a file is saved under. It is shown to the recipient and handed
/// to their browser, so it may not hide anything: no path separators, no
/// control characters, no invisible or bidirectional formatting characters
/// that could make `invoice\u{202E}fdp.exe` look like `invoiceexe.pdf`, no
/// characters that draw a blank (U+2800, private use…), runs of spaces or
/// blanks that push the real extension out of sight, piles of combining
/// marks that strike it through, and nothing Windows would refuse or rewrite
/// on saving (`<>:"|?*`, a trailing dot or space, device names such as
/// `CON`, `nul.txt`, `CON .txt` or `COM¹`).
#[derive(Clone, PartialEq, Eq)]
pub struct FileName(String);

impl FileName {
    /// The shell is expected to normalize to Unicode NFC before handing it over.
    pub fn new(name: String) -> Result<Self, SealError> {
        let acceptable = !name.is_empty()
            && name.len() <= MAX_NAME_LEN
            && name != "."
            && name != ".."
            && !name.chars().any(forbidden)
            && !has_blank_run(&name)
            && !has_mark_pile(&name)
            && !name.starts_with(' ')
            && !name.ends_with([' ', '.'])
            && !is_device_name(&name);
        if acceptable { Ok(Self(name)) } else { Err(SealError::InvalidFileName) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Most combining marks one character may carry: enough for the ordinary
/// writing of any script, too few to stack an overlay across the name.
const MAX_MARKS_PER_BASE: usize = 2;

fn forbidden(c: char) -> bool {
    matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*')
        || c.is_control()
        || (c.is_whitespace() && c != ' ')
        || is_invisible(c)
        || is_blank_glyph(c)
}

/// Format characters (Unicode category Cf), line and paragraph separators,
/// and the characters that draw nothing: Hangul fillers, the combining
/// grapheme joiner, variation selectors and tags.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{00AD}' | '\u{034F}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
        | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{115F}'..='\u{1160}' | '\u{17B4}'..='\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{206F}'
        | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}' | '\u{FFF0}'..='\u{FFFB}'
        | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}')
}

/// Visible characters by category that still draw a blank: the empty
/// braille pattern, the null notehead, the object replacement character,
/// and private-use characters, which most fonts leave empty.
fn is_blank_glyph(c: char) -> bool {
    matches!(c, '\u{2800}' | '\u{1D159}' | '\u{FFFC}' | '\u{E000}'..='\u{F8FF}'
        | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}')
}

/// Whitespace, or anything that draws nothing where a letter could be.
fn is_blank(c: char) -> bool {
    c.is_whitespace() || is_invisible(c) || is_blank_glyph(c)
}

/// Two blanks in a row, whatever their mix: a run pushes the real extension
/// out of sight.
fn has_blank_run(name: &str) -> bool {
    let mut previous = false;
    name.chars().any(|c| {
        let blank = is_blank(c);
        let run = blank && previous;
        previous = blank;
        run
    })
}

/// More than [`MAX_MARKS_PER_BASE`] combining marks in a row.
fn has_mark_pile(name: &str) -> bool {
    let mut marks = 0;
    name.chars().any(|c| {
        marks = if is_combining_mark(c) { marks + 1 } else { 0 };
        marks > MAX_MARKS_PER_BASE
    })
}

/// Nonspacing and enclosing marks of the generic combining blocks (where
/// overlays such as U+0336 live) and of the scripts that stack marks most:
/// Cyrillic, Hebrew, Arabic, Devanagari and Thai.
fn is_combining_mark(c: char) -> bool {
    matches!(c, '\u{0300}'..='\u{036F}' | '\u{0483}'..='\u{0489}' | '\u{0591}'..='\u{05BD}' | '\u{05BF}'
        | '\u{05C1}'..='\u{05C2}' | '\u{05C4}'..='\u{05C5}' | '\u{05C7}' | '\u{0610}'..='\u{061A}'
        | '\u{064B}'..='\u{065F}' | '\u{0670}' | '\u{06D6}'..='\u{06DC}' | '\u{06DF}'..='\u{06E4}'
        | '\u{06E7}'..='\u{06E8}' | '\u{06EA}'..='\u{06ED}' | '\u{0900}'..='\u{0902}' | '\u{093A}' | '\u{093C}'
        | '\u{0941}'..='\u{0948}' | '\u{094D}' | '\u{0951}'..='\u{0957}' | '\u{0962}'..='\u{0963}' | '\u{0E31}'
        | '\u{0E34}'..='\u{0E3A}' | '\u{0E47}'..='\u{0E4E}' | '\u{1AB0}'..='\u{1AFF}' | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20FF}' | '\u{2DE0}'..='\u{2DFF}' | '\u{A66F}'..='\u{A672}' | '\u{A674}'..='\u{A67D}'
        | '\u{FE20}'..='\u{FE2F}')
}

/// `CON`, `nul.txt`, `Lpt1.pdf`, `CON .txt`, `COM¹`, `CONIN$`…: Windows maps
/// these to devices whatever the extension, once the spaces and dots that
/// end the stem are dropped. Microsoft lists `COM0`–`COM9` and `COM¹²³`, and
/// the same for `LPT`.
fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches([' ', '.']).to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            let port = stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT")).unwrap_or_default();
            let mut digits = port.chars();
            matches!((digits.next(), digits.next()), (Some('0'..='9' | '\u{00B9}' | '\u{00B2}' | '\u{00B3}'), None))
        }
    }
}

impl fmt::Debug for FileName {
    // A name can say a lot about what is being shared: keep it out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileName(redacted, {} bytes)", self.0.len())
    }
}

/// The contents of a file, before sealing or after opening.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FileBytes(Vec<u8>);

impl FileBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SealError> {
        let value = Self(bytes);
        if value.0.is_empty() {
            return Err(SealError::PlaintextEmpty);
        }
        if value.0.len() > MAX_FILE_LEN {
            return Err(SealError::FileTooLarge);
        }
        Ok(value)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn size(&self) -> FileSize {
        FileSize(self.0.len() as u64)
    }
}

impl fmt::Debug for FileBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileBytes(redacted, {} bytes)", self.0.len())
    }
}

/// A file size from 1 byte to [`MAX_FILE_LEN`], and the chunks it makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSize(u64);

impl FileSize {
    pub fn new(bytes: u64) -> Result<Self, SealError> {
        if bytes == 0 || bytes > MAX_FILE_LEN as u64 { Err(SealError::FileTooLarge) } else { Ok(Self(bytes)) }
    }

    pub fn bytes(&self) -> u64 {
        self.0
    }

    pub fn chunk_count(&self) -> u32 {
        self.0.div_ceil(CHUNK_LEN as u64) as u32
    }

    /// Every chunk of the file, in order.
    pub fn chunks(&self) -> impl ExactSizeIterator<Item = ChunkPosition> + use<> {
        let (size, count) = (self.0 as usize, self.chunk_count());
        (0..count).map(move |index| {
            let start = index as usize * CHUNK_LEN;
            ChunkPosition { index, count, bytes: start..size.min(start + CHUNK_LEN) }
        })
    }
}

/// Where a chunk sits in its file. Its nonce and associated data come from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPosition {
    index: u32,
    count: u32,
    bytes: Range<usize>,
}

impl ChunkPosition {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    /// The bytes of the file this chunk carries.
    pub fn bytes(&self) -> Range<usize> {
        self.bytes.clone()
    }

    /// Length of the padded plaintext: a power of two, at least 256 bytes.
    pub fn padded_len(&self) -> usize {
        self.bytes.len().max(MIN_PADDED).next_power_of_two()
    }

    /// Length of the sealed chunk, tag included.
    pub fn sealed_len(&self) -> usize {
        self.padded_len() + TAG_LEN
    }

    pub fn nonce(&self) -> Nonce {
        let mut nonce = [0u8; Nonce::LEN];
        nonce[..4].copy_from_slice(CHUNK_MAGIC);
        nonce[4..8].copy_from_slice(&self.index.to_be_bytes());
        Nonce::from_array(nonce)
    }

    pub fn associated_data(&self) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[..4].copy_from_slice(CHUNK_MAGIC);
        aad[4] = VERSION;
        aad[5..9].copy_from_slice(&self.index.to_be_bytes());
        aad[9..].copy_from_slice(&self.count.to_be_bytes());
        aad
    }

    /// The chunk's share of the file, zero-padded.
    pub fn pad(&self, file: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.padded_len()));
        out.extend_from_slice(&file[self.bytes()]);
        out.resize(self.padded_len(), 0);
        out
    }

    /// The file bytes inside an opened chunk. Padding must be exactly zeros.
    pub fn unpad<'a>(&self, padded: &'a [u8]) -> Result<&'a [u8], SealError> {
        let len = self.bytes.len();
        if padded.len() != self.padded_len() || padded[len..].iter().any(|&b| b != 0) {
            return Err(SealError::MalformedEnvelope);
        }
        Ok(&padded[..len])
    }
}

/// A chunk as it travels: opaque ciphertext with its tag.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedChunk(Vec<u8>);

impl SealedChunk {
    pub const MAX_LEN: usize = CHUNK_LEN + TAG_LEN;

    pub fn new(bytes: Vec<u8>) -> Result<Self, SealError> {
        if (MIN_PADDED + TAG_LEN..=Self::MAX_LEN).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(SealError::MalformedEnvelope)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SealedChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedChunk({} bytes)", self.0.len())
    }
}

/// What the recipient needs to fetch and open a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileManifest {
    key: FileKey,
    size: FileSize,
    name: FileName,
}

impl FileManifest {
    pub fn new(key: FileKey, size: FileSize, name: FileName) -> Self {
        Self { key, size, name }
    }

    pub fn key(&self) -> &FileKey {
        &self.key
    }

    pub fn size(&self) -> FileSize {
        self.size
    }

    pub fn name(&self) -> &FileName {
        &self.name
    }

    /// The manifest as a secret, ready to be sealed like any other.
    pub fn to_plaintext(&self) -> Plaintext {
        let name = self.name.as_str().as_bytes();
        // Exact capacity: no reallocation leaves a copy of the key behind.
        let mut out = Vec::with_capacity(FIXED_LEN + name.len());
        out.extend_from_slice(MANIFEST_MAGIC);
        out.push(VERSION);
        out.extend_from_slice(self.key.expose());
        out.extend_from_slice(&self.size.0.to_be_bytes());
        // FileName caps the length at 255.
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        Plaintext::new(out).expect("a manifest is far below the plaintext limit")
    }

    /// Tells an opened secret apart: `None` for a text, the manifest for a
    /// file. A secret that starts like a manifest but is not a canonical one
    /// is refused.
    pub fn recognize(plaintext: &Plaintext) -> Result<Option<Self>, SealError> {
        let bytes = plaintext.expose();
        if !bytes.starts_with(MANIFEST_MAGIC) {
            return Ok(None);
        }
        let malformed = SealError::MalformedEnvelope;
        let fixed = bytes.get(..FIXED_LEN).ok_or(malformed)?;
        if fixed[5] != VERSION {
            return Err(malformed);
        }
        let key = FileKey::from_slice(&fixed[6..38])?;
        let size = FileSize::new(u64::from_be_bytes(fixed[38..46].try_into().map_err(|_| malformed)?))
            .map_err(|_| malformed)?;
        let name = &bytes[FIXED_LEN..];
        if name.len() != usize::from(fixed[46]) {
            return Err(malformed);
        }
        let name = core::str::from_utf8(name).map_err(|_| malformed)?;
        let name = FileName::new(name.to_owned()).map_err(|_| malformed)?;
        Ok(Some(Self { key, size, name }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> FileName {
        FileName::new(s.to_owned()).unwrap()
    }

    fn manifest(size: u64) -> FileManifest {
        FileManifest::new(FileKey::from_array([9; 32]), FileSize::new(size).unwrap(), name("relazione.pdf"))
    }

    #[test]
    fn manifest_roundtrips_and_is_recognized() {
        let original = manifest(3 * CHUNK_LEN as u64 + 5);
        let plaintext = original.to_plaintext();
        assert_eq!(plaintext.expose().len(), FIXED_LEN + "relazione.pdf".len());
        assert_eq!(FileManifest::recognize(&plaintext), Ok(Some(original)));
    }

    #[test]
    fn text_secrets_are_not_files() {
        for text in ["hunter2", "SGYF", "\u{FF}SGYF written as text"] {
            let plaintext = Plaintext::new(text.as_bytes().to_vec()).unwrap();
            assert_eq!(FileManifest::recognize(&plaintext), Ok(None), "{text}");
        }
    }

    #[test]
    fn chunk_layout_follows_the_size() {
        assert_eq!(FileSize::new(1).unwrap().chunk_count(), 1);
        assert_eq!(FileSize::new(CHUNK_LEN as u64).unwrap().chunk_count(), 1);
        assert_eq!(FileSize::new(CHUNK_LEN as u64 + 1).unwrap().chunk_count(), 2);
        assert_eq!(FileSize::new(MAX_FILE_LEN as u64).unwrap().chunk_count(), MAX_CHUNKS);
        let chunks: Vec<_> = FileSize::new(2 * CHUNK_LEN as u64 + 300).unwrap().chunks().collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[1].bytes(), CHUNK_LEN..2 * CHUNK_LEN);
        assert_eq!(chunks[2].bytes(), 2 * CHUNK_LEN..2 * CHUNK_LEN + 300);
        assert_eq!((chunks[0].padded_len(), chunks[2].padded_len()), (CHUNK_LEN, 512));
        assert!(chunks.iter().all(|c| c.count() == 3));
    }

    #[test]
    fn small_files_share_a_bucket() {
        let tiny = FileSize::new(3).unwrap().chunks().next().unwrap();
        let small = FileSize::new(200).unwrap().chunks().next().unwrap();
        assert_eq!((tiny.sealed_len(), small.sealed_len()), (256 + TAG_LEN, 256 + TAG_LEN));
    }

    #[test]
    fn padding_roundtrips() {
        let file: Vec<u8> = (0..CHUNK_LEN + 700).map(|i| i as u8).collect();
        for chunk in FileSize::new(file.len() as u64).unwrap().chunks() {
            let padded = chunk.pad(&file);
            assert_eq!(chunk.unpad(&padded).unwrap(), &file[chunk.bytes()]);
        }
    }

    #[test]
    fn file_bounds() {
        assert_eq!(FileBytes::new(vec![]), Err(SealError::PlaintextEmpty));
        assert!(FileBytes::new(vec![1; MAX_FILE_LEN]).is_ok());
        assert_eq!(FileBytes::new(vec![1; MAX_FILE_LEN + 1]), Err(SealError::FileTooLarge));
        assert_eq!(FileSize::new(0), Err(SealError::FileTooLarge));
        assert_eq!(SealedChunk::new(vec![0; SealedChunk::MAX_LEN + 1]), Err(SealError::MalformedEnvelope));
        assert_eq!(SealedChunk::new(vec![0; TAG_LEN]), Err(SealError::MalformedEnvelope));
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for ok in ["a", "Relazione finale (v2).pdf", "日本語.txt", "café.png", ".bashrc", &"x".repeat(MAX_NAME_LEN)]
        {
            assert!(FileName::new(ok.to_owned()).is_ok(), "{ok}");
        }
    }

    mod adversary {
        use super::*;

        #[test]
        fn names_that_hide_or_traverse_are_refused() {
            for bad in [
                "",
                ".",
                "..",
                "../../etc/passwd",
                "C:\\Windows\\evil.dll",
                "invoice\u{202E}fdp.exe",
                "zero\u{200B}width",
                "tab\there",
                "new\nline",
                "nul\0byte",
                "bom\u{FEFF}",
                &"x".repeat(MAX_NAME_LEN + 1),
                // Line and paragraph separators, Hangul fillers, the grapheme
                // joiner, variation selectors and tags: all invisible.
                "line\u{2028}sep",
                "para\u{2029}sep",
                "filler\u{115F}",
                "filler\u{1160}",
                "filler\u{3164}",
                "filler\u{FFA0}",
                "joiner\u{034F}",
                "variation\u{FE0F}",
                "tag\u{E0041}",
                "arabic\u{0600}mark",
                // Spaces that push the real extension out of sight.
                "report.pdf          .exe",
                "report.pdf\u{00A0}.exe",
                "report.pdf\u{3000}.exe",
                " leading",
                // What Windows would refuse or silently rewrite.
                "what?.txt",
                "a<b>.txt",
                "c:.txt",
                "quote\".txt",
                "pipe|.txt",
                "star*.txt",
                "trailing.",
                "trailing ",
                "CON",
                "con.txt",
                "Lpt1.pdf",
                "nul.tar.gz",
            ] {
                assert_eq!(FileName::new(bad.to_owned()), Err(SealError::InvalidFileName), "{bad:?}");
            }
        }

        #[test]
        fn blank_glyphs_that_push_the_extension_away_are_refused() {
            // Not format characters, so not invisible by category, but they
            // draw nothing: a run of them hides `.exe` as well as spaces do.
            let braille = "\u{2800}".repeat(60);
            let alternating = " \u{2800}".repeat(40);
            for bad in [
                format!("report.pdf{braille}.exe"),
                format!("report.pdf{alternating}.exe"),
                "blank\u{2800}".to_owned(),
                "null notehead\u{1D159}.exe".to_owned(),
                "object\u{FFFC}.exe".to_owned(),
                "private\u{E000}use.exe".to_owned(),
                "private\u{F0000}use.exe".to_owned(),
                "filler\u{115F}\u{1160}.exe".to_owned(),
            ] {
                assert_eq!(FileName::new(bad.clone()), Err(SealError::InvalidFileName), "{bad:?}");
            }
        }

        #[test]
        fn runs_of_blanks_are_refused_whatever_they_are_made_of() {
            for run in ["  ", " \u{2800}", "\u{2800} ", "\u{3164} ", " \u{00A0}"] {
                let bad = format!("report.pdf{run}x.exe");
                assert_eq!(FileName::new(bad.clone()), Err(SealError::InvalidFileName), "{bad:?}");
            }
        }

        #[test]
        fn combining_marks_cannot_pile_up_over_the_name() {
            let overlays = "\u{0336}".repeat(30);
            for bad in [
                format!("report.pdf{overlays}.exe"),
                "a\u{0301}\u{0302}\u{0303}.txt".to_owned(),
                "x\u{20D2}\u{20D2}\u{20D2}.txt".to_owned(),
                "\u{0336}\u{0336}\u{0336}lead.txt".to_owned(),
            ] {
                assert_eq!(FileName::new(bad.clone()), Err(SealError::InvalidFileName), "{bad:?}");
            }
            // One or two marks on a letter are ordinary writing.
            for good in ["e\u{0301}te\u{0301}.txt", "a\u{0323}\u{0302}.txt", "ไม้.txt", "شَدَّة.txt"] {
                assert!(FileName::new(good.to_owned()).is_ok(), "{good:?}");
            }
        }

        #[test]
        fn every_spelling_of_a_windows_device_is_refused() {
            for bad in [
                "CON .txt",
                "con  ",
                "NUL .tar.gz",
                "aux .",
                "COM\u{00B9}.txt",
                "com\u{00B2}",
                "LPT\u{00B3}.pdf",
                "COM0.txt",
                "lpt0",
                "CONIN$",
                "conout$.log",
                "CONIN$ .txt",
            ] {
                assert_eq!(FileName::new(bad.to_owned()), Err(SealError::InvalidFileName), "{bad:?}");
            }
            for good in ["CONSOLE.txt", "COM10.txt", "LPT\u{00B9}0.txt", "conin.txt", "NULL.txt", "a CON.txt"] {
                assert!(FileName::new(good.to_owned()).is_ok(), "{good:?}");
            }
        }

        #[test]
        fn a_double_extension_is_shown_whole_and_kept() {
            // Not hidden: the name is shown in full. Telling the real extension
            // apart is the page's job, not the sealer's.
            assert!(FileName::new("invoice.pdf.exe".to_owned()).is_ok());
        }

        #[test]
        fn ordinary_names_are_kept_as_they_are() {
            for good in [
                "Relazione finale (v2).pdf",
                "été 2026.txt",
                "日本語の資料.docx",
                "контракт.odt",
                "a.b.c",
                ".env",
                "console.log",
                "COM10.txt",
                "x".repeat(MAX_NAME_LEN).as_str(),
            ] {
                assert_eq!(FileName::new(good.to_owned()).map(|n| n.as_str().to_owned()), Ok(good.to_owned()));
            }
        }

        #[test]
        fn malformed_manifests_are_refused() {
            let good = manifest(1000).to_plaintext().expose().to_vec();
            let mut cases: Vec<Vec<u8>> = (MANIFEST_MAGIC.len()..good.len()).map(|n| good[..n].to_vec()).collect();
            let mut version = good.clone();
            version[5] = 2;
            let mut empty = good.clone();
            empty[38..46].copy_from_slice(&0u64.to_be_bytes());
            let mut huge = good.clone();
            huge[38..46].copy_from_slice(&(MAX_FILE_LEN as u64 + 1).to_be_bytes());
            let mut long_name = good.clone();
            long_name[46] += 1;
            let mut trailing = good.clone();
            trailing.push(b'x');
            let mut not_utf8 = good.clone();
            *not_utf8.last_mut().unwrap() = 0xC3;
            let mut hidden = good[..FIXED_LEN].to_vec();
            hidden[46] = 5;
            hidden.extend_from_slice("a\u{202E}b".as_bytes());
            cases.extend([version, empty, huge, long_name, trailing, not_utf8, hidden]);
            for bytes in cases {
                let plaintext = Plaintext::new(bytes.clone()).unwrap();
                assert_eq!(FileManifest::recognize(&plaintext), Err(SealError::MalformedEnvelope), "{bytes:02x?}");
            }
        }

        #[test]
        fn every_position_has_its_own_nonce_and_associated_data() {
            let chunks: Vec<_> = FileSize::new(MAX_FILE_LEN as u64).unwrap().chunks().collect();
            for (i, a) in chunks.iter().enumerate() {
                for b in &chunks[i + 1..] {
                    assert_ne!(a.nonce(), b.nonce());
                    assert_ne!(a.associated_data(), b.associated_data());
                }
            }
            // The same index in a file of another length is another position.
            let short = FileSize::new(1).unwrap().chunks().next().unwrap();
            assert_ne!(short.associated_data(), chunks[0].associated_data());
        }

        #[test]
        fn non_zero_or_resized_padding_is_refused() {
            let chunk = FileSize::new(10).unwrap().chunks().next().unwrap();
            let mut padded = chunk.pad(&[7; 10]).to_vec();
            padded[100] = 1;
            assert_eq!(chunk.unpad(&padded), Err(SealError::MalformedEnvelope));
            assert_eq!(chunk.unpad(&[7; 512]), Err(SealError::MalformedEnvelope));
        }

        #[test]
        fn debug_never_prints_names_contents_or_keys() {
            let rendered = format!(
                "{:?} {:?} {:?}",
                manifest(5),
                FileBytes::new(b"top secret contents".to_vec()).unwrap(),
                name("piano-segreto.pdf"),
            );
            assert!(!rendered.contains("relazione") && !rendered.contains("piano") && !rendered.contains("top secret"));
            assert!(!rendered.contains("9, 9"));
        }
    }
}
