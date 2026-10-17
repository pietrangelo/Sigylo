//! The envelope: the only thing that ever leaves the device.
//!
//! ```text
//! offset  size  field
//! 0       3     magic "SGY"
//! 3       1     version (1)
//! 4       1     mode: 1 = link key, 2 = recipient (hybrid KEM)
//! 5       1     flags: bit 0 = passphrase, other bits must be zero
//! [if passphrase]
//!         16    Argon2id salt
//!         12    Argon2id memory KiB, iterations, lanes (u32 BE each)
//! [if mode = 2]
//!         1120  hybrid encapsulation (ct_x25519 || ct_mlkem768)
//!         24    XChaCha20-Poly1305 nonce
//!         ≥ 16  ciphertext of the padded plaintext, with tag
//! ```
//!
//! Every byte before the ciphertext is the header, and the header is the
//! AEAD associated data: mode, KDF parameters and encapsulation cannot be
//! altered without the envelope failing to open.

use super::{Encapsulation, KdfCost, Salt, SealError};

const MAGIC: &[u8; 3] = b"SGY";
const VERSION: u8 = 1;
const FLAG_PASSPHRASE: u8 = 0b0000_0001;
const MODE_LINK_KEY: u8 = 1;
const MODE_RECIPIENT: u8 = 2;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// A 192-bit XChaCha20 nonce. Random nonces of this size never collide in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; Nonce::LEN]);

impl Nonce {
    pub const LEN: usize = 24;

    pub fn from_array(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// Where the base secret of an envelope comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// A random key carried in the link fragment.
    LinkKey,
    /// A hybrid encapsulation to the recipient's public key.
    Recipient(Encapsulation),
}

impl KeySource {
    pub fn mode_byte(&self) -> u8 {
        match self {
            Self::LinkKey => MODE_LINK_KEY,
            Self::Recipient(_) => MODE_RECIPIENT,
        }
    }
}

/// Passphrase stretching parameters recorded in the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassphraseLock {
    pub salt: Salt,
    pub cost: KdfCost,
}

/// Everything in the envelope except the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub source: KeySource,
    pub passphrase: Option<PassphraseLock>,
    pub nonce: Nonce,
}

impl EnvelopeHeader {
    /// The canonical header bytes, also used as AEAD associated data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + 28 + Encapsulation::LEN + Nonce::LEN);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.source.mode_byte());
        out.push(if self.passphrase.is_some() { FLAG_PASSPHRASE } else { 0 });
        if let Some(lock) = &self.passphrase {
            out.extend_from_slice(lock.salt.as_bytes());
            for v in [lock.cost.memory_kib(), lock.cost.iterations(), lock.cost.lanes()] {
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        if let KeySource::Recipient(enc) = &self.source {
            out.extend_from_slice(enc.as_bytes());
        }
        out.extend_from_slice(self.nonce.as_bytes());
        out
    }
}

/// A sealed secret: header plus authenticated ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    header: EnvelopeHeader,
    ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn new(header: EnvelopeHeader, ciphertext: Vec<u8>) -> Result<Self, SealError> {
        if ciphertext.len() < TAG_LEN {
            return Err(SealError::MalformedEnvelope);
        }
        Ok(Self { header, ciphertext })
    }

    pub fn header(&self) -> &EnvelopeHeader {
        &self.header
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Whether opening needs a passphrase (so the UI can ask before fetching).
    pub fn needs_passphrase(&self) -> bool {
        self.header.passphrase.is_some()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_bytes();
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Strict parser: rejects anything that would not re-encode to the same bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, SealError> {
        let mut r = Reader { buf: bytes, pos: 0 };
        if r.take(3)? != MAGIC || r.byte()? != VERSION {
            return Err(SealError::MalformedEnvelope);
        }
        let mode = r.byte()?;
        let flags = r.byte()?;
        if flags & !FLAG_PASSPHRASE != 0 {
            return Err(SealError::MalformedEnvelope);
        }
        let passphrase = if flags & FLAG_PASSPHRASE != 0 {
            let salt = Salt::from_array(r.array()?);
            let cost = KdfCost::new(r.u32()?, r.u32()?, r.u32()?).map_err(|_| SealError::MalformedEnvelope)?;
            Some(PassphraseLock { salt, cost })
        } else {
            None
        };
        let source = match mode {
            MODE_LINK_KEY => KeySource::LinkKey,
            MODE_RECIPIENT => KeySource::Recipient(Encapsulation::from_slice(r.take(Encapsulation::LEN)?)?),
            _ => return Err(SealError::MalformedEnvelope),
        };
        let nonce = Nonce::from_array(r.array()?);
        let header = EnvelopeHeader { source, passphrase, nonce };
        Self::new(header, bytes[r.pos..].to_vec())
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SealError> {
        let end = self.pos.checked_add(n).ok_or(SealError::MalformedEnvelope)?;
        let slice = self.buf.get(self.pos..end).ok_or(SealError::MalformedEnvelope)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SealError> {
        self.take(N)?.try_into().map_err(|_| SealError::MalformedEnvelope)
    }

    fn byte(&mut self) -> Result<u8, SealError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, SealError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link_envelope(passphrase: bool) -> Envelope {
        let header = EnvelopeHeader {
            source: KeySource::LinkKey,
            passphrase: passphrase
                .then(|| PassphraseLock { salt: Salt::from_array([7; 16]), cost: KdfCost::RECOMMENDED }),
            nonce: Nonce::from_array([3; 24]),
        };
        Envelope::new(header, vec![0xCC; 272]).unwrap()
    }

    fn recipient_envelope() -> Envelope {
        let header = EnvelopeHeader {
            source: KeySource::Recipient(Encapsulation::from_slice(&[5; Encapsulation::LEN]).unwrap()),
            passphrase: None,
            nonce: Nonce::from_array([3; 24]),
        };
        Envelope::new(header, vec![0xCC; 272]).unwrap()
    }

    #[test]
    fn roundtrips_every_shape() {
        for env in [link_envelope(false), link_envelope(true), recipient_envelope()] {
            assert_eq!(Envelope::parse(&env.to_bytes()).unwrap(), env);
        }
    }

    #[test]
    fn header_is_exactly_the_prefix_before_ciphertext() {
        let env = link_envelope(true);
        let bytes = env.to_bytes();
        let header = env.header().to_bytes();
        assert_eq!(&bytes[..header.len()], &header[..]);
        assert_eq!(header.len(), 6 + 28 + 24);
        assert!(env.needs_passphrase());
    }

    mod adversary {
        use super::*;

        #[test]
        fn every_truncation_is_rejected_or_shorter_ciphertext() {
            let bytes = recipient_envelope().to_bytes();
            let header_len = recipient_envelope().header().to_bytes().len();
            for len in 0..header_len + TAG_LEN {
                assert_eq!(Envelope::parse(&bytes[..len]), Err(SealError::MalformedEnvelope), "len {len}");
            }
        }

        #[test]
        fn unknown_version_mode_and_flags_are_rejected() {
            let good = link_envelope(false).to_bytes();
            for (offset, value) in [(0, b'X'), (3, 2), (3, 0), (4, 0), (4, 3), (5, 0b10), (5, 0x80)] {
                let mut bad = good.clone();
                bad[offset] = value;
                assert_eq!(Envelope::parse(&bad), Err(SealError::MalformedEnvelope), "byte {offset}={value}");
            }
        }

        #[test]
        fn hostile_kdf_cost_in_header_is_rejected() {
            let mut bytes = link_envelope(true).to_bytes();
            bytes[22..26].copy_from_slice(&(8u32 * 1024 * 1024).to_be_bytes());
            assert_eq!(Envelope::parse(&bytes), Err(SealError::MalformedEnvelope));
        }

        #[test]
        fn fuzzed_input_never_panics() {
            // Deterministic xorshift so the test is reproducible without extra crates.
            let mut state = 0x9E37_79B9_7F4A_7C15u64;
            let good = recipient_envelope().to_bytes();
            for round in 0..5_000 {
                let mut bytes = good.clone();
                for _ in 0..(round % 7 + 1) {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let i = (state as usize) % bytes.len();
                    bytes[i] = (state >> 32) as u8;
                }
                bytes.truncate((state as usize >> 8) % (bytes.len() + 1));
                if let Ok(env) = Envelope::parse(&bytes) {
                    assert_eq!(env.to_bytes(), bytes, "parse must be canonical");
                }
            }
        }
    }
}
