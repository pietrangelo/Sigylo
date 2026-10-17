use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::CustodyError;

/// Largest payload the relay keeps: a 64 KiB padded secret plus envelope header.
pub const MAX_PAYLOAD_LEN: usize = 72 * 1024;
/// Smallest payload the relay keeps: the smallest envelope a sealer makes,
/// a 6-byte header, a 24-byte nonce, 256 bytes of padded secret and the
/// 16-byte tag. Anything shorter is not an envelope, and every row costs
/// the database far more than its bytes.
pub const MIN_PAYLOAD_LEN: usize = 6 + 24 + 256 + 16;
/// Most chunks a file deposit can have: a 10 MiB file in 1 MiB chunks.
pub const MAX_CHUNKS: u16 = 10;
/// Largest chunk the relay keeps: 1 MiB of padded file plus the 16-byte tag.
/// Every chunk of a file but the last is exactly this long.
pub const MAX_CHUNK_LEN: usize = 1024 * 1024 + 16;
/// Smallest chunk: the last chunk of a file is padded to a power of two of
/// at least 256 bytes, plus the tag.
pub const MIN_CHUNK_LEN: usize = 256 + 16;
const CHUNK_TAG_LEN: usize = 16;
/// How long whoever opened a burn-after-reading file has to fetch its chunks.
pub const CLAIM_WINDOW_SECONDS: u32 = 60 * 60;
/// How many orphaned chunk objects one garbage batch deletes at most.
pub const GARBAGE_BATCH: u16 = 1000;
/// How long the object of a chunk that went waits in the garbage before it
/// may be deleted from the store: a burned chunk is read well before that.
pub const GARBAGE_GRACE_SECONDS: u32 = 5 * 60;
/// How long the object of a reserved upload waits in the garbage, in case
/// its chunk is never recorded.
pub const RESERVATION_SECONDS: u32 = 15 * 60;
/// How long after its reservation a chunk may still be recorded: long before
/// its object could be collected.
pub const RESERVATION_FRESH_SECONDS: u32 = 5 * 60;

/// An unguessable 128-bit identifier, always chosen by the custodian.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DropId([u8; DropId::LEN]);

impl DropId {
    pub const LEN: usize = 16;

    pub fn from_slice(bytes: &[u8]) -> Result<Self, CustodyError> {
        Ok(Self(bytes.try_into().map_err(|_| CustodyError::InvalidId)?))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for DropId {
    // Ids are bearer capabilities in a link: never print them whole.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DropId({:02x}{:02x}…)", self.0[0], self.0[1])
    }
}

/// Opaque ciphertext. The relay stores and returns it, nothing more.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPayload(Vec<u8>);

impl SealedPayload {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CustodyError> {
        match bytes.len() {
            0 => Err(CustodyError::PayloadEmpty),
            n if n < MIN_PAYLOAD_LEN => Err(CustodyError::PayloadTooSmall),
            n if n > MAX_PAYLOAD_LEN => Err(CustodyError::PayloadTooLarge),
            _ => Ok(Self(bytes)),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SealedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedPayload({} bytes)", self.0.len())
    }
}

/// How many chunks follow a file's manifest: 1 to [`MAX_CHUNKS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChunkCount(u16);

impl ChunkCount {
    pub fn new(count: u16) -> Result<Self, CustodyError> {
        if (1..=MAX_CHUNKS).contains(&count) { Ok(Self(count)) } else { Err(CustodyError::InvalidChunk) }
    }

    pub fn get(&self) -> u16 {
        self.0
    }

    pub fn contains(&self, index: ChunkIndex) -> bool {
        index.0 < self.0
    }

    /// Whether a sealed chunk of `len` bytes fits position `index` of the
    /// file: inside the count, and full ([`MAX_CHUNK_LEN`]) unless it is the
    /// last one. A short chunk anywhere else is not something a sealer makes.
    pub fn takes(&self, index: ChunkIndex, len: usize) -> bool {
        self.contains(index) && (index.0 + 1 == self.0 || len == MAX_CHUNK_LEN)
    }
}

/// The position of a chunk in its file, from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkIndex(u16);

impl ChunkIndex {
    pub fn new(index: u16) -> Result<Self, CustodyError> {
        if index < MAX_CHUNKS { Ok(Self(index)) } else { Err(CustodyError::InvalidChunk) }
    }

    pub fn get(&self) -> u16 {
        self.0
    }
}

/// One opaque piece of a sealed file: a power of two from 256 bytes to
/// 1 MiB, plus the 16-byte tag, as the sealer pads it.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedChunk(Vec<u8>);

impl SealedChunk {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CustodyError> {
        match bytes.len() {
            0 => Err(CustodyError::PayloadEmpty),
            n if n > MAX_CHUNK_LEN => Err(CustodyError::PayloadTooLarge),
            n if n < MIN_CHUNK_LEN || !(n - CHUNK_TAG_LEN).is_power_of_two() => Err(CustodyError::InvalidChunk),
            _ => Ok(Self(bytes)),
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

/// Handed to whoever opens a burn-after-reading file, and only to them: the
/// chunks are released against it, so nobody else with the link can fetch
/// them once the file has been opened.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimToken([u8; 32]);

impl ClaimToken {
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, CustodyError> {
        Ok(Self(bytes.try_into().map_err(|_| CustodyError::InvalidToken)?))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ClaimToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimToken(redacted)")
    }
}

/// What the vault stores instead of the claim token: SHA-256 of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimDigest([u8; 32]);

impl ClaimDigest {
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The name of one stored chunk in the chunk store: 128 random bits drawn by
/// the custodian. It says nothing of the deposit it belongs to; only the vault
/// maps a deposit's chunk to its object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectName([u8; ObjectName::LEN]);

impl ObjectName {
    pub const LEN: usize = 16;

    pub fn from_array(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, CustodyError> {
        Ok(Self(bytes.try_into().map_err(|_| CustodyError::InvalidChunk)?))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// Where the vault found a chunk, and whether it burns once handed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    pub object: ObjectName,
    pub burns: bool,
}

/// What happens after a successful read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Destroyed atomically by the first read (and in any case at expiry).
    BurnAfterReading,
    /// Readable any number of times until it expires.
    UntilExpiry,
}

/// How long something may stay in custody: 5 minutes to 7 days.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lifetime(u32);

impl Lifetime {
    pub const MIN: Self = Self(5 * 60);
    pub const ONE_HOUR: Self = Self(60 * 60);
    pub const ONE_DAY: Self = Self(24 * 60 * 60);
    pub const MAX: Self = Self(7 * 24 * 60 * 60);

    pub fn from_seconds(seconds: u32) -> Result<Self, CustodyError> {
        if (Self::MIN.0..=Self::MAX.0).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(CustodyError::LifetimeOutOfRange)
        }
    }

    pub fn seconds(&self) -> u32 {
        self.0
    }
}

/// Seconds since the Unix epoch, as decided by the vault's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixTime(pub i64);

/// What the custodian hands back when it takes something into custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    /// Where the deposit or request now lives: the id the links will carry.
    pub id: DropId,
    pub expires_at: UnixTime,
}

/// What the custodian hands back when it posts a request: the public id for
/// the sender's link and the private inbox, known only to the recipient's
/// link, where the answer will be filed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestReceipt {
    pub id: DropId,
    pub inbox: DropId,
    pub expires_at: UnixTime,
}

/// The sender's secret for revoking a deposit before it is read.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RevocationToken([u8; 32]);

impl RevocationToken {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CustodyError> {
        Ok(Self(bytes.try_into().map_err(|_| CustodyError::InvalidToken)?))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RevocationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RevocationToken(redacted)")
    }
}

/// What the vault stores instead of the token: SHA-256 of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationDigest([u8; 32]);

impl RevocationDigest {
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, CustodyError> {
        Ok(Self(bytes.try_into().map_err(|_| CustodyError::InvalidToken)?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A recipient's public key as the relay sees it: 1216 opaque bytes
/// (X25519 32 + ML-KEM-768 1184).
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientKeyBlob(Vec<u8>);

impl RecipientKeyBlob {
    pub const LEN: usize = 1216;

    pub fn new(bytes: Vec<u8>) -> Result<Self, CustodyError> {
        if bytes.len() == Self::LEN { Ok(Self(bytes)) } else { Err(CustodyError::InvalidRecipientKey) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RecipientKeyBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientKeyBlob(1216 bytes)")
    }
}

/// A sealed secret handed over for safekeeping. A file is its sealed
/// manifest as the payload plus `chunks` uploaded after it; until the last
/// chunk is in, the deposit cannot be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposit {
    pub id: DropId,
    pub payload: SealedPayload,
    pub retention: Retention,
    pub lifetime: Lifetime,
    pub revocation: Option<RevocationDigest>,
    pub chunks: Option<ChunkCount>,
}

/// The result of a successful read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub payload: SealedPayload,
    /// True when this read destroyed the deposit (or, for a file, claimed it).
    pub burned: bool,
    /// The chunks to fetch next, for a file.
    pub chunks: Option<ChunkCount>,
    /// For a burn-after-reading file: the only key to its chunks.
    pub claim: Option<ClaimToken>,
}

/// A recipient asking for one secret to be sealed to their public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Public: travels in the request link to the sender.
    pub id: DropId,
    /// Private: where the answer is filed, known only to the recipient's link.
    pub inbox: DropId,
    pub recipient_key: RecipientKeyBlob,
    pub lifetime: Lifetime,
}

/// A request as a sender sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostedRequest {
    pub recipient_key: RecipientKeyBlob,
    pub expires_at: UnixTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_window_is_five_minutes_to_seven_days() {
        assert_eq!(Lifetime::from_seconds(299), Err(CustodyError::LifetimeOutOfRange));
        assert_eq!(Lifetime::from_seconds(300), Ok(Lifetime::MIN));
        assert_eq!(Lifetime::from_seconds(604_800), Ok(Lifetime::MAX));
        assert_eq!(Lifetime::from_seconds(604_801), Err(CustodyError::LifetimeOutOfRange));
        assert_eq!(Lifetime::from_seconds(0), Err(CustodyError::LifetimeOutOfRange));
    }

    #[test]
    fn payload_bounds() {
        assert_eq!(SealedPayload::new(vec![]), Err(CustodyError::PayloadEmpty));
        assert!(SealedPayload::new(vec![1; MAX_PAYLOAD_LEN]).is_ok());
        assert_eq!(SealedPayload::new(vec![1; MAX_PAYLOAD_LEN + 1]), Err(CustodyError::PayloadTooLarge));
        assert!(SealedPayload::new(vec![1; MIN_PAYLOAD_LEN]).is_ok());
    }

    #[test]
    fn fixed_sizes() {
        assert_eq!(DropId::from_slice(&[0; 15]), Err(CustodyError::InvalidId));
        assert_eq!(RecipientKeyBlob::new(vec![0; 1215]), Err(CustodyError::InvalidRecipientKey));
        assert_eq!(RevocationToken::from_slice(&[0; 31]), Err(CustodyError::InvalidToken));
        assert!(RecipientKeyBlob::new(vec![0; 1216]).is_ok());
        assert_eq!(ClaimToken::from_slice(&[0; 33]), Err(CustodyError::InvalidToken));
    }

    #[test]
    fn chunk_bounds() {
        assert_eq!(ChunkCount::new(0), Err(CustodyError::InvalidChunk));
        assert_eq!(ChunkCount::new(MAX_CHUNKS).map(|c| c.get()), Ok(MAX_CHUNKS));
        assert_eq!(ChunkCount::new(MAX_CHUNKS + 1), Err(CustodyError::InvalidChunk));
        assert_eq!(ChunkIndex::new(MAX_CHUNKS - 1).map(|i| i.get()), Ok(MAX_CHUNKS - 1));
        assert_eq!(ChunkIndex::new(MAX_CHUNKS), Err(CustodyError::InvalidChunk));
        let three = ChunkCount::new(3).unwrap();
        assert!(three.contains(ChunkIndex::new(2).unwrap()) && !three.contains(ChunkIndex::new(3).unwrap()));
        assert_eq!(SealedChunk::new(vec![]), Err(CustodyError::PayloadEmpty));
        assert!(SealedChunk::new(vec![1; MAX_CHUNK_LEN]).is_ok());
        assert_eq!(SealedChunk::new(vec![1; MAX_CHUNK_LEN + 1]), Err(CustodyError::PayloadTooLarge));
        // What the sealer makes: a power of two from 256 B to 1 MiB, plus the tag.
        for padded in (8..=20).map(|k| 1usize << k) {
            assert!(SealedChunk::new(vec![1; padded + 16]).is_ok(), "{padded}");
        }
    }

    #[test]
    fn only_the_last_chunk_may_be_short() {
        let three = ChunkCount::new(3).unwrap();
        let at = |i| ChunkIndex::new(i).unwrap();
        assert!(three.takes(at(0), MAX_CHUNK_LEN) && three.takes(at(1), MAX_CHUNK_LEN));
        assert!(!three.takes(at(0), MIN_CHUNK_LEN) && !three.takes(at(1), 512 + 16));
        assert!(three.takes(at(2), MIN_CHUNK_LEN) && three.takes(at(2), MAX_CHUNK_LEN));
        assert!(!three.takes(at(3), MAX_CHUNK_LEN));
        let one = ChunkCount::new(1).unwrap();
        assert!(one.takes(at(0), MIN_CHUNK_LEN));
    }

    mod adversary {
        use super::*;

        #[test]
        fn payloads_smaller_than_any_envelope_are_refused() {
            // Each row costs the database far more than its bytes: tiny
            // payloads would fill it while the ceiling saw almost nothing.
            assert_eq!(MIN_PAYLOAD_LEN, 6 + 24 + 256 + 16);
            for len in [1, 4, MIN_PAYLOAD_LEN - 1] {
                assert_eq!(SealedPayload::new(vec![1; len]), Err(CustodyError::PayloadTooSmall), "{len}");
            }
        }

        #[test]
        fn chunks_the_sealer_never_makes_are_refused() {
            assert_eq!(MIN_CHUNK_LEN, 256 + 16);
            for len in [1, 16, 271, 273, 300, 4096, 4096 + 15, 4096 + 17, MAX_CHUNK_LEN - 1, 128 + 16] {
                assert_eq!(SealedChunk::new(vec![1; len]), Err(CustodyError::InvalidChunk), "{len}");
            }
        }

        #[test]
        fn debug_never_prints_capabilities_or_ciphertext() {
            let id = DropId::from_slice(&[0xAB; 16]).unwrap();
            let rendered = format!(
                "{id:?} {:?} {:?} {:?} {:?}",
                RevocationToken::from_slice(&[0xCD; 32]).unwrap(),
                SealedPayload::new(vec![0xEF; MIN_PAYLOAD_LEN]).unwrap(),
                ClaimToken::from_array([0xCD; 32]),
                SealedChunk::new(vec![0xEF; MIN_CHUNK_LEN]).unwrap(),
            );
            assert!(!rendered.contains("abababab"));
            assert!(!rendered.to_lowercase().contains("cd") && !rendered.to_lowercase().contains("ef"));
        }
    }
}
