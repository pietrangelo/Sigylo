//! The calls the relay makes to the vault in its Durable Object, and the
//! replies, as bytes: one [`Call`] per [`custody::Vault`] method. Strict like
//! every parser here: a message decodes only if it is exactly what `encode`
//! writes, and every value goes through the Custody constructors again.

use custody::{
    ChunkCount, ChunkIndex, ChunkRef, ClaimDigest, CustodyError, Deposit, DropId, Lifetime, ObjectName, Opened,
    PostedRequest, Receipt, RecipientKeyBlob, Request, Retention, RevocationDigest, SealedPayload, UnixTime,
};

use super::records::Reader;

/// Most objects one garbage call names: a full batch.
const MAX_OBJECTS: usize = custody::GARBAGE_BATCH as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Deposit(Deposit),
    Open { id: DropId, claim: ClaimDigest },
    ReserveChunk { id: DropId, index: ChunkIndex, object: ObjectName, len: u32 },
    PutChunk { id: DropId, index: ChunkIndex, object: ObjectName, len: u32 },
    OpenChunk { id: DropId, index: ChunkIndex, claim: Option<ClaimDigest> },
    BurnChunk { id: DropId, index: ChunkIndex, claim: ClaimDigest },
    Garbage { limit: u16 },
    ForgetGarbage { objects: Vec<ObjectName> },
    Revoke { id: DropId, digest: RevocationDigest },
    PostRequest(Request),
    FetchRequest { id: DropId },
    AnswerRequest(Deposit),
    PurgeExpired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Failed(CustodyError),
    /// `deposit`, `post_request`.
    Expires(UnixTime),
    /// `open`; the claim token never travels, the custodian holds it.
    Opened(Option<Opened>),
    /// `reserve_chunk`, `put_chunk`, `burn_chunk`.
    Flag(bool),
    Chunk(Option<ChunkRef>),
    /// `garbage`.
    Objects(Vec<ObjectName>),
    /// `forget_garbage`.
    Done,
    Revoked(Option<Vec<ObjectName>>),
    Request(Option<PostedRequest>),
    Answered(Option<Receipt>),
    Purged(u64),
}

const ERRORS: [CustodyError; 13] = [
    CustodyError::InvalidId,
    CustodyError::PayloadEmpty,
    CustodyError::PayloadTooSmall,
    CustodyError::PayloadTooLarge,
    CustodyError::LifetimeOutOfRange,
    CustodyError::InvalidRecipientKey,
    CustodyError::InvalidToken,
    CustodyError::InvalidChunk,
    CustodyError::AlreadyExists,
    CustodyError::NotFound,
    CustodyError::VaultUnavailable,
    CustodyError::StorageFull,
    CustodyError::RandomnessUnavailable,
];

struct Writer(Vec<u8>);

impl Writer {
    fn new(tag: u8) -> Self {
        Self(vec![tag])
    }

    fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    fn byte(&mut self, byte: u8) -> &mut Self {
        self.0.push(byte);
        self
    }

    fn flag(&mut self, flag: bool) -> &mut Self {
        self.byte(u8::from(flag))
    }

    fn u16(&mut self, n: u16) -> &mut Self {
        self.bytes(&n.to_be_bytes())
    }

    fn u32(&mut self, n: u32) -> &mut Self {
        self.bytes(&n.to_be_bytes())
    }

    fn i64(&mut self, n: i64) -> &mut Self {
        self.bytes(&n.to_be_bytes())
    }

    fn sized(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32(bytes.len() as u32).bytes(bytes)
    }

    fn objects(&mut self, objects: &[ObjectName]) -> &mut Self {
        self.u16(objects.len() as u16);
        for object in objects {
            self.bytes(object.as_bytes());
        }
        self
    }

    fn deposit(&mut self, deposit: &Deposit) -> &mut Self {
        self.bytes(deposit.id.as_bytes())
            .flag(deposit.retention == Retention::UntilExpiry)
            .u32(deposit.lifetime.seconds())
            .flag(deposit.revocation.is_some());
        if let Some(digest) = &deposit.revocation {
            self.bytes(digest.as_bytes());
        }
        self.u16(deposit.chunks.map_or(0, |c| c.get())).sized(deposit.payload.as_bytes())
    }
}

impl Reader<'_> {
    fn flag(&mut self) -> Option<bool> {
        match self.byte()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn id(&mut self) -> Option<DropId> {
        DropId::from_slice(self.take(DropId::LEN)?).ok()
    }

    fn index(&mut self) -> Option<ChunkIndex> {
        ChunkIndex::new(self.u16()?).ok()
    }

    fn object(&mut self) -> Option<ObjectName> {
        Some(ObjectName::from_array(self.array()?))
    }

    fn sized(&mut self) -> Option<&[u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn payload(&mut self) -> Option<SealedPayload> {
        SealedPayload::new(self.sized()?.to_vec()).ok()
    }

    fn chunk_count(&mut self) -> Option<Option<ChunkCount>> {
        match self.u16()? {
            0 => Some(None),
            n => ChunkCount::new(n).ok().map(Some),
        }
    }

    fn objects(&mut self) -> Option<Vec<ObjectName>> {
        let count = usize::from(self.u16()?);
        if count > MAX_OBJECTS {
            return None;
        }
        (0..count).map(|_| self.object()).collect()
    }

    fn deposit(&mut self) -> Option<Deposit> {
        let id = self.id()?;
        let retention = if self.flag()? { Retention::UntilExpiry } else { Retention::BurnAfterReading };
        let lifetime = Lifetime::from_seconds(self.u32()?).ok()?;
        let revocation = if self.flag()? { Some(RevocationDigest::from_array(self.array()?)) } else { None };
        let chunks = self.chunk_count()?;
        let payload = self.payload()?;
        Some(Deposit { id, payload, retention, lifetime, revocation, chunks })
    }
}

impl Call {
    pub fn encode(&self) -> Vec<u8> {
        let mut w;
        match self {
            Self::Deposit(deposit) => {
                w = Writer::new(1);
                w.deposit(deposit);
            }
            Self::Open { id, claim } => {
                w = Writer::new(2);
                w.bytes(id.as_bytes()).bytes(claim.as_bytes());
            }
            Self::ReserveChunk { id, index, object, len } => {
                w = Writer::new(3);
                w.bytes(id.as_bytes()).u16(index.get()).bytes(object.as_bytes()).u32(*len);
            }
            Self::PutChunk { id, index, object, len } => {
                w = Writer::new(4);
                w.bytes(id.as_bytes()).u16(index.get()).bytes(object.as_bytes()).u32(*len);
            }
            Self::OpenChunk { id, index, claim } => {
                w = Writer::new(5);
                w.bytes(id.as_bytes()).u16(index.get()).flag(claim.is_some());
                if let Some(claim) = claim {
                    w.bytes(claim.as_bytes());
                }
            }
            Self::BurnChunk { id, index, claim } => {
                w = Writer::new(6);
                w.bytes(id.as_bytes()).u16(index.get()).bytes(claim.as_bytes());
            }
            Self::Garbage { limit } => {
                w = Writer::new(7);
                w.u16(*limit);
            }
            Self::ForgetGarbage { objects } => {
                w = Writer::new(8);
                w.objects(objects);
            }
            Self::Revoke { id, digest } => {
                w = Writer::new(9);
                w.bytes(id.as_bytes()).bytes(digest.as_bytes());
            }
            Self::PostRequest(request) => {
                w = Writer::new(10);
                w.bytes(request.id.as_bytes())
                    .bytes(request.inbox.as_bytes())
                    .u32(request.lifetime.seconds())
                    .bytes(request.recipient_key.as_bytes());
            }
            Self::FetchRequest { id } => {
                w = Writer::new(11);
                w.bytes(id.as_bytes());
            }
            Self::AnswerRequest(deposit) => {
                w = Writer::new(12);
                w.deposit(deposit);
            }
            Self::PurgeExpired => w = Writer::new(13),
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        let call = match r.byte()? {
            1 => Self::Deposit(r.deposit()?),
            2 => Self::Open { id: r.id()?, claim: ClaimDigest::from_array(r.array()?) },
            3 => Self::ReserveChunk { id: r.id()?, index: r.index()?, object: r.object()?, len: r.u32()? },
            4 => Self::PutChunk { id: r.id()?, index: r.index()?, object: r.object()?, len: r.u32()? },
            5 => {
                let (id, index) = (r.id()?, r.index()?);
                let claim = if r.flag()? { Some(ClaimDigest::from_array(r.array()?)) } else { None };
                Self::OpenChunk { id, index, claim }
            }
            6 => Self::BurnChunk { id: r.id()?, index: r.index()?, claim: ClaimDigest::from_array(r.array()?) },
            7 => Self::Garbage { limit: r.u16()? },
            8 => Self::ForgetGarbage { objects: r.objects()? },
            9 => Self::Revoke { id: r.id()?, digest: RevocationDigest::from_array(r.array()?) },
            10 => Self::PostRequest(Request {
                id: r.id()?,
                inbox: r.id()?,
                lifetime: Lifetime::from_seconds(r.u32()?).ok()?,
                recipient_key: RecipientKeyBlob::new(r.take(RecipientKeyBlob::LEN)?.to_vec()).ok()?,
            }),
            11 => Self::FetchRequest { id: r.id()? },
            12 => Self::AnswerRequest(r.deposit()?),
            13 => Self::PurgeExpired,
            _ => return None,
        };
        r.end()?;
        Some(call)
    }
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let mut w;
        match self {
            Self::Failed(error) => {
                w = Writer::new(0);
                w.byte(ERRORS.iter().position(|e| e == error).unwrap_or(10) as u8);
            }
            Self::Expires(at) => {
                w = Writer::new(1);
                w.i64(at.0);
            }
            Self::Opened(opened) => {
                w = Writer::new(2);
                w.flag(opened.is_some());
                if let Some(opened) = opened {
                    w.flag(opened.burned).u16(opened.chunks.map_or(0, |c| c.get())).sized(opened.payload.as_bytes());
                }
            }
            Self::Flag(flag) => {
                w = Writer::new(3);
                w.flag(*flag);
            }
            Self::Chunk(chunk) => {
                w = Writer::new(4);
                w.flag(chunk.is_some());
                if let Some(chunk) = chunk {
                    w.bytes(chunk.object.as_bytes()).flag(chunk.burns);
                }
            }
            Self::Objects(objects) => {
                w = Writer::new(5);
                w.objects(objects);
            }
            Self::Done => w = Writer::new(6),
            Self::Revoked(objects) => {
                w = Writer::new(7);
                w.flag(objects.is_some());
                if let Some(objects) = objects {
                    w.objects(objects);
                }
            }
            Self::Request(request) => {
                w = Writer::new(8);
                w.flag(request.is_some());
                if let Some(request) = request {
                    w.i64(request.expires_at.0).bytes(request.recipient_key.as_bytes());
                }
            }
            Self::Answered(receipt) => {
                w = Writer::new(9);
                w.flag(receipt.is_some());
                if let Some(receipt) = receipt {
                    w.bytes(receipt.id.as_bytes()).i64(receipt.expires_at.0);
                }
            }
            Self::Purged(n) => {
                w = Writer::new(10);
                w.bytes(&n.to_be_bytes());
            }
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        let reply = match r.byte()? {
            0 => Self::Failed(*ERRORS.get(usize::from(r.byte()?))?),
            1 => Self::Expires(UnixTime(r.i64()?)),
            2 => Self::Opened(if r.flag()? {
                let burned = r.flag()?;
                let chunks = r.chunk_count()?;
                Some(Opened { payload: r.payload()?, burned, chunks, claim: None })
            } else {
                None
            }),
            3 => Self::Flag(r.flag()?),
            4 => Self::Chunk(if r.flag()? { Some(ChunkRef { object: r.object()?, burns: r.flag()? }) } else { None }),
            5 => Self::Objects(r.objects()?),
            6 => Self::Done,
            7 => Self::Revoked(if r.flag()? { Some(r.objects()?) } else { None }),
            8 => Self::Request(if r.flag()? {
                let expires_at = UnixTime(r.i64()?);
                let recipient_key = RecipientKeyBlob::new(r.take(RecipientKeyBlob::LEN)?.to_vec()).ok()?;
                Some(PostedRequest { recipient_key, expires_at })
            } else {
                None
            }),
            9 => Self::Answered(if r.flag()? {
                Some(Receipt { id: r.id()?, expires_at: UnixTime(r.i64()?) })
            } else {
                None
            }),
            10 => Self::Purged(r.u64()?),
            _ => return None,
        };
        r.end()?;
        Some(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> DropId {
        DropId::from_slice(&[n; 16]).unwrap()
    }

    fn payload() -> SealedPayload {
        SealedPayload::new(vec![0xA5; custody::MIN_PAYLOAD_LEN + 3]).unwrap()
    }

    fn deposit() -> Deposit {
        Deposit {
            id: id(1),
            payload: payload(),
            retention: Retention::UntilExpiry,
            lifetime: Lifetime::ONE_DAY,
            revocation: Some(RevocationDigest::from_array([2; 32])),
            chunks: ChunkCount::new(3).ok(),
        }
    }

    fn calls() -> Vec<Call> {
        let index = ChunkIndex::new(9).unwrap();
        let object = ObjectName::from_array([4; 16]);
        let claim = ClaimDigest::from_array([5; 32]);
        vec![
            Call::Deposit(deposit()),
            Call::Deposit(Deposit {
                revocation: None,
                chunks: None,
                retention: Retention::BurnAfterReading,
                ..deposit()
            }),
            Call::Open { id: id(1), claim },
            Call::ReserveChunk { id: id(1), index, object, len: 7 },
            Call::PutChunk { id: id(1), index, object, len: u32::MAX },
            Call::OpenChunk { id: id(1), index, claim: Some(claim) },
            Call::OpenChunk { id: id(1), index, claim: None },
            Call::BurnChunk { id: id(1), index, claim },
            Call::Garbage { limit: 1000 },
            Call::ForgetGarbage { objects: vec![object; 1000] },
            Call::ForgetGarbage { objects: vec![] },
            Call::Revoke { id: id(3), digest: RevocationDigest::from_array([6; 32]) },
            Call::PostRequest(Request {
                id: id(1),
                inbox: id(2),
                recipient_key: RecipientKeyBlob::new(vec![8; RecipientKeyBlob::LEN]).unwrap(),
                lifetime: Lifetime::MAX,
            }),
            Call::FetchRequest { id: id(4) },
            Call::AnswerRequest(deposit()),
            Call::PurgeExpired,
        ]
    }

    fn replies() -> Vec<Reply> {
        let object = ObjectName::from_array([4; 16]);
        let mut replies: Vec<Reply> = ERRORS.iter().map(|e| Reply::Failed(*e)).collect();
        replies.extend([
            Reply::Expires(UnixTime(1_800_000_000)),
            Reply::Opened(None),
            Reply::Opened(Some(Opened {
                payload: payload(),
                burned: true,
                chunks: ChunkCount::new(10).ok(),
                claim: None,
            })),
            Reply::Opened(Some(Opened { payload: payload(), burned: false, chunks: None, claim: None })),
            Reply::Flag(true),
            Reply::Flag(false),
            Reply::Chunk(None),
            Reply::Chunk(Some(ChunkRef { object, burns: true })),
            Reply::Objects(vec![object; 3]),
            Reply::Done,
            Reply::Revoked(None),
            Reply::Revoked(Some(vec![])),
            Reply::Revoked(Some(vec![object])),
            Reply::Request(None),
            Reply::Request(Some(PostedRequest {
                recipient_key: RecipientKeyBlob::new(vec![8; RecipientKeyBlob::LEN]).unwrap(),
                expires_at: UnixTime(9),
            })),
            Reply::Answered(None),
            Reply::Answered(Some(Receipt { id: id(7), expires_at: UnixTime(10) })),
            Reply::Purged(u64::MAX),
        ]);
        replies
    }

    #[test]
    fn every_call_and_reply_round_trips() {
        for call in calls() {
            assert_eq!(Call::decode(&call.encode()), Some(call.clone()), "{call:?}");
        }
        for reply in replies() {
            assert_eq!(Reply::decode(&reply.encode()), Some(reply.clone()), "{reply:?}");
        }
    }

    mod adversary {
        use super::*;

        #[test]
        fn every_truncation_and_every_extra_byte_is_refused() {
            for bytes in calls().iter().map(Call::encode) {
                for cut in 0..bytes.len() {
                    assert_eq!(Call::decode(&bytes[..cut]), None);
                }
                assert_eq!(Call::decode(&[bytes.as_slice(), &[0]].concat()), None);
            }
            for bytes in replies().iter().map(Reply::encode) {
                for cut in 0..bytes.len() {
                    assert_eq!(Reply::decode(&bytes[..cut]), None);
                }
                assert_eq!(Reply::decode(&[bytes.as_slice(), &[0]].concat()), None);
            }
        }

        #[test]
        fn unknown_tags_and_values_outside_custody_are_refused() {
            assert_eq!(Call::decode(&[0]), None);
            assert_eq!(Call::decode(&[14]), None);
            assert_eq!(Reply::decode(&[11]), None);
            assert_eq!(Reply::decode(&[0, 13]), None);
            // A boolean that is neither 0 nor 1.
            assert_eq!(Reply::decode(&[3, 2]), None);
            // A chunk index or count past a file's ten.
            let mut open = Call::OpenChunk { id: id(1), index: ChunkIndex::new(0).unwrap(), claim: None }.encode();
            open[17..19].copy_from_slice(&10u16.to_be_bytes());
            assert_eq!(Call::decode(&open), None);
            let mut bytes = Call::Deposit(deposit()).encode();
            let count = 1 + 16 + 1 + 4 + 1 + 32;
            bytes[count..count + 2].copy_from_slice(&11u16.to_be_bytes());
            assert_eq!(Call::decode(&bytes), None);
            // A lifetime outside five minutes to seven days.
            let mut bytes = Call::Deposit(deposit()).encode();
            bytes[18..22].copy_from_slice(&299u32.to_be_bytes());
            assert_eq!(Call::decode(&bytes), None);
        }

        #[test]
        fn a_length_prefix_that_lies_is_refused() {
            let mut bytes =
                Reply::Opened(Some(Opened { payload: payload(), burned: true, chunks: None, claim: None })).encode();
            // Claim the payload is longer than what follows, then shorter.
            let len = 1 + 1 + 1 + 2;
            let real = u32::from_be_bytes(bytes[len..len + 4].try_into().unwrap());
            bytes[len..len + 4].copy_from_slice(&(real + 1).to_be_bytes());
            assert_eq!(Reply::decode(&bytes), None);
            bytes[len..len + 4].copy_from_slice(&(real - 1).to_be_bytes());
            assert_eq!(Reply::decode(&bytes), None);
            bytes[len..len + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert_eq!(Reply::decode(&bytes), None);
        }

        #[test]
        fn a_list_longer_than_one_batch_is_refused() {
            let mut bytes = Call::ForgetGarbage { objects: vec![] }.encode();
            bytes[1..3].copy_from_slice(&1001u16.to_be_bytes());
            bytes.extend(std::iter::repeat_n(0u8, 1001 * 16));
            assert_eq!(Call::decode(&bytes), None);
        }

        #[test]
        fn a_reply_never_carries_a_claim_token() {
            let opened = Opened {
                payload: payload(),
                burned: true,
                chunks: ChunkCount::new(1).ok(),
                claim: Some(custody::ClaimToken::from_array([0xCC; 32])),
            };
            let bytes = Reply::Opened(Some(opened)).encode();
            assert!(!bytes.windows(32).any(|w| w == [0xCC; 32]));
            let Some(Reply::Opened(Some(back))) = Reply::decode(&bytes) else { panic!() };
            assert_eq!(back.claim, None);
        }
    }
}
