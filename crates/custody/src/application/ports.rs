//! Ports of the Custody context.

use crate::core::{
    ChunkIndex, ChunkRef, ClaimDigest, ClaimToken, CustodyError, Deposit, DropId, ObjectName, Opened, PostedRequest,
    Receipt, Request, RevocationDigest, RevocationToken, SealedChunk, UnixTime,
};

/// Durable, blind storage of deposits and requests.
///
/// Contract every adapter must honour (checked by the contract tests in
/// `custody-adapters`):
///
/// * the vault's own clock is authoritative for expiry; anything past
///   `expires_at` behaves as if it never existed;
/// * [`Vault::open`] on a [`crate::Retention::BurnAfterReading`] deposit
///   returns it **at most once**, even under concurrent reads;
/// * [`Vault::answer_request`] consumes the request and stores the answer
///   under the request's private inbox id (never its public id) in one
///   atomic step, at most once;
/// * ids are unique across deposits: a second deposit under a live id fails
///   with [`CustodyError::AlreadyExists`] (ids come from an [`IdSource`], so
///   this only guards against a broken random source);
/// * a file deposit opens only once all its chunks are in; each chunk is
///   written once, and only before the deposit has been opened; every chunk
///   but the last is full ([`crate::ChunkCount::takes`]);
/// * opening a burn-after-reading file claims it instead of deleting it: from
///   then on it cannot be opened again, its chunks go only to the holder of
///   the claim, each burned at most once, and the claim lapses after
///   [`crate::CLAIM_WINDOW_SECONDS`] at most. The deposit goes with its last chunk;
/// * the vault never holds a chunk's bytes, only the name of its object in
///   the [`ChunkStore`]. Whenever a chunk goes (burned, revoked, expired), its
///   name joins the garbage until [`Vault::forget_garbage`], and is handed
///   out by [`Vault::garbage`] only after [`crate::GARBAGE_GRACE_SECONDS`];
///   a reserved upload's name waits there [`crate::RESERVATION_SECONDS`];
/// * the ceiling counts every row, not only the bytes it holds, and the chunk
///   budget counts the garbage too: storing (a deposit, a request, an answer
///   or a chunk reservation) may fail with [`CustodyError::StorageFull`],
///   and then changes nothing; reading never does.
// Workers run on one thread, so the futures need not be `Send`.
#[allow(async_fn_in_trait)]
pub trait Vault {
    /// Stores the deposit and returns when it expires.
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError>;

    /// Returns the payload if it is live (and complete), burning it when its
    /// retention says so. A burn-after-reading file is claimed with `claim`.
    /// The returned [`Opened::claim`] is always `None`: the custodian holds the token.
    async fn open(&self, id: &DropId, claim: &ClaimDigest) -> Result<Option<Opened>, CustodyError>;

    /// Before a chunk is stored: whether the live, unopened file deposit
    /// takes chunk `index` of `len` bytes (inside its count, not in yet, full
    /// unless last). If it does, `object` joins the garbage for
    /// [`crate::RESERVATION_SECONDS`], so it is collected unless
    /// [`Vault::put_chunk`] records it. False, with nothing written, when it
    /// does not; [`CustodyError::StorageFull`] when the rows or the chunks
    /// would outgrow their room.
    async fn reserve_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError>;

    /// After the store kept it: records that chunk `index` is the reserved
    /// `object`, of `len` bytes, and takes it out of the garbage. False when
    /// the reservation is gone or older than [`crate::RESERVATION_FRESH_SECONDS`],
    /// or the deposit no longer takes that chunk (one already in included).
    async fn put_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError>;

    /// Finds one chunk of a complete file, of a burn-after-reading file only
    /// against its claim. Burns nothing: see [`Vault::burn_chunk`].
    async fn open_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimDigest>,
    ) -> Result<Option<ChunkRef>, CustodyError>;

    /// Burns chunk `index` of a burn-after-reading file claimed with `claim`,
    /// once it was read from the store. True for exactly one caller, even
    /// under concurrent burns: only that one may hand the chunk out.
    async fn burn_chunk(&self, id: &DropId, index: ChunkIndex, claim: &ClaimDigest) -> Result<bool, CustodyError>;

    /// Up to `limit` objects whose chunk is gone, that may still be in the
    /// store, and whose wait in the garbage is over.
    async fn garbage(&self, limit: u16) -> Result<Vec<ObjectName>, CustodyError>;

    /// Drops objects from the garbage once the store deleted them.
    async fn forget_garbage(&self, objects: &[ObjectName]) -> Result<(), CustodyError>;

    /// Deletes a live deposit whose stored digest matches, and names the
    /// objects of its chunks (now in the garbage). `None` if nothing was deleted.
    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<Option<Vec<ObjectName>>, CustodyError>;

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError>;

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError>;

    /// Atomically consumes the live request `answer.id` and stores `answer`
    /// under that request's inbox id, which the receipt names.
    /// `None` when there was no live request to answer.
    async fn answer_request(&self, answer: &Deposit) -> Result<Option<Receipt>, CustodyError>;

    /// Physically removes everything expired. Returns how many rows went.
    async fn purge_expired(&self) -> Result<u64, CustodyError>;
}

/// Where the sealed chunks of files live, apart from the vault (Cloudflare R2).
///
/// Blind like the vault: objects are opaque bytes under names the custodian
/// draws itself, never a client, so nobody can overwrite or guess one.
#[allow(async_fn_in_trait)]
pub trait ChunkStore {
    async fn put(&self, object: &ObjectName, chunk: &SealedChunk) -> Result<(), CustodyError>;

    async fn get(&self, object: &ObjectName) -> Result<Option<SealedChunk>, CustodyError>;

    /// Deletes the objects; deleting one that is not there is no error.
    async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError>;
}

/// Fresh, unguessable ids for deposits and requests.
///
/// The custodian picks every id itself and never takes one from a client:
/// otherwise whoever read a burn-after-reading secret first could deposit a
/// copy (or a forgery, sealed with the key from the link) under the same id,
/// and the real recipient would open it without noticing anything.
///
/// It also draws the claim tokens that bind a burn-after-reading file to
/// whoever opened it, and the names of stored chunks.
pub trait IdSource {
    fn fresh(&self) -> Result<DropId, CustodyError>;

    fn fresh_claim(&self) -> Result<ClaimToken, CustodyError>;

    /// The name of a chunk's object in the [`ChunkStore`].
    fn fresh_object(&self) -> Result<ObjectName, CustodyError>;
}

/// One-way digest of revocation and claim tokens (SHA-256).
pub trait TokenDigest {
    fn digest(&self, token: &RevocationToken) -> RevocationDigest;

    fn digest_claim(&self, claim: &ClaimToken) -> ClaimDigest;
}
