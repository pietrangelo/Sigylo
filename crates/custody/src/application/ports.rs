//! Ports of the Custody context.

use crate::core::{
    ChunkIndex, ClaimDigest, ClaimToken, CustodyError, Deposit, DropId, Opened, PostedRequest, Request,
    RevocationDigest, RevocationToken, SealedChunk, UnixTime,
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
///   under the request's id in one atomic step, at most once;
/// * ids are unique across deposits: a second deposit under a live id fails
///   with [`CustodyError::AlreadyExists`] (ids come from an [`IdSource`], so
///   this only guards against a broken random source);
/// * a file deposit opens only once all its chunks are in; each chunk is
///   written once, and only before the deposit has been opened;
/// * opening a burn-after-reading file claims it instead of deleting it: from
///   then on it cannot be opened again, its chunks go only to the holder of
///   the claim, each at most once, and the claim lapses after
///   [`crate::CLAIM_WINDOW_SECONDS`] at most. The deposit goes with its last chunk.
// Workers run on one thread, so the futures need not be `Send`.
#[allow(async_fn_in_trait)]
pub trait Vault {
    /// Stores the deposit and returns when it expires.
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError>;

    /// Returns the payload if it is live (and complete), burning it when its
    /// retention says so. A burn-after-reading file is claimed with `claim`.
    /// The returned [`Opened::claim`] is always `None`: the custodian holds the token.
    async fn open(&self, id: &DropId, claim: &ClaimDigest) -> Result<Option<Opened>, CustodyError>;

    /// Stores one chunk of a file deposit that is live and not yet opened.
    /// False when there is no such deposit or the index is past its count;
    /// [`CustodyError::AlreadyExists`] when that chunk is already in.
    async fn put_chunk(&self, id: &DropId, index: ChunkIndex, chunk: &SealedChunk) -> Result<bool, CustodyError>;

    /// Hands out one chunk of a complete file: of a burn-after-reading file
    /// only against its claim, and then at most once.
    async fn open_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimDigest>,
    ) -> Result<Option<SealedChunk>, CustodyError>;

    /// Deletes a live deposit whose stored digest matches. True if deleted.
    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<bool, CustodyError>;

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError>;

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError>;

    /// Atomically consumes the live request `answer.id` and stores `answer`.
    /// `None` when there was no live request to answer.
    async fn answer_request(&self, answer: &Deposit) -> Result<Option<UnixTime>, CustodyError>;

    /// Physically removes everything expired. Returns how many rows went.
    async fn purge_expired(&self) -> Result<u64, CustodyError>;
}

/// Fresh, unguessable ids for deposits and requests.
///
/// The custodian picks every id itself and never takes one from a client:
/// otherwise whoever read a burn-after-reading secret first could deposit a
/// copy (or a forgery, sealed with the key from the link) under the same id,
/// and the real recipient would open it without noticing anything.
///
/// It also draws the claim tokens that bind a burn-after-reading file to
/// whoever opened it.
pub trait IdSource {
    fn fresh(&self) -> Result<DropId, CustodyError>;

    fn fresh_claim(&self) -> Result<ClaimToken, CustodyError>;
}

/// One-way digest of revocation and claim tokens (SHA-256).
pub trait TokenDigest {
    fn digest(&self, token: &RevocationToken) -> RevocationDigest;

    fn digest_claim(&self, claim: &ClaimToken) -> ClaimDigest;
}
