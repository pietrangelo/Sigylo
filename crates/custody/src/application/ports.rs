//! Ports of the Custody context.

use crate::core::{
    CustodyError, Deposit, DropId, Opened, PostedRequest, Request, RevocationDigest, RevocationToken, UnixTime,
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
///   this only guards against a broken random source).
// Workers run on one thread, so the futures need not be `Send`.
#[allow(async_fn_in_trait)]
pub trait Vault {
    /// Stores the deposit and returns when it expires.
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError>;

    /// Returns the payload if it is live, burning it when its retention says so.
    async fn open(&self, id: &DropId) -> Result<Option<Opened>, CustodyError>;

    /// Deletes a live deposit whose stored digest matches. True if deleted.
    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<bool, CustodyError>;

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError>;

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError>;

    /// Atomically consumes the live request `answer.id` and stores `answer`
    /// under that request's inbox id.
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
pub trait IdSource {
    fn fresh(&self) -> Result<DropId, CustodyError>;
}

/// One-way digest of revocation tokens (SHA-256).
pub trait TokenDigest {
    fn digest(&self, token: &RevocationToken) -> RevocationDigest;
}
