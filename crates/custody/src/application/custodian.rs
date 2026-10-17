//! Use cases of the Custody context.

use super::ports::{IdSource, TokenDigest, Vault};
use crate::core::{
    ChunkCount, ChunkIndex, ClaimToken, CustodyError, Deposit, DropId, Lifetime, Opened, PostedRequest, Receipt,
    RecipientKeyBlob, Request, Retention, RevocationToken, SealedChunk, SealedPayload, UnixTime,
};

/// What a sender hands over when answering a request. For a file, the
/// payload is its sealed manifest and the chunks are uploaded after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub payload: SealedPayload,
    pub retention: Retention,
    pub lifetime: Lifetime,
    pub chunks: Option<ChunkCount>,
}

/// Keeps sealed envelopes on behalf of senders and recipients.
#[derive(Debug)]
pub struct Custodian<V, D, I> {
    vault: V,
    digest: D,
    ids: I,
}

impl<V: Vault, D: TokenDigest, I: IdSource> Custodian<V, D, I> {
    pub fn new(vault: V, digest: D, ids: I) -> Self {
        Self { vault, digest, ids }
    }

    /// Deposit a sealed secret under a fresh id. The revocation token, if
    /// any, is stored only as a digest, so a vault dump does not let anyone revoke.
    pub async fn deposit(
        &self,
        payload: SealedPayload,
        retention: Retention,
        lifetime: Lifetime,
        revocation: Option<&RevocationToken>,
    ) -> Result<Receipt, CustodyError> {
        self.deposit_with(payload, None, retention, lifetime, revocation).await
    }

    /// Deposit a file: its sealed manifest now, its `chunks` with
    /// [`Custodian::put_chunk`] right after. Nobody can open it before the
    /// last chunk is in.
    pub async fn deposit_file(
        &self,
        manifest: SealedPayload,
        chunks: ChunkCount,
        retention: Retention,
        lifetime: Lifetime,
        revocation: Option<&RevocationToken>,
    ) -> Result<Receipt, CustodyError> {
        self.deposit_with(manifest, Some(chunks), retention, lifetime, revocation).await
    }

    async fn deposit_with(
        &self,
        payload: SealedPayload,
        chunks: Option<ChunkCount>,
        retention: Retention,
        lifetime: Lifetime,
        revocation: Option<&RevocationToken>,
    ) -> Result<Receipt, CustodyError> {
        let id = self.ids.fresh()?;
        let revocation = revocation.map(|token| self.digest.digest(token));
        let deposit = Deposit { id, payload, retention, lifetime, revocation, chunks };
        let expires_at = self.vault.deposit(&deposit).await?;
        Ok(Receipt { id, expires_at })
    }

    /// Store one chunk of a file deposited under `id` (or of an answer).
    pub async fn put_chunk(&self, id: &DropId, index: ChunkIndex, chunk: SealedChunk) -> Result<(), CustodyError> {
        if self.vault.put_chunk(id, index, &chunk).await? { Ok(()) } else { Err(CustodyError::NotFound) }
    }

    /// Hand the payload to whoever holds the link. Burn-after-reading
    /// deposits are destroyed by this very call; a burn-after-reading file is
    /// claimed, and the claim token that releases its chunks comes back here only.
    pub async fn open(&self, id: &DropId) -> Result<Opened, CustodyError> {
        let claim = self.ids.fresh_claim()?;
        let opened = self.vault.open(id, &self.digest.digest_claim(&claim)).await?.ok_or(CustodyError::NotFound)?;
        let claimed = opened.burned && opened.chunks.is_some();
        Ok(Opened { claim: claimed.then_some(claim), ..opened })
    }

    /// Hand out one chunk of an opened file. A burn-after-reading file's
    /// chunks need the claim from [`Custodian::open`] and are destroyed as they go.
    pub async fn open_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimToken>,
    ) -> Result<SealedChunk, CustodyError> {
        let digest = claim.map(|claim| self.digest.digest_claim(claim));
        self.vault.open_chunk(id, index, digest.as_ref()).await?.ok_or(CustodyError::NotFound)
    }

    /// Destroy a deposit before anyone reads it.
    pub async fn revoke(&self, id: &DropId, token: &RevocationToken) -> Result<(), CustodyError> {
        let digest = self.digest.digest(token);
        if self.vault.revoke(id, &digest).await? { Ok(()) } else { Err(CustodyError::NotFound) }
    }

    /// Publish a recipient's public key under a fresh id.
    pub async fn post_request(
        &self,
        recipient_key: RecipientKeyBlob,
        lifetime: Lifetime,
    ) -> Result<Receipt, CustodyError> {
        let id = self.ids.fresh()?;
        let expires_at = self.vault.post_request(&Request { id, recipient_key, lifetime }).await?;
        Ok(Receipt { id, expires_at })
    }

    pub async fn fetch_request(&self, id: &DropId) -> Result<PostedRequest, CustodyError> {
        self.vault.fetch_request(id).await?.ok_or(CustodyError::NotFound)
    }

    /// Answer a request: the request disappears and the answer is stored
    /// under the same id, where the recipient's private link will look.
    /// A request can be answered once; answers cannot be revoked by a token.
    pub async fn answer_request(&self, id: DropId, answer: Answer) -> Result<UnixTime, CustodyError> {
        let deposit = Deposit {
            id,
            payload: answer.payload,
            retention: answer.retention,
            lifetime: answer.lifetime,
            revocation: None,
            chunks: answer.chunks,
        };
        self.vault.answer_request(&deposit).await?.ok_or(CustodyError::NotFound)
    }

    pub async fn purge_expired(&self) -> Result<u64, CustodyError> {
        self.vault.purge_expired().await
    }
}
