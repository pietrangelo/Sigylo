//! Use cases of the Custody context.

use core::slice;

use super::ports::{ChunkStore, IdSource, TokenDigest, Vault};
use crate::core::{
    ChunkCount, ChunkIndex, ClaimToken, CustodyError, Deposit, DropId, GARBAGE_BATCH, Lifetime, ObjectName, Opened,
    PostedRequest, Receipt, RecipientKeyBlob, Request, RequestReceipt, Retention, RevocationToken, SealedChunk,
    SealedPayload,
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

/// Keeps sealed envelopes on behalf of senders and recipients: in the vault,
/// and a file's chunks in the chunk store.
#[derive(Debug)]
pub struct Custodian<V, S, D, I> {
    vault: V,
    store: S,
    digest: D,
    ids: I,
}

impl<V: Vault, S: ChunkStore, D: TokenDigest, I: IdSource> Custodian<V, S, D, I> {
    pub fn new(vault: V, store: S, digest: D, ids: I) -> Self {
        Self { vault, store, digest, ids }
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
    ///
    /// The vault first reserves it: a chunk the deposit does not take is
    /// refused before a byte reaches the store, and the fresh object name is
    /// on record (as garbage due later) before the store writes it, so an
    /// upload cut short anywhere leaves nothing that is not collected. Once
    /// the store has the bytes, the vault records the chunk, atomically.
    pub async fn put_chunk(&self, id: &DropId, index: ChunkIndex, chunk: SealedChunk) -> Result<(), CustodyError> {
        let object = self.ids.fresh_object()?;
        // A chunk is at most 1 MiB + 16 bytes.
        let len = chunk.as_bytes().len() as u32;
        if !self.vault.reserve_chunk(id, index, &object, len).await? {
            return Err(CustodyError::NotFound);
        }
        self.store.put(&object, &chunk).await?;
        if self.vault.put_chunk(id, index, &object, len).await? {
            return Ok(());
        }
        // Refused after all (taken meanwhile): no need to wait for the collector.
        self.discard(slice::from_ref(&object)).await;
        Err(CustodyError::NotFound)
    }

    /// Delete objects whose chunks are gone from the store now, and forget
    /// them once it did. If the store fails they stay in the garbage, for
    /// the collector.
    async fn discard(&self, objects: &[ObjectName]) {
        if self.store.delete(objects).await.is_ok() {
            let _ = self.vault.forget_garbage(objects).await;
        }
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
    /// chunks need the claim from [`Custodian::open`] and are destroyed as
    /// they go: burned in the vault only once the store has delivered the
    /// bytes, so a failing store loses nothing, and handed out only by the
    /// call whose burn counted, so never twice.
    pub async fn open_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimToken>,
    ) -> Result<SealedChunk, CustodyError> {
        let digest = claim.map(|claim| self.digest.digest_claim(claim));
        let found = self.vault.open_chunk(id, index, digest.as_ref()).await?.ok_or(CustodyError::NotFound)?;
        let chunk = self.store.get(&found.object).await?.ok_or(CustodyError::NotFound)?;
        if found.burns {
            let digest = digest.ok_or(CustodyError::NotFound)?;
            if !self.vault.burn_chunk(id, index, &digest).await? {
                return Err(CustodyError::NotFound);
            }
            self.discard(slice::from_ref(&found.object)).await;
        }
        Ok(chunk)
    }

    /// Delete from the store the objects whose chunks are gone (burned,
    /// revoked, expired) and whose wait is over, batch after batch while
    /// `more()` says there is time and a full batch suggests there is more.
    /// They leave the garbage only once the store has deleted them, so a
    /// failing store loses track of nothing.
    pub async fn collect_garbage(&self, mut more: impl FnMut() -> bool) -> Result<usize, CustodyError> {
        let mut collected = 0;
        loop {
            let objects = self.vault.garbage(GARBAGE_BATCH).await?;
            if objects.is_empty() {
                return Ok(collected);
            }
            self.store.delete(&objects).await?;
            self.vault.forget_garbage(&objects).await?;
            collected += objects.len();
            if objects.len() < usize::from(GARBAGE_BATCH) || !more() {
                return Ok(collected);
            }
        }
    }

    /// Destroy a deposit before anyone reads it. A file's chunks leave the
    /// store at once.
    pub async fn revoke(&self, id: &DropId, token: &RevocationToken) -> Result<(), CustodyError> {
        let digest = self.digest.digest(token);
        let objects = self.vault.revoke(id, &digest).await?.ok_or(CustodyError::NotFound)?;
        if !objects.is_empty() {
            self.discard(&objects).await;
        }
        Ok(())
    }

    /// Publish a recipient's public key under a fresh id, with a second fresh
    /// id for the private inbox where the answer will be filed. The request
    /// link carries only the first, so whoever reads it on the way to the
    /// sender can neither fetch nor burn the answer.
    pub async fn post_request(
        &self,
        recipient_key: RecipientKeyBlob,
        lifetime: Lifetime,
    ) -> Result<RequestReceipt, CustodyError> {
        let id = self.ids.fresh()?;
        let inbox = self.ids.fresh()?;
        if inbox == id {
            // Only a broken random source repeats itself; filing the answer
            // under the public id would hand it to the request link.
            return Err(CustodyError::RandomnessUnavailable);
        }
        let expires_at = self.vault.post_request(&Request { id, inbox, recipient_key, lifetime }).await?;
        Ok(RequestReceipt { id, inbox, expires_at })
    }

    pub async fn fetch_request(&self, id: &DropId) -> Result<PostedRequest, CustodyError> {
        self.vault.fetch_request(id).await?.ok_or(CustodyError::NotFound)
    }

    /// Answer a request: the request disappears and the answer is stored in
    /// its private inbox, where only the recipient's link will look.
    /// A request can be answered once; answers cannot be revoked by a token.
    /// The receipt names the inbox for the one who answered, so a file's
    /// chunks can follow it there; the request link alone never reveals it.
    pub async fn answer_request(&self, id: DropId, answer: Answer) -> Result<Receipt, CustodyError> {
        // `id` names the request; the vault files the deposit in its inbox.
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
