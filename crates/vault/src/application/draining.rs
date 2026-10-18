//! Moving custody from one vault to another without losing anything: while
//! the old one drains (at most the longest lifetime, 7 days), everything new
//! goes to the new vault, and whatever is asked for by id is looked for in
//! the new vault first, then in the old one. Nothing is copied: what lives
//! in the old vault stays there until it is read, revoked or expires.

use custody::{
    ChunkIndex, ChunkRef, ClaimDigest, CustodyError, Deposit, DropId, GARBAGE_BATCH, ObjectName, Opened, PostedRequest,
    Receipt, Request, RevocationDigest, UnixTime, Vault,
};

#[derive(Debug)]
pub struct Draining<N, O> {
    new: N,
    old: O,
}

impl<N: Vault, O: Vault> Draining<N, O> {
    pub fn new(new: N, old: O) -> Self {
        Self { new, old }
    }
}

impl<N: Vault, O: Vault> Vault for Draining<N, O> {
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError> {
        self.new.deposit(deposit).await
    }

    async fn open(&self, id: &DropId, claim: &ClaimDigest) -> Result<Option<Opened>, CustodyError> {
        match self.new.open(id, claim).await? {
            Some(opened) => Ok(Some(opened)),
            None => self.old.open(id, claim).await,
        }
    }

    async fn reserve_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        Ok(self.new.reserve_chunk(id, index, object, len).await?
            || self.old.reserve_chunk(id, index, object, len).await?)
    }

    async fn put_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        Ok(self.new.put_chunk(id, index, object, len).await? || self.old.put_chunk(id, index, object, len).await?)
    }

    async fn open_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimDigest>,
    ) -> Result<Option<ChunkRef>, CustodyError> {
        match self.new.open_chunk(id, index, claim).await? {
            Some(chunk) => Ok(Some(chunk)),
            None => self.old.open_chunk(id, index, claim).await,
        }
    }

    async fn burn_chunk(&self, id: &DropId, index: ChunkIndex, claim: &ClaimDigest) -> Result<bool, CustodyError> {
        Ok(self.new.burn_chunk(id, index, claim).await? || self.old.burn_chunk(id, index, claim).await?)
    }

    async fn garbage(&self, limit: u16) -> Result<Vec<ObjectName>, CustodyError> {
        let mut objects = self.new.garbage(limit).await?;
        let room = limit.min(GARBAGE_BATCH).saturating_sub(objects.len() as u16);
        if room > 0 {
            // The old vault never holds up the new one's cleaning.
            objects.extend(self.old.garbage(room).await.unwrap_or_default());
        }
        Ok(objects)
    }

    async fn forget_garbage(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        // Each vault forgets the names it knows and ignores the rest.
        // An object the old vault fails to forget is deleted again later, harmlessly.
        self.new.forget_garbage(objects).await?;
        let _ = self.old.forget_garbage(objects).await;
        Ok(())
    }

    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<Option<Vec<ObjectName>>, CustodyError> {
        match self.new.revoke(id, digest).await? {
            Some(objects) => Ok(Some(objects)),
            None => self.old.revoke(id, digest).await,
        }
    }

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError> {
        self.new.post_request(request).await
    }

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError> {
        match self.new.fetch_request(id).await? {
            Some(request) => Ok(Some(request)),
            None => self.old.fetch_request(id).await,
        }
    }

    async fn answer_request(&self, answer: &Deposit) -> Result<Option<Receipt>, CustodyError> {
        // A request lives where it was posted, and its answer goes there too.
        match self.new.answer_request(answer).await? {
            Some(receipt) => Ok(Some(receipt)),
            None => self.old.answer_request(answer).await,
        }
    }

    async fn purge_expired(&self) -> Result<u64, CustodyError> {
        Ok(self.new.purge_expired().await? + self.old.purge_expired().await.unwrap_or(0))
    }
}
