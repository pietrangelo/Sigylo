//! The relay and the vault talk in [`Call`]s and [`Reply`]s: the relay holds
//! a [`RemoteVault`], the Durable Object runs [`serve`] on its own vault.

use custody::{
    ChunkIndex, ChunkRef, ClaimDigest, CustodyError, Deposit, DropId, ObjectName, Opened, PostedRequest, Receipt,
    Request, RevocationDigest, UnixTime, Vault,
};

use super::ports::Link;
use crate::core::{Call, Reply};

/// A [`Vault`] somewhere else, reached through a [`Link`].
#[derive(Debug)]
pub struct RemoteVault<L> {
    link: L,
}

impl<L: Link> RemoteVault<L> {
    pub fn new(link: L) -> Self {
        Self { link }
    }

    async fn call(&self, call: Call) -> Result<Reply, CustodyError> {
        let bytes = self.link.call(call.encode()).await?;
        match Reply::decode(&bytes).ok_or(CustodyError::VaultUnavailable)? {
            Reply::Failed(error) => Err(error),
            reply => Ok(reply),
        }
    }
}

/// A reply that does not answer the call it came back for.
fn unexpected<T>() -> Result<T, CustodyError> {
    Err(CustodyError::VaultUnavailable)
}

impl<L: Link> Vault for RemoteVault<L> {
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError> {
        match self.call(Call::Deposit(deposit.clone())).await? {
            Reply::Expires(at) => Ok(at),
            _ => unexpected(),
        }
    }

    async fn open(&self, id: &DropId, claim: &ClaimDigest) -> Result<Option<Opened>, CustodyError> {
        match self.call(Call::Open { id: *id, claim: *claim }).await? {
            Reply::Opened(opened) => Ok(opened),
            _ => unexpected(),
        }
    }

    async fn reserve_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        match self.call(Call::ReserveChunk { id: *id, index, object: *object, len }).await? {
            Reply::Flag(flag) => Ok(flag),
            _ => unexpected(),
        }
    }

    async fn put_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        object: &ObjectName,
        len: u32,
    ) -> Result<bool, CustodyError> {
        match self.call(Call::PutChunk { id: *id, index, object: *object, len }).await? {
            Reply::Flag(flag) => Ok(flag),
            _ => unexpected(),
        }
    }

    async fn open_chunk(
        &self,
        id: &DropId,
        index: ChunkIndex,
        claim: Option<&ClaimDigest>,
    ) -> Result<Option<ChunkRef>, CustodyError> {
        match self.call(Call::OpenChunk { id: *id, index, claim: claim.copied() }).await? {
            Reply::Chunk(chunk) => Ok(chunk),
            _ => unexpected(),
        }
    }

    async fn burn_chunk(&self, id: &DropId, index: ChunkIndex, claim: &ClaimDigest) -> Result<bool, CustodyError> {
        match self.call(Call::BurnChunk { id: *id, index, claim: *claim }).await? {
            Reply::Flag(flag) => Ok(flag),
            _ => unexpected(),
        }
    }

    async fn garbage(&self, limit: u16) -> Result<Vec<ObjectName>, CustodyError> {
        match self.call(Call::Garbage { limit }).await? {
            Reply::Objects(objects) => Ok(objects),
            _ => unexpected(),
        }
    }

    async fn forget_garbage(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        // A call names one batch at most.
        for batch in objects.chunks(usize::from(custody::GARBAGE_BATCH)) {
            match self.call(Call::ForgetGarbage { objects: batch.to_vec() }).await? {
                Reply::Done => {}
                _ => return unexpected(),
            }
        }
        Ok(())
    }

    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<Option<Vec<ObjectName>>, CustodyError> {
        match self.call(Call::Revoke { id: *id, digest: *digest }).await? {
            Reply::Revoked(objects) => Ok(objects),
            _ => unexpected(),
        }
    }

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError> {
        match self.call(Call::PostRequest(request.clone())).await? {
            Reply::Expires(at) => Ok(at),
            _ => unexpected(),
        }
    }

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError> {
        match self.call(Call::FetchRequest { id: *id }).await? {
            Reply::Request(request) => Ok(request),
            _ => unexpected(),
        }
    }

    async fn answer_request(&self, answer: &Deposit) -> Result<Option<Receipt>, CustodyError> {
        match self.call(Call::AnswerRequest(answer.clone())).await? {
            Reply::Answered(receipt) => Ok(receipt),
            _ => unexpected(),
        }
    }

    async fn purge_expired(&self) -> Result<u64, CustodyError> {
        match self.call(Call::PurgeExpired).await? {
            Reply::Purged(gone) => Ok(gone),
            _ => unexpected(),
        }
    }
}

/// Runs one encoded call on `vault` and encodes its reply. A call that does
/// not decode gets [`CustodyError::VaultUnavailable`], like any fault.
pub async fn serve(vault: &impl Vault, call: &[u8]) -> Vec<u8> {
    let Some(call) = Call::decode(call) else {
        return Reply::Failed(CustodyError::VaultUnavailable).encode();
    };
    let reply = match call {
        Call::Deposit(deposit) => vault.deposit(&deposit).await.map(Reply::Expires),
        Call::Open { id, claim } => vault.open(&id, &claim).await.map(|opened| {
            // The claim token stays with the custodian that drew it.
            Reply::Opened(opened.map(|o| Opened { claim: None, ..o }))
        }),
        Call::ReserveChunk { id, index, object, len } => {
            vault.reserve_chunk(&id, index, &object, len).await.map(Reply::Flag)
        }
        Call::PutChunk { id, index, object, len } => vault.put_chunk(&id, index, &object, len).await.map(Reply::Flag),
        Call::OpenChunk { id, index, claim } => vault.open_chunk(&id, index, claim.as_ref()).await.map(Reply::Chunk),
        Call::BurnChunk { id, index, claim } => vault.burn_chunk(&id, index, &claim).await.map(Reply::Flag),
        Call::Garbage { limit } => vault.garbage(limit).await.map(Reply::Objects),
        Call::ForgetGarbage { objects } => vault.forget_garbage(&objects).await.map(|()| Reply::Done),
        Call::Revoke { id, digest } => vault.revoke(&id, &digest).await.map(Reply::Revoked),
        Call::PostRequest(request) => vault.post_request(&request).await.map(Reply::Expires),
        Call::FetchRequest { id } => vault.fetch_request(&id).await.map(Reply::Request),
        Call::AnswerRequest(answer) => vault.answer_request(&answer).await.map(Reply::Answered),
        Call::PurgeExpired => vault.purge_expired().await.map(Reply::Purged),
    };
    reply.unwrap_or_else(Reply::Failed).encode()
}
