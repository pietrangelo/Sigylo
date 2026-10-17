//! Use cases of the Custody context.

use super::ports::{TokenDigest, Vault};
use crate::core::{
    CustodyError, Deposit, DropId, Lifetime, Opened, PostedRequest, Request, Retention, RevocationToken, SealedPayload,
    UnixTime,
};

/// What a sender hands over when answering a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub payload: SealedPayload,
    pub retention: Retention,
    pub lifetime: Lifetime,
}

/// Keeps sealed envelopes on behalf of senders and recipients.
#[derive(Debug)]
pub struct Custodian<V, D> {
    vault: V,
    digest: D,
}

impl<V: Vault, D: TokenDigest> Custodian<V, D> {
    pub fn new(vault: V, digest: D) -> Self {
        Self { vault, digest }
    }

    /// Deposit a sealed secret. The revocation token, if any, is stored only
    /// as a digest, so a vault dump does not let anyone revoke.
    pub async fn deposit(
        &self,
        id: DropId,
        payload: SealedPayload,
        retention: Retention,
        lifetime: Lifetime,
        revocation: Option<&RevocationToken>,
    ) -> Result<UnixTime, CustodyError> {
        let revocation = revocation.map(|token| self.digest.digest(token));
        self.vault.deposit(&Deposit { id, payload, retention, lifetime, revocation }).await
    }

    /// Hand the payload to whoever holds the link. Burn-after-reading
    /// deposits are destroyed by this very call.
    pub async fn open(&self, id: &DropId) -> Result<Opened, CustodyError> {
        self.vault.open(id).await?.ok_or(CustodyError::NotFound)
    }

    /// Destroy a deposit before anyone reads it.
    pub async fn revoke(&self, id: &DropId, token: &RevocationToken) -> Result<(), CustodyError> {
        let digest = self.digest.digest(token);
        if self.vault.revoke(id, &digest).await? { Ok(()) } else { Err(CustodyError::NotFound) }
    }

    pub async fn post_request(&self, request: Request) -> Result<UnixTime, CustodyError> {
        self.vault.post_request(&request).await
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
        };
        self.vault.answer_request(&deposit).await?.ok_or(CustodyError::NotFound)
    }

    pub async fn purge_expired(&self) -> Result<u64, CustodyError> {
        self.vault.purge_expired().await
    }
}
