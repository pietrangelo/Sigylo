//! Use cases of the Custody context.

use super::ports::{IdSource, TokenDigest, Vault};
use crate::core::{
    CustodyError, Deposit, DropId, Lifetime, Opened, PostedRequest, Receipt, RecipientKeyBlob, Request, RequestReceipt,
    Retention, RevocationToken, SealedPayload, UnixTime,
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
        let id = self.ids.fresh()?;
        let revocation = revocation.map(|token| self.digest.digest(token));
        let expires_at = self.vault.deposit(&Deposit { id, payload, retention, lifetime, revocation }).await?;
        Ok(Receipt { id, expires_at })
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
    pub async fn answer_request(&self, id: DropId, answer: Answer) -> Result<UnixTime, CustodyError> {
        // `id` names the request; the vault files the deposit in its inbox.
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
