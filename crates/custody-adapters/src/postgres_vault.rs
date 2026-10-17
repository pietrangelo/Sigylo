use custody::{
    CustodyError, Deposit, DropId, Opened, PostedRequest, RecipientKeyBlob, Request, Retention, RevocationDigest,
    SealedPayload, UnixTime, Vault,
};
use tokio_postgres::{Client, Error, error::SqlState};

/// The vault on PostgreSQL. Every operation is one call to a `custody.*`
/// function, so atomicity and expiry are decided inside the database.
#[derive(Debug)]
pub struct PostgresVault<'a> {
    client: &'a Client,
}

impl<'a> PostgresVault<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }
}

fn vault_error(error: Error) -> CustodyError {
    match error.code() {
        Some(code) if *code == SqlState::UNIQUE_VIOLATION => CustodyError::AlreadyExists,
        Some(code) if *code == SqlState::INVALID_PARAMETER_VALUE => CustodyError::LifetimeOutOfRange,
        _ => CustodyError::VaultUnavailable,
    }
}

/// A payload read back from the database. The table's CHECK constraint
/// matches the domain's bounds, so this only fails on a corrupted row.
fn payload(bytes: Vec<u8>) -> Result<SealedPayload, CustodyError> {
    SealedPayload::new(bytes).map_err(|_| CustodyError::VaultUnavailable)
}

fn lifetime(deposit: &Deposit) -> i32 {
    // Lifetime is capped at 7 days, far inside i32.
    deposit.lifetime.seconds() as i32
}

impl Vault for PostgresVault<'_> {
    async fn deposit(&self, deposit: &Deposit) -> Result<UnixTime, CustodyError> {
        let revocation = deposit.revocation.as_ref().map(|d| d.as_bytes().as_slice());
        let row = self
            .client
            .query_one(
                "select custody.deposit($1, $2, $3, $4, $5)",
                &[
                    &deposit.id.as_bytes().as_slice(),
                    &deposit.payload.as_bytes(),
                    &(deposit.retention == Retention::BurnAfterReading),
                    &lifetime(deposit),
                    &revocation,
                ],
            )
            .await
            .map_err(vault_error)?;
        Ok(UnixTime(row.get(0)))
    }

    async fn open(&self, id: &DropId) -> Result<Option<Opened>, CustodyError> {
        let row = self
            .client
            .query_opt("select payload, burned from custody.open($1)", &[&id.as_bytes().as_slice()])
            .await
            .map_err(vault_error)?;
        row.map(|row| Ok(Opened { payload: payload(row.get(0))?, burned: row.get(1) })).transpose()
    }

    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<bool, CustodyError> {
        let row = self
            .client
            .query_one("select custody.revoke($1, $2)", &[&id.as_bytes().as_slice(), &digest.as_bytes().as_slice()])
            .await
            .map_err(vault_error)?;
        Ok(row.get(0))
    }

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError> {
        let row = self
            .client
            .query_one(
                "select custody.post_request($1, $2, $3)",
                &[
                    &request.id.as_bytes().as_slice(),
                    &request.recipient_key.as_bytes(),
                    &(request.lifetime.seconds() as i32),
                ],
            )
            .await
            .map_err(vault_error)?;
        Ok(UnixTime(row.get(0)))
    }

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError> {
        let row = self
            .client
            .query_opt("select recipient_key, expires_at from custody.fetch_request($1)", &[&id.as_bytes().as_slice()])
            .await
            .map_err(vault_error)?;
        row.map(|row| {
            Ok(PostedRequest {
                recipient_key: RecipientKeyBlob::new(row.get(0)).map_err(|_| CustodyError::VaultUnavailable)?,
                expires_at: UnixTime(row.get(1)),
            })
        })
        .transpose()
    }

    async fn answer_request(&self, answer: &Deposit) -> Result<Option<UnixTime>, CustodyError> {
        let row = self
            .client
            .query_one(
                "select custody.answer_request($1, $2, $3, $4)",
                &[
                    &answer.id.as_bytes().as_slice(),
                    &answer.payload.as_bytes(),
                    &(answer.retention == Retention::BurnAfterReading),
                    &lifetime(answer),
                ],
            )
            .await
            .map_err(vault_error)?;
        Ok(row.get::<_, Option<i64>>(0).map(UnixTime))
    }

    async fn purge_expired(&self) -> Result<u64, CustodyError> {
        let row = self.client.query_one("select custody.purge_expired()", &[]).await.map_err(vault_error)?;
        Ok(row.get::<_, i64>(0).max(0) as u64)
    }
}
