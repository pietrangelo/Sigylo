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

/// Every statement the vault sends.
///
/// Hyperdrive caches the result of a `SELECT` it believes is read-only for up
/// to a minute, and it cannot see that `custody.open` deletes the row it
/// returns. A cached `open` would hand a burned, revoked or expired secret out
/// again. Hyperdrive never caches a statement that calls a STABLE or VOLATILE
/// built-in, so each one also selects `now()`: a second line of defence behind
/// the Hyperdrive configuration created with `--caching-disabled`.
mod sql {
    pub const DEPOSIT: &str = "select custody.deposit($1, $2, $3, $4, $5), now()";
    pub const OPEN: &str = "select payload, burned, now() from custody.open($1)";
    pub const REVOKE: &str = "select custody.revoke($1, $2), now()";
    pub const POST_REQUEST: &str = "select custody.post_request($1, $2, $3, $4), now()";
    pub const FETCH_REQUEST: &str = "select recipient_key, expires_at, now() from custody.fetch_request($1)";
    pub const ANSWER_REQUEST: &str = "select custody.answer_request($1, $2, $3, $4), now()";
    pub const PURGE_EXPIRED: &str = "select custody.purge_expired(), now()";

    #[cfg(test)]
    pub const ALL: [&str; 7] = [DEPOSIT, OPEN, REVOKE, POST_REQUEST, FETCH_REQUEST, ANSWER_REQUEST, PURGE_EXPIRED];
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
                sql::DEPOSIT,
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
        let row = self.client.query_opt(sql::OPEN, &[&id.as_bytes().as_slice()]).await.map_err(vault_error)?;
        row.map(|row| Ok(Opened { payload: payload(row.get(0))?, burned: row.get(1) })).transpose()
    }

    async fn revoke(&self, id: &DropId, digest: &RevocationDigest) -> Result<bool, CustodyError> {
        let row = self
            .client
            .query_one(sql::REVOKE, &[&id.as_bytes().as_slice(), &digest.as_bytes().as_slice()])
            .await
            .map_err(vault_error)?;
        Ok(row.get(0))
    }

    async fn post_request(&self, request: &Request) -> Result<UnixTime, CustodyError> {
        let row = self
            .client
            .query_one(
                sql::POST_REQUEST,
                &[
                    &request.id.as_bytes().as_slice(),
                    &request.inbox.as_bytes().as_slice(),
                    &request.recipient_key.as_bytes(),
                    &(request.lifetime.seconds() as i32),
                ],
            )
            .await
            .map_err(vault_error)?;
        Ok(UnixTime(row.get(0)))
    }

    async fn fetch_request(&self, id: &DropId) -> Result<Option<PostedRequest>, CustodyError> {
        let row = self.client.query_opt(sql::FETCH_REQUEST, &[&id.as_bytes().as_slice()]).await.map_err(vault_error)?;
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
                sql::ANSWER_REQUEST,
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
        let row = self.client.query_one(sql::PURGE_EXPIRED, &[]).await.map_err(vault_error)?;
        Ok(row.get::<_, i64>(0).max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::sql;

    mod adversary {
        use super::*;

        #[test]
        fn no_statement_can_be_served_from_the_hyperdrive_cache() {
            for statement in sql::ALL {
                assert!(statement.contains("now()"), "cacheable by Hyperdrive: {statement}");
                assert!(!statement.contains("--") && !statement.contains("/*"), "comments are no cache control");
            }
        }
    }
}
