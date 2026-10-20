use access::{
    AccessError, AccountId, AccountStore, Budget, Keyring, KeyringSnapshot, KeyringVersion, KeyringWrite, LoginHandle,
    LoginState, RegistrationRecord, SessionDigest, Throttle, UnixTime,
};
use tokio_postgres::Client;
use tokio_postgres::error::SqlState;

/// The account store on PostgreSQL. Every operation is one call to an
/// `access.*` function, so atomicity and expiry are decided inside the database.
#[derive(Debug)]
pub struct PostgresAccounts<'a> {
    client: &'a Client,
}

impl<'a> PostgresAccounts<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }
}

/// Every statement the store sends. Each also selects `now()`, so Hyperdrive
/// never serves one from its cache (see custody-adapters' vault): a cached
/// `take_login` would let a login handle work twice, a cached `keyring` would
/// hand out a keyring after sign-out.
mod sql {
    pub const ENROLL: &str = "select access.enroll($1, $2), now()";
    pub const REGISTRATION: &str = "select access.registration($1), now()";
    pub const PARK_LOGIN: &str = "select access.park_login($1, $2, $3, $4), now()";
    pub const TAKE_LOGIN: &str = "select account, state, now() from access.take_login($1)";
    pub const OPEN_SESSION: &str = "select access.open_session($1, $2, $3), now()";
    pub const CLOSE_SESSION: &str = "select access.close_session($1), now()";
    pub const CLOSE_SESSIONS: &str = "select access.close_sessions($1), now()";
    pub const KEYRING: &str = "select keyring, version, now() from access.keyring($1)";
    pub const STORE_KEYRING: &str = "select access.store_keyring($1, $2, $3), now()";
    pub const CLOSE_ACCOUNT: &str = "select access.close_account($1), now()";
    pub const PURGE_EXPIRED: &str = "select access.purge_expired(), now()";
    pub const ADMIT: &str = "select access.admit($1, $2, $3), now()";

    #[cfg(test)]
    pub const ALL: [&str; 12] = [
        ENROLL,
        REGISTRATION,
        PARK_LOGIN,
        TAKE_LOGIN,
        OPEN_SESSION,
        CLOSE_SESSION,
        CLOSE_SESSIONS,
        KEYRING,
        STORE_KEYRING,
        CLOSE_ACCOUNT,
        PURGE_EXPIRED,
        ADMIT,
    ];
}

/// A full account store (SQLSTATE 53100, raised by `access.ensure_room`)
/// is reported as such; anything else means the store could not be used.
fn unavailable(e: tokio_postgres::Error) -> AccessError {
    if e.code() == Some(&SqlState::DISK_FULL) { AccessError::StorageFull } else { AccessError::StoreUnavailable }
}

/// Rows read back are re-validated; the table constraints match the domain,
/// so this only fails on a corrupted row.
fn corrupt(_: AccessError) -> AccessError {
    AccessError::StoreUnavailable
}

fn version(v: i64) -> Result<KeyringVersion, AccessError> {
    u64::try_from(v).map(KeyringVersion).map_err(|_| AccessError::StoreUnavailable)
}

impl AccountStore for PostgresAccounts<'_> {
    async fn enroll(&self, account: &AccountId, record: &RegistrationRecord) -> Result<bool, AccessError> {
        let row = self
            .client
            .query_one(sql::ENROLL, &[&account.as_bytes().as_slice(), &record.as_bytes()])
            .await
            .map_err(unavailable)?;
        Ok(row.get(0))
    }

    async fn record(&self, account: &AccountId) -> Result<Option<RegistrationRecord>, AccessError> {
        let row =
            self.client.query_one(sql::REGISTRATION, &[&account.as_bytes().as_slice()]).await.map_err(unavailable)?;
        row.get::<_, Option<Vec<u8>>>(0).map(|r| RegistrationRecord::from_slice(&r).map_err(corrupt)).transpose()
    }

    async fn park_login(
        &self,
        handle: &LoginHandle,
        account: &AccountId,
        state: &LoginState,
        lifetime_seconds: u32,
    ) -> Result<(), AccessError> {
        let seconds = i32::try_from(lifetime_seconds).map_err(|_| AccessError::StoreUnavailable)?;
        self.client
            .query_one(
                sql::PARK_LOGIN,
                &[&handle.expose().as_slice(), &account.as_bytes().as_slice(), &state.expose(), &seconds],
            )
            .await
            .map_err(unavailable)?;
        Ok(())
    }

    async fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError> {
        let row = self.client.query_opt(sql::TAKE_LOGIN, &[&handle.expose().as_slice()]).await.map_err(unavailable)?;
        row.map(|row| {
            let account = AccountId::from_slice(row.get(0)).map_err(corrupt)?;
            let state = LoginState::from_slice(row.get(1)).map_err(corrupt)?;
            Ok((account, state))
        })
        .transpose()
    }

    async fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError> {
        let seconds = i32::try_from(lifetime_seconds).map_err(|_| AccessError::StoreUnavailable)?;
        let row = self
            .client
            .query_one(sql::OPEN_SESSION, &[&digest.as_bytes().as_slice(), &account.as_bytes().as_slice(), &seconds])
            .await
            .map_err(unavailable)?;
        Ok(row.get::<_, Option<i64>>(0).map(UnixTime))
    }

    async fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError> {
        self.client.query_one(sql::CLOSE_SESSION, &[&digest.as_bytes().as_slice()]).await.map_err(unavailable)?;
        Ok(())
    }

    async fn close_sessions(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        let row =
            self.client.query_one(sql::CLOSE_SESSIONS, &[&digest.as_bytes().as_slice()]).await.map_err(unavailable)?;
        Ok(row.get(0))
    }

    async fn keyring(&self, digest: &SessionDigest) -> Result<Option<KeyringSnapshot>, AccessError> {
        let row = self.client.query_opt(sql::KEYRING, &[&digest.as_bytes().as_slice()]).await.map_err(unavailable)?;
        row.map(|row| {
            let keyring = row.get::<_, Option<Vec<u8>>>(0).map(Keyring::new).transpose().map_err(corrupt)?;
            Ok(KeyringSnapshot { keyring, version: version(row.get(1))? })
        })
        .transpose()
    }

    async fn store_keyring(
        &self,
        digest: &SessionDigest,
        keyring: &Keyring,
        expected: KeyringVersion,
    ) -> Result<KeyringWrite, AccessError> {
        let expected = i64::try_from(expected.0).map_err(|_| AccessError::Conflict)?;
        let row = self
            .client
            .query_one(sql::STORE_KEYRING, &[&digest.as_bytes().as_slice(), &keyring.as_bytes(), &expected])
            .await
            .map_err(unavailable)?;
        Ok(match row.get::<_, Option<i64>>(0) {
            None => KeyringWrite::Unauthorized,
            Some(-1) => KeyringWrite::Stale,
            Some(v) => KeyringWrite::Stored(version(v)?),
        })
    }

    async fn close_account(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        let row =
            self.client.query_one(sql::CLOSE_ACCOUNT, &[&digest.as_bytes().as_slice()]).await.map_err(unavailable)?;
        Ok(row.get(0))
    }

    async fn purge_expired(&self) -> Result<u64, AccessError> {
        let row = self.client.query_one(sql::PURGE_EXPIRED, &[]).await.map_err(unavailable)?;
        Ok(row.get::<_, i64>(0).max(0) as u64)
    }
}

/// The login budgets per account, counted in the database: one count for the
/// whole world, however many Cloudflare locations the attempts come through,
/// and one per budget ([`crate::throttle_bucket`]). Fails closed: if the
/// count cannot be taken, the attempt is refused.
#[derive(Debug)]
pub struct PostgresThrottle<'a> {
    client: &'a Client,
    per_minute: i32,
}

impl<'a> PostgresThrottle<'a> {
    pub fn new(client: &'a Client, per_minute: u16) -> Self {
        Self { client, per_minute: i32::from(per_minute) }
    }
}

impl Throttle for PostgresThrottle<'_> {
    async fn admit(&self, account: &AccountId, budget: &Budget) -> bool {
        let bucket = crate::throttle_bucket(account, budget);
        // Registrations count against a reserve of their own, so a flood of logins cannot stop them.
        let registration = matches!(budget, Budget::Registration);
        match self.client.query_one(sql::ADMIT, &[&bucket.as_slice(), &self.per_minute, &registration]).await {
            Ok(row) => row.get(0),
            Err(_) => false,
        }
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
