//! The relay and the accounts object talk in [`AccountCall`]s and
//! [`AccountReply`]s: the relay holds a [`RemoteAccounts`] (and counts
//! attempts through a [`VaultThrottle`]), the Durable Object runs
//! [`serve_accounts`] on its [`AccountLedger`]. One port call is one request
//! to the object.

use access::{
    AccessError, AccountId, AccountStore, Budget, Keyring, KeyringSnapshot, KeyringVersion, KeyringWrite, LoginHandle,
    LoginState, RegistrationRecord, SessionDigest, Throttle, UnixTime,
};

use super::accounts::AccountLedger;
use super::ports::{Accounts, Clock, KeyValue, Link};
use crate::core::{AccountCall, AccountReply, Class};

/// Where an attempt on a budget is counted: 32 bytes worked out by the
/// relay (`access_adapters::throttle_bucket`), so a device's pass never
/// reaches the accounts object, only the bucket it hashes to.
pub type Bucket = fn(&AccountId, &Budget) -> [u8; 32];

/// The Access store somewhere else, reached through a [`Link`].
#[derive(Debug)]
pub struct RemoteAccounts<L> {
    link: L,
    bucket: Bucket,
}

impl<L: Link> RemoteAccounts<L> {
    pub fn new(link: L, bucket: Bucket) -> Self {
        Self { link, bucket }
    }

    /// A link that fails or a reply that does not decode is a store that
    /// cannot answer.
    async fn call(&self, call: AccountCall) -> Result<AccountReply, AccessError> {
        let bytes = self.link.call(call.encode()).await.map_err(|_| AccessError::StoreUnavailable)?;
        match AccountReply::decode(&bytes).ok_or(AccessError::StoreUnavailable)? {
            AccountReply::Failed(error) => Err(error),
            reply => Ok(reply),
        }
    }
}

/// A reply that does not answer the call it came back for.
fn unexpected<T>() -> Result<T, AccessError> {
    Err(AccessError::StoreUnavailable)
}

impl<L: Link> AccountStore for RemoteAccounts<L> {
    async fn enroll(&self, account: &AccountId, record: &RegistrationRecord) -> Result<bool, AccessError> {
        match self.call(AccountCall::Enroll { account: *account, record: record.clone() }).await? {
            AccountReply::Flag(enrolled) => Ok(enrolled),
            _ => unexpected(),
        }
    }

    async fn record(&self, account: &AccountId) -> Result<Option<RegistrationRecord>, AccessError> {
        match self.call(AccountCall::Record { account: *account }).await? {
            AccountReply::Record(record) => Ok(record),
            _ => unexpected(),
        }
    }

    async fn park_login(
        &self,
        handle: &LoginHandle,
        account: &AccountId,
        state: &LoginState,
        lifetime_seconds: u32,
        budget: &Budget,
    ) -> Result<(), AccessError> {
        let bucket = match Class::of(budget) {
            Class::Login => None,
            Class::Device => Some((self.bucket)(account, budget)),
            // A registration has no login to park.
            Class::Registration => return unexpected(),
        };
        let call = AccountCall::Park {
            handle: handle.clone(),
            account: *account,
            state: state.clone(),
            lifetime: lifetime_seconds,
            bucket,
        };
        match self.call(call).await? {
            AccountReply::Done => Ok(()),
            _ => unexpected(),
        }
    }

    async fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError> {
        match self.call(AccountCall::Take { handle: handle.clone() }).await? {
            AccountReply::Login(login) => Ok(login),
            _ => unexpected(),
        }
    }

    async fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        record: &RegistrationRecord,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError> {
        let call = AccountCall::OpenSession {
            digest: *digest,
            account: *account,
            record: record.clone(),
            lifetime: lifetime_seconds,
        };
        match self.call(call).await? {
            AccountReply::Expires(at) => Ok(at),
            _ => unexpected(),
        }
    }

    async fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError> {
        match self.call(AccountCall::CloseSession { digest: *digest }).await? {
            AccountReply::Done => Ok(()),
            _ => unexpected(),
        }
    }

    async fn close_sessions(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        match self.call(AccountCall::CloseSessions { digest: *digest }).await? {
            AccountReply::Flag(closed) => Ok(closed),
            _ => unexpected(),
        }
    }

    async fn keyring(&self, digest: &SessionDigest) -> Result<Option<KeyringSnapshot>, AccessError> {
        match self.call(AccountCall::Keyring { digest: *digest }).await? {
            AccountReply::Keyring(snapshot) => Ok(snapshot),
            _ => unexpected(),
        }
    }

    async fn store_keyring(
        &self,
        digest: &SessionDigest,
        keyring: &Keyring,
        expected: KeyringVersion,
    ) -> Result<KeyringWrite, AccessError> {
        match self.call(AccountCall::StoreKeyring { digest: *digest, keyring: keyring.clone(), expected }).await? {
            AccountReply::Written(write) => Ok(write),
            _ => unexpected(),
        }
    }

    async fn close_account(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        match self.call(AccountCall::CloseAccount { digest: *digest }).await? {
            AccountReply::Flag(closed) => Ok(closed),
            _ => unexpected(),
        }
    }

    async fn purge_expired(&self) -> Result<u64, AccessError> {
        match self.call(AccountCall::Purge).await? {
            AccountReply::Purged(gone) => Ok(gone),
            _ => unexpected(),
        }
    }
}

impl<L: Link> Accounts for RemoteAccounts<L> {
    async fn admit(
        &self,
        account: &AccountId,
        bucket: &[u8; 32],
        class: Class,
        limit: u16,
    ) -> Result<bool, AccessError> {
        match self.call(AccountCall::Admit { account: *account, bucket: *bucket, class, limit }).await? {
            AccountReply::Flag(admitted) => Ok(admitted),
            _ => unexpected(),
        }
    }
}

/// Runs one encoded call on the accounts object's ledger and encodes its
/// reply. A call that does not decode gets [`AccessError::StoreUnavailable`],
/// like any fault. A plain `fn`: nothing here waits, so the object never
/// runs another request in the middle of one.
pub fn serve_accounts<K: KeyValue, C: Clock>(ledger: &AccountLedger<'_, K, C>, call: &[u8]) -> Vec<u8> {
    let Some(call) = AccountCall::decode(call) else {
        return AccountReply::Failed(AccessError::StoreUnavailable).encode();
    };
    let reply = match call {
        AccountCall::Enroll { account, record } => ledger.enroll(&account, &record).map(AccountReply::Flag),
        AccountCall::Record { account } => ledger.record(&account).map(AccountReply::Record),
        AccountCall::Park { handle, account, state, lifetime, bucket } => {
            let class = if bucket.is_some() { Class::Device } else { Class::Login };
            ledger.park_login(&handle, &account, &state, lifetime, class, bucket.as_ref()).map(|()| AccountReply::Done)
        }
        AccountCall::Take { handle } => ledger.take_login(&handle).map(AccountReply::Login),
        AccountCall::OpenSession { digest, account, record, lifetime } => {
            ledger.open_session(&digest, &account, &record, lifetime).map(AccountReply::Expires)
        }
        AccountCall::CloseSession { digest } => ledger.close_session(&digest).map(|()| AccountReply::Done),
        AccountCall::CloseSessions { digest } => ledger.close_sessions(&digest).map(AccountReply::Flag),
        AccountCall::Keyring { digest } => ledger.keyring(&digest).map(AccountReply::Keyring),
        AccountCall::StoreKeyring { digest, keyring, expected } => {
            ledger.store_keyring(&digest, &keyring, expected).map(AccountReply::Written)
        }
        AccountCall::CloseAccount { digest } => ledger.close_account(&digest).map(AccountReply::Flag),
        AccountCall::Purge => ledger.purge_expired().map(AccountReply::Purged),
        AccountCall::Admit { account, bucket, class, limit } => {
            ledger.admit(&account, &bucket, class, limit).map(AccountReply::Flag)
        }
    };
    reply.unwrap_or_else(AccountReply::Failed).encode()
}

/// The throttle that counts in the accounts object, once for the whole
/// world, `limit` attempts a minute per account and budget. Fails closed:
/// a fault of any kind, a full memory or a limit out of range included, is
/// a refusal, never an admission.
#[derive(Debug)]
pub struct VaultThrottle<'a, A> {
    accounts: &'a A,
    limit: u16,
    bucket: Bucket,
}

impl<'a, A: Accounts> VaultThrottle<'a, A> {
    pub fn new(accounts: &'a A, limit: u16, bucket: Bucket) -> Self {
        Self { accounts, limit, bucket }
    }
}

impl<A: Accounts> Throttle for VaultThrottle<'_, A> {
    async fn admit(&self, account: &AccountId, budget: &Budget) -> bool {
        let bucket = (self.bucket)(account, budget);
        matches!(self.accounts.admit(account, &bucket, Class::of(budget), self.limit).await, Ok(true))
    }
}
