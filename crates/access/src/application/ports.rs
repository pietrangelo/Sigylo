//! Ports of the Access context.

use crate::core::{
    AccessError, AccountId, CredentialFinalization, CredentialRequest, CredentialResponse, ExportKey, Keyring,
    KeyringKey, KeyringSnapshot, KeyringVersion, LoginHandle, LoginState, Password, RegistrationRecord,
    RegistrationRequest, RegistrationResponse, SessionDigest, SessionToken, UnixTime, Username,
};

/// The relay's side of OPAQUE, holding the relay's long-term secret (OPRF
/// seed, key-exchange key and the key that files accounts).
pub trait OpaqueServer {
    /// The keyed hash of the username under which the account is filed.
    fn account_of(&self, username: &Username) -> AccountId;

    fn registration_response(
        &self,
        account: &AccountId,
        request: &RegistrationRequest,
    ) -> Result<RegistrationResponse, AccessError>;

    /// KE2. With no record (unknown account) it must answer with a response
    /// indistinguishable from a real one, so logins do not reveal who exists.
    fn begin_login(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        request: &CredentialRequest,
    ) -> Result<(CredentialResponse, LoginState), AccessError>;

    /// Checks KE3. [`AccessError::NotAuthentic`] on any mismatch.
    fn finish_login(
        &self,
        account: &AccountId,
        state: &LoginState,
        finalization: &CredentialFinalization,
    ) -> Result<(), AccessError>;
}

/// The device's side of OPAQUE. The states hold the blinding factor and
/// must wipe themselves on drop.
pub trait OpaqueClient {
    type Registration;
    type Login;

    fn begin_registration(&self, password: &Password)
    -> Result<(RegistrationRequest, Self::Registration), AccessError>;

    fn finish_registration(
        &self,
        state: Self::Registration,
        password: &Password,
        response: &RegistrationResponse,
    ) -> Result<(RegistrationRecord, ExportKey), AccessError>;

    fn begin_login(&self, password: &Password) -> Result<(CredentialRequest, Self::Login), AccessError>;

    /// [`AccessError::NotAuthentic`] when the response does not open with
    /// this password (wrong password, unknown user or a tampered response).
    fn finish_login(
        &self,
        state: Self::Login,
        password: &Password,
        response: &CredentialResponse,
    ) -> Result<(CredentialFinalization, ExportKey), AccessError>;
}

/// Derives the keyring key from the export key (HKDF-SHA-512).
pub trait KeyringKdf {
    fn derive(&self, export_key: &ExportKey, info: &[u8]) -> KeyringKey;
}

/// Outcome of a keyring write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringWrite {
    Stored(KeyringVersion),
    /// The stored version is not the one the write expected.
    Stale,
    /// No live session behind the digest.
    Unauthorized,
}

/// Durable storage of accounts, logins in progress and sessions.
///
/// Contract every adapter must honour (checked by the contract tests in
/// `access-adapters`):
///
/// * the store's own clock decides every expiry;
/// * [`AccountStore::enroll`] never overwrites an existing account;
/// * [`AccountStore::take_login`] returns a parked login **at most once**;
/// * a session works only while it and its account live;
/// * [`AccountStore::store_keyring`] writes only when the stored version is
///   `expected`, atomically, and then bumps it by one;
/// * closing an account removes its record, keyring and every session.
// Workers run on one thread, so the futures need not be `Send`.
#[allow(async_fn_in_trait)]
pub trait AccountStore {
    /// False when the account already exists.
    async fn enroll(&self, account: &AccountId, record: &RegistrationRecord) -> Result<bool, AccessError>;

    async fn record(&self, account: &AccountId) -> Result<Option<RegistrationRecord>, AccessError>;

    async fn park_login(
        &self,
        handle: &LoginHandle,
        account: &AccountId,
        state: &LoginState,
        lifetime_seconds: u32,
    ) -> Result<(), AccessError>;

    async fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError>;

    /// `None` when the account no longer exists.
    async fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError>;

    async fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError>;

    /// `None` when there is no live session behind the digest.
    async fn keyring(&self, digest: &SessionDigest) -> Result<Option<KeyringSnapshot>, AccessError>;

    async fn store_keyring(
        &self,
        digest: &SessionDigest,
        keyring: &Keyring,
        expected: KeyringVersion,
    ) -> Result<KeyringWrite, AccessError>;

    /// False when there is no live session behind the digest.
    async fn close_account(&self, digest: &SessionDigest) -> Result<bool, AccessError>;

    /// Physically removes expired logins and sessions. Returns how many went.
    async fn purge_expired(&self) -> Result<u64, AccessError>;
}

/// Fresh, unguessable session tokens and login handles.
pub trait Tokens {
    fn session(&self) -> Result<SessionToken, AccessError>;
    fn login_handle(&self) -> Result<LoginHandle, AccessError>;
}

/// One-way digest of session tokens (SHA-256).
pub trait SessionDigester {
    fn digest(&self, token: &SessionToken) -> SessionDigest;
}

/// Limits login attempts per account, wherever they come from: the per-address
/// limit alone would let a botnet guess one account's password at leisure.
#[allow(async_fn_in_trait)]
pub trait Throttle {
    async fn admit(&self, account: &AccountId) -> bool;
}

// Borrowed ports work too, so one adapter can serve several use cases.

impl<T: OpaqueServer> OpaqueServer for &T {
    fn account_of(&self, username: &Username) -> AccountId {
        (**self).account_of(username)
    }

    fn registration_response(
        &self,
        account: &AccountId,
        request: &RegistrationRequest,
    ) -> Result<RegistrationResponse, AccessError> {
        (**self).registration_response(account, request)
    }

    fn begin_login(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        request: &CredentialRequest,
    ) -> Result<(CredentialResponse, LoginState), AccessError> {
        (**self).begin_login(account, record, request)
    }

    fn finish_login(
        &self,
        account: &AccountId,
        state: &LoginState,
        finalization: &CredentialFinalization,
    ) -> Result<(), AccessError> {
        (**self).finish_login(account, state, finalization)
    }
}

impl<T: OpaqueClient> OpaqueClient for &T {
    type Registration = T::Registration;
    type Login = T::Login;

    fn begin_registration(
        &self,
        password: &Password,
    ) -> Result<(RegistrationRequest, Self::Registration), AccessError> {
        (**self).begin_registration(password)
    }

    fn finish_registration(
        &self,
        state: Self::Registration,
        password: &Password,
        response: &RegistrationResponse,
    ) -> Result<(RegistrationRecord, ExportKey), AccessError> {
        (**self).finish_registration(state, password, response)
    }

    fn begin_login(&self, password: &Password) -> Result<(CredentialRequest, Self::Login), AccessError> {
        (**self).begin_login(password)
    }

    fn finish_login(
        &self,
        state: Self::Login,
        password: &Password,
        response: &CredentialResponse,
    ) -> Result<(CredentialFinalization, ExportKey), AccessError> {
        (**self).finish_login(state, password, response)
    }
}

impl<T: AccountStore> AccountStore for &T {
    async fn enroll(&self, account: &AccountId, record: &RegistrationRecord) -> Result<bool, AccessError> {
        (**self).enroll(account, record).await
    }

    async fn record(&self, account: &AccountId) -> Result<Option<RegistrationRecord>, AccessError> {
        (**self).record(account).await
    }

    async fn park_login(
        &self,
        handle: &LoginHandle,
        account: &AccountId,
        state: &LoginState,
        lifetime_seconds: u32,
    ) -> Result<(), AccessError> {
        (**self).park_login(handle, account, state, lifetime_seconds).await
    }

    async fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError> {
        (**self).take_login(handle).await
    }

    async fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError> {
        (**self).open_session(digest, account, lifetime_seconds).await
    }

    async fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError> {
        (**self).close_session(digest).await
    }

    async fn keyring(&self, digest: &SessionDigest) -> Result<Option<KeyringSnapshot>, AccessError> {
        (**self).keyring(digest).await
    }

    async fn store_keyring(
        &self,
        digest: &SessionDigest,
        keyring: &Keyring,
        expected: KeyringVersion,
    ) -> Result<KeyringWrite, AccessError> {
        (**self).store_keyring(digest, keyring, expected).await
    }

    async fn close_account(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        (**self).close_account(digest).await
    }

    async fn purge_expired(&self) -> Result<u64, AccessError> {
        (**self).purge_expired().await
    }
}

impl<T: Tokens> Tokens for &T {
    fn session(&self) -> Result<SessionToken, AccessError> {
        (**self).session()
    }

    fn login_handle(&self) -> Result<LoginHandle, AccessError> {
        (**self).login_handle()
    }
}

impl<T: SessionDigester> SessionDigester for &T {
    fn digest(&self, token: &SessionToken) -> SessionDigest {
        (**self).digest(token)
    }
}

impl<T: Throttle> Throttle for &T {
    async fn admit(&self, account: &AccountId) -> bool {
        (**self).admit(account).await
    }
}
