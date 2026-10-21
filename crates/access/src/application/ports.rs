//! Ports of the Access context.

use crate::core::{
    AccessError, AccountId, Budget, CredentialFinalization, CredentialRequest, CredentialResponse, DevicePass,
    ExportKey, Keyring, KeyringKey, KeyringSnapshot, KeyringVersion, LoginHandle, LoginState, Password,
    RegistrationRecord, RegistrationRequest, RegistrationResponse, SessionDigest, SessionToken, UnixTime, Username,
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

    /// Refuses a record no login could ever use, with
    /// [`AccessError::MalformedMessage`]: the client sends it unchecked.
    fn check_record(&self, record: &RegistrationRecord) -> Result<(), AccessError>;

    /// KE2. With no record (unknown account) it must answer with a response
    /// indistinguishable from a real one, so logins do not reveal who exists.
    fn begin_login(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        request: &CredentialRequest,
    ) -> Result<(CredentialResponse, LoginState), AccessError>;

    /// Checks KE3 against the state and the account's record as it is now
    /// (`None` once the account is gone). A state begun on another record,
    /// such as the previous owner's of a name that changed hands meanwhile,
    /// never finishes. [`AccessError::NotAuthentic`] on any mismatch.
    fn finish_login(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
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
/// `access-adapters/tests/vault_accounts.rs`):
///
/// * the store's own clock decides every expiry;
/// * a lifetime above [`crate::LOGIN_WINDOW_SECONDS`] (logins) or
///   [`crate::SESSION_SECONDS`] (sessions) is refused;
/// * [`AccountStore::enroll`] never overwrites an existing account;
/// * [`AccountStore::take_login`] returns a parked login **at most once**,
///   and removes an expired one too, without returning it;
/// * a login is parked under the [`Budget`] its attempt spent;
/// * a session opens only on the record the password was checked against;
/// * a session works only while it and its account live;
/// * [`AccountStore::store_keyring`] writes only when the stored version is
///   `expected`, atomically, and then bumps it by one;
/// * an account keeps at most [`crate::MAX_SESSIONS`] live sessions: opening
///   one more ends the one that expires first, the lowest digest on a tie,
///   never the one being opened;
/// * [`AccountStore::close_sessions`] and [`AccountStore::close_account`]
///   need a live session behind the digest;
/// * closing an account removes its record, keyring, every session and its
///   parked logins;
/// * [`AccountStore::purge_expired`] counts every expired login, session
///   and attempt counter it removes.
// Workers run on one thread, so the futures need not be `Send`.
#[allow(async_fn_in_trait)]
pub trait AccountStore {
    /// False when the account already exists.
    async fn enroll(&self, account: &AccountId, record: &RegistrationRecord) -> Result<bool, AccessError>;

    async fn record(&self, account: &AccountId) -> Result<Option<RegistrationRecord>, AccessError>;

    /// `budget` is the one the attempt spent, so a store that keeps logins
    /// apart by budget charges the right one.
    async fn park_login(
        &self,
        handle: &LoginHandle,
        account: &AccountId,
        state: &LoginState,
        lifetime_seconds: u32,
        budget: &Budget,
    ) -> Result<(), AccessError>;

    async fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError>;

    /// `None` when the account no longer exists or its record is no longer
    /// `record`, the one the password was just checked against.
    async fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        record: &RegistrationRecord,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError>;

    async fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError>;

    /// Ends every session of the account behind the digest, this one
    /// included. False when there is no live session behind it.
    async fn close_sessions(&self, digest: &SessionDigest) -> Result<bool, AccessError>;

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

    /// Physically removes expired logins, sessions and attempt counters.
    /// Returns how many went.
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
/// The count must be one for the whole world, not one per data centre, and
/// one per account and [`Budget`]: spending one never spends another.
#[allow(async_fn_in_trait)]
pub trait Throttle {
    async fn admit(&self, account: &AccountId, budget: &Budget) -> bool;
}

/// Issues and checks [`DevicePass`]es with a key only the relay holds.
pub trait Passes {
    fn issue(&self, account: &AccountId, record: &RegistrationRecord) -> Result<DevicePass, AccessError>;

    /// True only for an unexpired pass this relay issued for this account
    /// while it had this record: once a name changes hands, old passes are void.
    fn admits(&self, pass: &DevicePass, account: &AccountId, record: &RegistrationRecord) -> bool;
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

    fn check_record(&self, record: &RegistrationRecord) -> Result<(), AccessError> {
        (**self).check_record(record)
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
        record: Option<&RegistrationRecord>,
        state: &LoginState,
        finalization: &CredentialFinalization,
    ) -> Result<(), AccessError> {
        (**self).finish_login(account, record, state, finalization)
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
        budget: &Budget,
    ) -> Result<(), AccessError> {
        (**self).park_login(handle, account, state, lifetime_seconds, budget).await
    }

    async fn take_login(&self, handle: &LoginHandle) -> Result<Option<(AccountId, LoginState)>, AccessError> {
        (**self).take_login(handle).await
    }

    async fn open_session(
        &self,
        digest: &SessionDigest,
        account: &AccountId,
        record: &RegistrationRecord,
        lifetime_seconds: u32,
    ) -> Result<Option<UnixTime>, AccessError> {
        (**self).open_session(digest, account, record, lifetime_seconds).await
    }

    async fn close_session(&self, digest: &SessionDigest) -> Result<(), AccessError> {
        (**self).close_session(digest).await
    }

    async fn close_sessions(&self, digest: &SessionDigest) -> Result<bool, AccessError> {
        (**self).close_sessions(digest).await
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
    async fn admit(&self, account: &AccountId, budget: &Budget) -> bool {
        (**self).admit(account, budget).await
    }
}

impl<T: Passes> Passes for &T {
    fn issue(&self, account: &AccountId, record: &RegistrationRecord) -> Result<DevicePass, AccessError> {
        (**self).issue(account, record)
    }

    fn admits(&self, pass: &DevicePass, account: &AccountId, record: &RegistrationRecord) -> bool {
        (**self).admits(pass, account, record)
    }
}

/// Both must admit; the second is asked only when the first did, so a cheap
/// first filter spares the second its work.
impl<A: Throttle, B: Throttle> Throttle for (A, B) {
    async fn admit(&self, account: &AccountId, budget: &Budget) -> bool {
        self.0.admit(account, budget).await && self.1.admit(account, budget).await
    }
}
