//! The relay's use cases: register, log in, sign out, keep the keyring.

use super::ports::{AccountStore, KeyringWrite, OpaqueServer, SessionDigester, Throttle, Tokens};
use crate::core::{
    AccessError, CredentialFinalization, CredentialRequest, CredentialResponse, Keyring, KeyringSnapshot,
    KeyringVersion, LOGIN_WINDOW_SECONDS, LoginHandle, RegistrationRecord, RegistrationRequest, RegistrationResponse,
    SESSION_SECONDS, Session, SessionToken, Username,
};

/// What the relay answers to the first half of a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginChallenge {
    /// Names this login when the client comes back with KE3.
    pub handle: LoginHandle,
    pub response: CredentialResponse,
}

/// Lets members in, never learning their passwords.
#[derive(Debug)]
pub struct Gatekeeper<O, S, T, D, R> {
    opaque: O,
    store: S,
    tokens: T,
    digest: D,
    throttle: R,
}

impl<O: OpaqueServer, S: AccountStore, T: Tokens, D: SessionDigester, R: Throttle> Gatekeeper<O, S, T, D, R> {
    pub fn new(opaque: O, store: S, tokens: T, digest: D, throttle: R) -> Self {
        Self { opaque, store, tokens, digest, throttle }
    }

    /// First half of a registration. Says nothing about whether the name is
    /// free: that is only known (and only revealed) when [`Self::register`] runs.
    pub fn registration_response(
        &self,
        username: &Username,
        request: &RegistrationRequest,
    ) -> Result<RegistrationResponse, AccessError> {
        self.opaque.registration_response(&self.opaque.account_of(username), request)
    }

    /// Second half: file the record. An existing account is never overwritten.
    pub async fn register(&self, username: &Username, record: &RegistrationRecord) -> Result<(), AccessError> {
        let account = self.opaque.account_of(username);
        if self.store.enroll(&account, record).await? { Ok(()) } else { Err(AccessError::AlreadyRegistered) }
    }

    /// KE1 → KE2. Unknown accounts get a fake but indistinguishable answer.
    pub async fn begin_login(
        &self,
        username: &Username,
        request: &CredentialRequest,
    ) -> Result<LoginChallenge, AccessError> {
        let account = self.opaque.account_of(username);
        if !self.throttle.admit(&account).await {
            return Err(AccessError::Throttled);
        }
        let record = self.store.record(&account).await?;
        let (response, state) = self.opaque.begin_login(&account, record.as_ref(), request)?;
        let handle = self.tokens.login_handle()?;
        self.store.park_login(&handle, &account, &state, LOGIN_WINDOW_SECONDS).await?;
        Ok(LoginChallenge { handle, response })
    }

    /// KE3 → session. A handle works once, whatever the outcome.
    pub async fn finish_login(
        &self,
        handle: &LoginHandle,
        finalization: &CredentialFinalization,
    ) -> Result<Session, AccessError> {
        let (account, state) = self.store.take_login(handle).await?.ok_or(AccessError::NotAuthentic)?;
        self.opaque.finish_login(&state, finalization)?;
        let token = self.tokens.session()?;
        let expires_at = self
            .store
            .open_session(&self.digest.digest(&token), &account, SESSION_SECONDS)
            .await?
            .ok_or(AccessError::NotAuthentic)?;
        Ok(Session { token, expires_at })
    }

    pub async fn sign_out(&self, token: &SessionToken) -> Result<(), AccessError> {
        self.store.close_session(&self.digest.digest(token)).await
    }

    pub async fn keyring(&self, token: &SessionToken) -> Result<KeyringSnapshot, AccessError> {
        self.store.keyring(&self.digest.digest(token)).await?.ok_or(AccessError::Unauthorized)
    }

    /// Replace the keyring, provided nobody wrote it since `expected` was read.
    pub async fn store_keyring(
        &self,
        token: &SessionToken,
        keyring: &Keyring,
        expected: KeyringVersion,
    ) -> Result<KeyringVersion, AccessError> {
        match self.store.store_keyring(&self.digest.digest(token), keyring, expected).await? {
            KeyringWrite::Stored(version) => Ok(version),
            KeyringWrite::Stale => Err(AccessError::Conflict),
            KeyringWrite::Unauthorized => Err(AccessError::Unauthorized),
        }
    }

    /// Delete the account, its keyring and all its sessions. The name becomes free.
    pub async fn close_account(&self, token: &SessionToken) -> Result<(), AccessError> {
        if self.store.close_account(&self.digest.digest(token)).await? {
            Ok(())
        } else {
            Err(AccessError::Unauthorized)
        }
    }

    pub async fn purge_expired(&self) -> Result<u64, AccessError> {
        self.store.purge_expired().await
    }
}
