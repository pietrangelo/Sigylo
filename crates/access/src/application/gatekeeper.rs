//! The relay's use cases: register, log in, sign out, keep the keyring.

use super::ports::{AccountStore, KeyringWrite, OpaqueServer, Passes, SessionDigester, Throttle, Tokens};
use crate::core::{
    AccessError, Budget, CredentialFinalization, CredentialRequest, CredentialResponse, DevicePass, Keyring,
    KeyringSnapshot, KeyringVersion, LOGIN_WINDOW_SECONDS, LoginHandle, RegistrationRecord, RegistrationRequest,
    RegistrationResponse, SESSION_SECONDS, Session, SessionToken, Username,
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
pub struct Gatekeeper<O, S, T, D, R, P> {
    opaque: O,
    store: S,
    tokens: T,
    digest: D,
    throttle: R,
    passes: P,
}

impl<O: OpaqueServer, S: AccountStore, T: Tokens, D: SessionDigester, R: Throttle, P: Passes>
    Gatekeeper<O, S, T, D, R, P>
{
    pub fn new(opaque: O, store: S, tokens: T, digest: D, throttle: R, passes: P) -> Self {
        Self { opaque, store, tokens, digest, throttle, passes }
    }

    /// First half of a registration. A taken name is refused here, never
    /// evaluated: the OPRF answer for an existing account's key would let
    /// anyone holding one KE2 of that account test password guesses offline.
    /// Saying "taken" reveals nothing [`Self::register`] would not, so it
    /// spends no budget: registering someone's name cannot lock them out.
    /// A free name spends its registration budget, never its login one.
    pub async fn registration_response(
        &self,
        username: &Username,
        request: &RegistrationRequest,
    ) -> Result<RegistrationResponse, AccessError> {
        let account = self.opaque.account_of(username);
        if self.store.record(&account).await?.is_some() {
            return Err(AccessError::AlreadyRegistered);
        }
        if !self.throttle.admit(&account, &Budget::Registration).await {
            return Err(AccessError::Throttled);
        }
        self.opaque.registration_response(&account, request)
    }

    /// Second half: file the record. An existing account is never overwritten.
    pub async fn register(&self, username: &Username, record: &RegistrationRecord) -> Result<(), AccessError> {
        let account = self.opaque.account_of(username);
        if self.store.enroll(&account, record).await? { Ok(()) } else { Err(AccessError::AlreadyRegistered) }
    }

    /// KE1 → KE2. Unknown accounts get a fake but indistinguishable answer.
    /// A device showing a valid pass spends its own allowance; any other
    /// attempt spends the account's shared one, which guessing can exhaust.
    pub async fn begin_login(
        &self,
        username: &Username,
        request: &CredentialRequest,
        pass: Option<&DevicePass>,
    ) -> Result<LoginChallenge, AccessError> {
        let account = self.opaque.account_of(username);
        let record = self.store.record(&account).await?;
        let budget = match (pass, &record) {
            (Some(pass), Some(record)) if self.passes.admits(pass, &account, record) => Budget::Device(pass.clone()),
            _ => Budget::Login,
        };
        if !self.throttle.admit(&account, &budget).await {
            return Err(AccessError::Throttled);
        }
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
        // The record as it is now: the name may have changed hands since KE2.
        let record = self.store.record(&account).await?.ok_or(AccessError::NotAuthentic)?;
        self.opaque.finish_login(&account, Some(&record), &state, finalization)?;
        let pass = self.passes.issue(&account, &record)?;
        let token = self.tokens.session()?;
        let expires_at = self
            .store
            .open_session(&self.digest.digest(&token), &account, SESSION_SECONDS)
            .await?
            .ok_or(AccessError::NotAuthentic)?;
        Ok(Session { token, expires_at, pass })
    }

    pub async fn sign_out(&self, token: &SessionToken) -> Result<(), AccessError> {
        self.store.close_session(&self.digest.digest(token)).await
    }

    /// Ends every session of the account, on every device, this one
    /// included: for a token that may have been stolen. The account and
    /// its keyring stay.
    pub async fn sign_out_everywhere(&self, token: &SessionToken) -> Result<(), AccessError> {
        if self.store.close_sessions(&self.digest.digest(token)).await? {
            Ok(())
        } else {
            Err(AccessError::Unauthorized)
        }
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
