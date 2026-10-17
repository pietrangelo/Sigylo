//! The device's use cases: register and log in without the password ever
//! leaving it, and come out with the keyring key.

use core::fmt;

use super::ports::{KeyringKdf, OpaqueClient};
use crate::core::{
    AccessError, CredentialFinalization, CredentialRequest, CredentialResponse, ExportKey, KEYRING_INFO, KeyringKey,
    Password, RegistrationRecord, RegistrationRequest, RegistrationResponse,
};

/// A registration between its two round trips. Holds the password: drop it
/// (or finish it) as soon as the relay answers.
pub struct PendingRegistration<S> {
    password: Password,
    state: S,
}

/// A login between its two round trips.
pub struct PendingLogin<S> {
    password: Password,
    state: S,
}

impl<S> fmt::Debug for PendingRegistration<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingRegistration(redacted)")
    }
}

impl<S> fmt::Debug for PendingLogin<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingLogin(redacted)")
    }
}

/// Registers and logs in on behalf of the person at the device.
#[derive(Debug, Clone, Copy)]
pub struct Member<C, K> {
    opaque: C,
    kdf: K,
}

impl<C: OpaqueClient, K: KeyringKdf> Member<C, K> {
    pub fn new(opaque: C, kdf: K) -> Self {
        Self { opaque, kdf }
    }

    pub fn begin_registration(
        &self,
        password: Password,
    ) -> Result<(RegistrationRequest, PendingRegistration<C::Registration>), AccessError> {
        let (request, state) = self.opaque.begin_registration(&password)?;
        Ok((request, PendingRegistration { password, state }))
    }

    /// The record goes to the relay; the keyring key stays here.
    pub fn finish_registration(
        &self,
        pending: PendingRegistration<C::Registration>,
        response: &RegistrationResponse,
    ) -> Result<(RegistrationRecord, KeyringKey), AccessError> {
        let PendingRegistration { password, state } = pending;
        let (record, export_key) = self.opaque.finish_registration(state, &password, response)?;
        Ok((record, self.keyring_key(&export_key)))
    }

    pub fn begin_login(&self, password: Password) -> Result<(CredentialRequest, PendingLogin<C::Login>), AccessError> {
        let (request, state) = self.opaque.begin_login(&password)?;
        Ok((request, PendingLogin { password, state }))
    }

    /// KE3 goes to the relay; the keyring key, the same one registration
    /// produced, stays here.
    pub fn finish_login(
        &self,
        pending: PendingLogin<C::Login>,
        response: &CredentialResponse,
    ) -> Result<(CredentialFinalization, KeyringKey), AccessError> {
        let PendingLogin { password, state } = pending;
        let (finalization, export_key) = self.opaque.finish_login(state, &password, response)?;
        Ok((finalization, self.keyring_key(&export_key)))
    }

    fn keyring_key(&self, export_key: &ExportKey) -> KeyringKey {
        self.kdf.derive(export_key, KEYRING_INFO)
    }
}
