//! # Access (bounded context)
//!
//! Accounts without a password on the server. Registration and login use
//! OPAQUE (RFC 9807): the password never leaves the device, not even hashed,
//! and the relay keeps only a registration record that is useless without
//! both the password and the relay's OPRF key. A stolen database cannot be
//! attacked offline; a stolen database *and* relay secret still forces one
//! Argon2id guess per password tried, per account.
//!
//! A successful login gives two things:
//!
//! * a **session**: a random bearer token the relay stores only as a digest,
//!   which opens the account's keyring for a few hours;
//! * a **keyring key**, derived on the device from OPAQUE's export key. The
//!   relay never sees it: the keyring is sealed with it before upload and is
//!   opaque bytes to the relay, like every other envelope.
//!
//! Pure domain: OPAQUE itself, the store and the random sources arrive
//! through the ports in [`application`], implemented in `access-adapters`.
#![forbid(unsafe_code)]

pub mod application;
pub mod core;

pub use crate::core::{
    AccessError, AccountId, CredentialFinalization, CredentialRequest, CredentialResponse, ExportKey, KEYRING_INFO,
    Keyring, KeyringKey, KeyringSnapshot, KeyringVersion, LOGIN_WINDOW_SECONDS, LoginHandle, LoginState,
    MAX_KEYRING_LEN, MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, Password, RegistrationRecord, RegistrationRequest,
    RegistrationResponse, SESSION_SECONDS, Session, SessionDigest, SessionToken, UnixTime, Username,
};
pub use application::{
    AccountStore, Gatekeeper, KeyringKdf, KeyringWrite, LoginChallenge, Member, OpaqueClient, OpaqueServer,
    PendingLogin, PendingRegistration, SessionDigester, Throttle, Tokens,
};
