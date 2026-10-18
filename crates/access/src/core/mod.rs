//! Core ring: value objects of the Access context. Pure and deterministic.
//!
//! The protocol messages are opaque bytes of fixed length (the OPAQUE suite
//! of Sigylo v1: ristretto255, SHA-512, Argon2id); the domain checks their
//! size, the adapters their cryptography.

mod error;
mod messages;
mod secrets;
mod values;

pub use error::AccessError;
pub use messages::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRecord, RegistrationRequest,
    RegistrationResponse,
};
pub use secrets::{
    DevicePass, ExportKey, KeyringKey, LoginHandle, LoginState, MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, Password,
    SessionToken,
};
pub use values::{
    AccountId, Budget, KEYRING_INFO, Keyring, KeyringSnapshot, KeyringVersion, LOGIN_WINDOW_SECONDS, MAX_KEYRING_LEN,
    MAX_SESSIONS, PASS_SECONDS, SESSION_SECONDS, Session, SessionDigest, UnixTime, Username,
};
