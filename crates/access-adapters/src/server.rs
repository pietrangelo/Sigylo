use core::fmt;

use access::{
    AccessError, AccountId, CredentialFinalization, CredentialRequest, CredentialResponse, LoginState, OpaqueServer,
    RegistrationRecord, RegistrationRequest, RegistrationResponse, UnixTime, Username,
};
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opaque_ke::{ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::passes::HmacPasses;
use crate::rng;
use crate::suite::Suite;
use crate::tokens::HmacSessionDigest;

/// The relay's OPAQUE keys, all derived from one 32-byte secret (the
/// Worker secret `OPAQUE_SERVER_SEED`): the OPRF seed and the 3DH key pair,
/// the key that files accounts under a hash of their name, the key that
/// seals a login in progress while it waits in the database, the key of
/// the session digests the database keeps instead of tokens, the key of
/// device passes, and a public canary that names the secret. Losing or
/// changing the secret locks every account out; leaking it together with the
/// database lets an attacker test passwords offline, one Argon2id each.
pub struct OpaqueKeys {
    setup: ServerSetup<Suite>,
    account_key: Zeroizing<[u8; 32]>,
    state_key: Zeroizing<[u8; 32]>,
    session_key: Zeroizing<[u8; 32]>,
    pass_key: Zeroizing<[u8; 32]>,
    canary: [u8; 32],
}

/// Raw opaque-ke `ServerLogin` state; [`LoginState`] adds nonce and tag.
const RAW_STATE_LEN: usize = 128;
const NONCE_LEN: usize = 24;

/// A login state opens only for the account and the record it began on: once
/// a name changes hands, a login the previous owner had in flight is void.
fn state_aad(account: &AccountId, record: Option<&RegistrationRecord>) -> Vec<u8> {
    let record = match record {
        Some(r) => <Sha256 as sha2::Digest>::digest(r.as_bytes()).to_vec(),
        None => b"no record".to_vec(),
    };
    [b"sigylo/v1/login-state\0".as_slice(), account.as_bytes(), &record].concat()
}

impl OpaqueKeys {
    pub const SEED_LEN: usize = 32;

    pub fn from_seed(seed: &[u8]) -> Result<Self, AccessError> {
        if seed.len() != Self::SEED_LEN {
            return Err(AccessError::NotConfigured);
        }
        let hkdf = Hkdf::<Sha512>::new(Some(b"sigylo/v1/opaque"), seed);
        let mut setup_seed = Zeroizing::new([0u8; 32]);
        let mut account_key = Zeroizing::new([0u8; 32]);
        let mut state_key = Zeroizing::new([0u8; 32]);
        let mut session_key = Zeroizing::new([0u8; 32]);
        let mut pass_key = Zeroizing::new([0u8; 32]);
        let mut canary = [0u8; 32];
        hkdf.expand(b"server-setup", &mut *setup_seed).map_err(|_| AccessError::NotConfigured)?;
        hkdf.expand(b"account-id", &mut *account_key).map_err(|_| AccessError::NotConfigured)?;
        hkdf.expand(b"login-state", &mut *state_key).map_err(|_| AccessError::NotConfigured)?;
        hkdf.expand(b"session-digest", &mut *session_key).map_err(|_| AccessError::NotConfigured)?;
        hkdf.expand(b"device-pass", &mut *pass_key).map_err(|_| AccessError::NotConfigured)?;
        hkdf.expand(b"canary", &mut canary).map_err(|_| AccessError::NotConfigured)?;
        // Deterministic: the same secret always yields the same keys
        // (pinned by tests/opaque_pin.rs, so a library upgrade cannot drift).
        let setup = ServerSetup::<Suite>::new(&mut ChaCha20Rng::from_seed(*setup_seed));
        Ok(Self { setup, account_key, state_key, session_key, pass_key, canary })
    }

    /// The digest the store keeps for a session token, keyed by this relay's
    /// secret: a database writer without it cannot mint a usable session.
    pub fn session_digest(&self) -> HmacSessionDigest {
        HmacSessionDigest::new(*self.session_key)
    }

    /// Device passes, dated by the relay's clock.
    pub fn passes(&self, now: UnixTime) -> HmacPasses {
        HmacPasses::new(*self.pass_key, now)
    }

    /// A public fingerprint of the secret: it reveals nothing of it, and it
    /// changes whenever the secret does. The deploy compares it with the one
    /// accounts were made under (`OPAQUE_CANARY` in wrangler.toml), so a
    /// lost or replaced secret, which would lock every account out, stops
    /// the deploy instead of passing unseen.
    pub fn canary(&self) -> [u8; 32] {
        self.canary
    }

    /// Seals a raw login state to its account. Whoever can write the
    /// database still cannot plant a state of their own, nor move one to
    /// another account: only this relay's secret makes one that opens.
    fn seal_state(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        raw: &[u8],
    ) -> Result<LoginState, AccessError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| AccessError::RandomnessUnavailable)?;
        let sealed = XChaCha20Poly1305::new(&(*self.state_key).into())
            .encrypt(&XNonce::from(nonce), Payload { msg: raw, aad: &state_aad(account, record) })
            .map_err(|_| AccessError::MalformedMessage)?;
        let parked = Zeroizing::new([nonce.as_slice(), &sealed].concat());
        LoginState::from_slice(&parked)
    }

    fn open_state(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        state: &LoginState,
    ) -> Result<Zeroizing<Vec<u8>>, AccessError> {
        let (nonce, sealed) = state.expose().split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| AccessError::NotAuthentic)?;
        let raw = XChaCha20Poly1305::new(&(*self.state_key).into())
            .decrypt(&XNonce::from(nonce), Payload { msg: sealed, aad: &state_aad(account, record) })
            .map_err(|_| AccessError::NotAuthentic)?;
        Ok(Zeroizing::new(raw))
    }

    /// The relay's long-term public key (the 3DH static key).
    pub fn public_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.setup.keypair().public().serialize());
        out
    }
}

impl fmt::Debug for OpaqueKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueKeys(redacted)")
    }
}

impl OpaqueServer for OpaqueKeys {
    fn account_of(&self, username: &Username) -> AccountId {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.account_key).expect("HMAC takes any key length");
        mac.update(b"sigylo/v1/account\0");
        mac.update(username.as_bytes());
        AccountId::from_array(mac.finalize().into_bytes().into())
    }

    fn registration_response(
        &self,
        account: &AccountId,
        request: &RegistrationRequest,
    ) -> Result<RegistrationResponse, AccessError> {
        let request = opaque_ke::RegistrationRequest::<Suite>::deserialize(request.as_bytes())
            .map_err(|_| AccessError::MalformedMessage)?;
        let started = ServerRegistration::<Suite>::start(&self.setup, request, account.as_bytes())
            .map_err(|_| AccessError::MalformedMessage)?;
        RegistrationResponse::from_slice(&started.message.serialize())
    }

    fn begin_login(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        request: &CredentialRequest,
    ) -> Result<(CredentialResponse, LoginState), AccessError> {
        let stored = record;
        let record = record
            .map(|r| ServerRegistration::<Suite>::deserialize(r.as_bytes()))
            .transpose()
            .map_err(|_| AccessError::StoreUnavailable)?;
        let request = opaque_ke::CredentialRequest::<Suite>::deserialize(request.as_bytes())
            .map_err(|_| AccessError::MalformedMessage)?;
        let started = ServerLogin::start(
            &mut rng::fresh()?,
            &self.setup,
            record,
            request,
            account.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|_| AccessError::MalformedMessage)?;
        let state = Zeroizing::new(started.state.serialize());
        debug_assert_eq!(state.len(), RAW_STATE_LEN);
        Ok((CredentialResponse::from_slice(&started.message.serialize())?, self.seal_state(account, stored, &state)?))
    }

    fn finish_login(
        &self,
        account: &AccountId,
        record: Option<&RegistrationRecord>,
        state: &LoginState,
        finalization: &CredentialFinalization,
    ) -> Result<(), AccessError> {
        let raw = self.open_state(account, record, state)?;
        let state = ServerLogin::<Suite>::deserialize(&raw).map_err(|_| AccessError::NotAuthentic)?;
        let finalization = opaque_ke::CredentialFinalization::<Suite>::deserialize(finalization.as_bytes())
            .map_err(|_| AccessError::NotAuthentic)?;
        state.finish(finalization, ServerLoginParameters::default()).map_err(|_| AccessError::NotAuthentic)?;
        Ok(())
    }
}
