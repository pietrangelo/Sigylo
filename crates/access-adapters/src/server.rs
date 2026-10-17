use core::fmt;

use access::{
    AccessError, AccountId, CredentialFinalization, CredentialRequest, CredentialResponse, LoginState, OpaqueServer,
    RegistrationRecord, RegistrationRequest, RegistrationResponse, Username,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opaque_ke::{ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::rng;
use crate::suite::Suite;

/// The relay's OPAQUE keys, all derived from one 32-byte secret (the
/// Worker secret `OPAQUE_SERVER_SEED`): the OPRF seed and the 3DH key pair,
/// and the key that files accounts under a hash of their name. Losing or
/// changing the secret locks every account out; leaking it together with the
/// database lets an attacker test passwords offline, one Argon2id each.
pub struct OpaqueKeys {
    setup: ServerSetup<Suite>,
    account_key: Zeroizing<[u8; 32]>,
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
        hkdf.expand(b"server-setup", &mut *setup_seed).map_err(|_| AccessError::NotConfigured)?;
        hkdf.expand(b"account-id", &mut *account_key).map_err(|_| AccessError::NotConfigured)?;
        // Deterministic: the same secret always yields the same keys
        // (pinned by tests/opaque_pin.rs, so a library upgrade cannot drift).
        let setup = ServerSetup::<Suite>::new(&mut ChaCha20Rng::from_seed(*setup_seed));
        Ok(Self { setup, account_key })
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
        Ok((CredentialResponse::from_slice(&started.message.serialize())?, LoginState::from_slice(&state)?))
    }

    fn finish_login(&self, state: &LoginState, finalization: &CredentialFinalization) -> Result<(), AccessError> {
        let state = ServerLogin::<Suite>::deserialize(state.expose()).map_err(|_| AccessError::NotAuthentic)?;
        let finalization = opaque_ke::CredentialFinalization::<Suite>::deserialize(finalization.as_bytes())
            .map_err(|_| AccessError::NotAuthentic)?;
        state.finish(finalization, ServerLoginParameters::default()).map_err(|_| AccessError::NotAuthentic)?;
        Ok(())
    }
}
