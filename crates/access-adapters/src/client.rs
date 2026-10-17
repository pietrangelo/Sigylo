use access::{
    AccessError, CredentialFinalization, CredentialRequest, CredentialResponse, ExportKey, OpaqueClient, Password,
    RegistrationRecord, RegistrationRequest, RegistrationResponse,
};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters};
use zeroize::Zeroize;

use crate::rng;
use crate::suite::Suite;

/// The device's side of OPAQUE. Its states wipe themselves on drop.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpaqueDevice;

/// Copies the export key out of opaque-ke's result and wipes the original
/// in place: the result types do not wipe themselves, and the array is
/// `Copy`, so passing it by value would only wipe a copy.
fn export_key(bytes: &mut [u8]) -> Result<ExportKey, AccessError> {
    let key = ExportKey::from_slice(bytes);
    bytes.zeroize();
    key
}

impl OpaqueClient for OpaqueDevice {
    type Registration = ClientRegistration<Suite>;
    type Login = ClientLogin<Suite>;

    fn begin_registration(
        &self,
        password: &Password,
    ) -> Result<(RegistrationRequest, Self::Registration), AccessError> {
        let started = ClientRegistration::<Suite>::start(&mut rng::fresh()?, password.expose())
            .map_err(|_| AccessError::InvalidPassword)?;
        Ok((RegistrationRequest::from_slice(&started.message.serialize())?, started.state))
    }

    fn finish_registration(
        &self,
        state: Self::Registration,
        password: &Password,
        response: &RegistrationResponse,
    ) -> Result<(RegistrationRecord, ExportKey), AccessError> {
        let response = opaque_ke::RegistrationResponse::<Suite>::deserialize(response.as_bytes())
            .map_err(|_| AccessError::NotAuthentic)?;
        let mut finished = state
            .finish(&mut rng::fresh()?, password.expose(), response, ClientRegistrationFinishParameters::default())
            .map_err(|_| AccessError::NotAuthentic)?;
        let key = export_key(finished.export_key.as_mut_slice());
        Ok((RegistrationRecord::from_slice(&finished.message.serialize())?, key?))
    }

    fn begin_login(&self, password: &Password) -> Result<(CredentialRequest, Self::Login), AccessError> {
        let started = ClientLogin::<Suite>::start(&mut rng::fresh()?, password.expose())
            .map_err(|_| AccessError::InvalidPassword)?;
        Ok((CredentialRequest::from_slice(&started.message.serialize())?, started.state))
    }

    fn finish_login(
        &self,
        state: Self::Login,
        password: &Password,
        response: &CredentialResponse,
    ) -> Result<(CredentialFinalization, ExportKey), AccessError> {
        // A malformed, tampered or fake response fails exactly like a wrong password.
        let response = opaque_ke::CredentialResponse::<Suite>::deserialize(response.as_bytes())
            .map_err(|_| AccessError::NotAuthentic)?;
        let mut finished = state
            .finish(&mut rng::fresh()?, password.expose(), response, ClientLoginFinishParameters::default())
            .map_err(|_| AccessError::NotAuthentic)?;
        finished.session_key.as_mut_slice().zeroize();
        let key = export_key(finished.export_key.as_mut_slice());
        Ok((CredentialFinalization::from_slice(&finished.message.serialize())?, key?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod adversary {
        use super::*;

        #[test]
        fn the_export_key_is_wiped_where_opaque_ke_left_it() {
            let mut original = [0xA5u8; 64];
            let key = export_key(&mut original).unwrap();
            assert_eq!(original, [0; 64]);
            assert_eq!(key, ExportKey::from_slice(&[0xA5; 64]).unwrap());
        }
    }
}
