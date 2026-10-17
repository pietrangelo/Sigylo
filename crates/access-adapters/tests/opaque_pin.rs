//! Pins the OPAQUE suite of Sigylo v1. If any of these changes, every
//! registered account stops working: bump the suite (and migrate), never
//! update the constants.

use access::{
    CredentialFinalization, CredentialRequest, CredentialResponse, LoginState, OpaqueClient, OpaqueServer, Password,
    RegistrationRecord, RegistrationRequest, RegistrationResponse, Username,
};
use access_adapters::{HARDENING_LANES, HARDENING_MEMORY_KIB, HARDENING_PASSES, Hardening, OpaqueDevice, OpaqueKeys};
use opaque_ke::generic_array::GenericArray;
use opaque_ke::ksf::Ksf;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_domain_lengths_are_the_suite_lengths() {
    let keys = OpaqueKeys::from_seed(&[7; 32]).unwrap();
    let account = keys.account_of(&Username::new("ada").unwrap());
    let password = Password::new(b"correct horse battery".to_vec()).unwrap();

    let (request, state) = OpaqueDevice.begin_registration(&password).unwrap();
    assert_eq!(request.as_bytes().len(), RegistrationRequest::LEN);
    let response = keys.registration_response(&account, &request).unwrap();
    assert_eq!(response.as_bytes().len(), RegistrationResponse::LEN);
    let (record, _) = OpaqueDevice.finish_registration(state, &password, &response).unwrap();
    assert_eq!(record.as_bytes().len(), RegistrationRecord::LEN);

    let (request, state) = OpaqueDevice.begin_login(&password).unwrap();
    assert_eq!(request.as_bytes().len(), CredentialRequest::LEN);
    let (response, server_state) = keys.begin_login(&account, Some(&record), &request).unwrap();
    assert_eq!(response.as_bytes().len(), CredentialResponse::LEN);
    assert_eq!(server_state.expose().len(), LoginState::LEN);
    let (finalization, _) = OpaqueDevice.finish_login(state, &password, &response).unwrap();
    assert_eq!(finalization.as_bytes().len(), CredentialFinalization::LEN);
}

#[test]
fn the_same_secret_always_yields_the_same_relay_keys() {
    let keys = OpaqueKeys::from_seed(&[7; 32]).unwrap();
    assert_eq!(hex(&keys.public_key()), "c617fb15501ba29ba1d737642a756cb1e1319420a2e6832a8be133ec8835ba46");
    let account = keys.account_of(&Username::new("ada").unwrap());
    assert_eq!(hex(account.as_bytes()), "32e9430eb9ea9e59a423e47c8e388934c165f4aa29774933970d49fa3f1c94f0");
}

#[test]
fn the_hardening_is_argon2id_64_mib_3_passes_1_lane() {
    assert_eq!((HARDENING_MEMORY_KIB, HARDENING_PASSES, HARDENING_LANES), (65_536, 3, 1));
    let input = GenericArray::<u8, opaque_ke::generic_array::typenum::U64>::clone_from_slice(&[1; 64]);
    let output = Hardening.hash(input).unwrap();
    assert_eq!(hex(&Sha256::digest(output)), "f0af42ef54a813175f1bc966daf3bac6768ba742231a703fab870d525c7ee2df");
}
