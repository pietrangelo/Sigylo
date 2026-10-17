//! The real OPAQUE adapters, driven through the domain's use cases' ports.

use access::{
    AccessError, AccountId, CredentialFinalization, CredentialResponse, ExportKey, KEYRING_INFO, KeyringKdf,
    OpaqueClient, OpaqueServer, Password, RegistrationRecord, RegistrationResponse, Username,
};
use access_adapters::{HkdfKeyringKdf, OpaqueDevice, OpaqueKeys};

fn keys() -> OpaqueKeys {
    OpaqueKeys::from_seed(&[42; 32]).unwrap()
}

fn pw(s: &str) -> Password {
    Password::new(s.as_bytes().to_vec()).unwrap()
}

fn account(keys: &OpaqueKeys, name: &str) -> AccountId {
    keys.account_of(&Username::new(name).unwrap())
}

fn register(keys: &OpaqueKeys, account: &AccountId, password: &str) -> (RegistrationRecord, ExportKey) {
    let (request, state) = OpaqueDevice.begin_registration(&pw(password)).unwrap();
    let response = keys.registration_response(account, &request).unwrap();
    OpaqueDevice.finish_registration(state, &pw(password), &response).unwrap()
}

/// A whole login; `tamper` may alter KE2 before the client sees it.
fn login(
    keys: &OpaqueKeys,
    account: &AccountId,
    record: Option<&RegistrationRecord>,
    password: &str,
    tamper: impl FnOnce(&mut Vec<u8>),
) -> Result<ExportKey, AccessError> {
    let (request, state) = OpaqueDevice.begin_login(&pw(password)).unwrap();
    let (response, server_state) = keys.begin_login(account, record, &request).unwrap();
    let mut bytes = response.as_bytes().to_vec();
    tamper(&mut bytes);
    let response = CredentialResponse::from_slice(&bytes).unwrap();
    let (finalization, export) = OpaqueDevice.finish_login(state, &pw(password), &response)?;
    keys.finish_login(&server_state, &finalization)?;
    Ok(export)
}

#[test]
fn login_recovers_the_export_key_of_registration() {
    let keys = keys();
    let ada = account(&keys, "ada");
    let (record, at_registration) = register(&keys, &ada, "correct horse battery");
    let at_login = login(&keys, &ada, Some(&record), "correct horse battery", |_| {}).unwrap();
    assert_eq!(at_login, at_registration);
    let k1 = HkdfKeyringKdf.derive(&at_login, KEYRING_INFO);
    assert_eq!(k1, HkdfKeyringKdf.derive(&at_registration, KEYRING_INFO));
    assert_ne!(k1, HkdfKeyringKdf.derive(&at_login, b"another purpose"));
}

#[test]
fn accounts_are_filed_under_a_keyed_hash_of_the_name() {
    let keys = keys();
    assert_eq!(account(&keys, "Ada"), account(&keys, "ada"));
    assert_ne!(account(&keys, "ada"), account(&keys, "bob"));
    // Another relay secret files the same name elsewhere: guessing names
    // against a database dump needs the secret too.
    let other = OpaqueKeys::from_seed(&[43; 32]).unwrap();
    assert_ne!(account(&keys, "ada"), account(&other, "ada"));
}

#[test]
fn the_relay_secret_must_be_32_bytes() {
    assert_eq!(OpaqueKeys::from_seed(&[1; 31]).unwrap_err(), AccessError::NotConfigured);
    assert_eq!(OpaqueKeys::from_seed(&[]).unwrap_err(), AccessError::NotConfigured);
}

mod adversary {
    use super::*;

    #[test]
    fn a_wrong_password_fails_on_the_device_before_anything_is_sent() {
        let keys = keys();
        let ada = account(&keys, "ada");
        let (record, _) = register(&keys, &ada, "correct horse battery");
        assert_eq!(login(&keys, &ada, Some(&record), "correct horse batterY", |_| {}), Err(AccessError::NotAuthentic));
    }

    #[test]
    fn an_unknown_account_looks_like_a_real_one_and_fails_like_a_wrong_password() {
        let keys = keys();
        let ghost = account(&keys, "ghost");
        let (request, state) = OpaqueDevice.begin_login(&pw("any password")).unwrap();
        let (response, _) = keys.begin_login(&ghost, None, &request).unwrap();
        assert_eq!(response.as_bytes().len(), CredentialResponse::LEN);
        assert_eq!(
            OpaqueDevice.finish_login(state, &pw("any password"), &response).unwrap_err(),
            AccessError::NotAuthentic
        );
    }

    #[test]
    fn every_bit_of_the_relay_answer_is_authenticated() {
        let keys = keys();
        let ada = account(&keys, "ada");
        let (record, _) = register(&keys, &ada, "correct horse battery");
        for position in [0, 31, 32, 63, 64, 100, 191, 192, 223, 224, 255, 256, 319] {
            let result = login(&keys, &ada, Some(&record), "correct horse battery", |b| b[position] ^= 0x01);
            assert_eq!(result, Err(AccessError::NotAuthentic), "bit flip at {position}");
        }
    }

    #[test]
    fn a_record_moved_to_another_account_does_not_open() {
        // A relay (or an attacker with write access to the table) that files
        // Ada's record under Bob's account cannot make Ada's password work there.
        let keys = keys();
        let (ada, bob) = (account(&keys, "ada"), account(&keys, "bob"));
        let (record, _) = register(&keys, &ada, "correct horse battery");
        assert_eq!(login(&keys, &bob, Some(&record), "correct horse battery", |_| {}), Err(AccessError::NotAuthentic));
    }

    #[test]
    fn a_relay_with_another_secret_cannot_answer_for_the_real_one() {
        let keys = keys();
        let ada = account(&keys, "ada");
        let (record, _) = register(&keys, &ada, "correct horse battery");
        let impostor = OpaqueKeys::from_seed(&[1; 32]).unwrap();
        assert_eq!(
            login(&impostor, &ada, Some(&record), "correct horse battery", |_| {}),
            Err(AccessError::NotAuthentic)
        );
    }

    #[test]
    fn ke3_from_one_login_does_not_finish_another() {
        let keys = keys();
        let ada = account(&keys, "ada");
        let (record, _) = register(&keys, &ada, "correct horse battery");
        let run = || {
            let (request, state) = OpaqueDevice.begin_login(&pw("correct horse battery")).unwrap();
            let (response, server_state) = keys.begin_login(&ada, Some(&record), &request).unwrap();
            let (finalization, _) = OpaqueDevice.finish_login(state, &pw("correct horse battery"), &response).unwrap();
            (finalization, server_state)
        };
        let (first, _) = run();
        let (_, second_state) = run();
        assert_eq!(keys.finish_login(&second_state, &first), Err(AccessError::NotAuthentic));
        let mut flipped = first.as_bytes().to_vec();
        flipped[10] ^= 0x80;
        let flipped = CredentialFinalization::from_slice(&flipped).unwrap();
        assert_eq!(keys.finish_login(&second_state, &flipped), Err(AccessError::NotAuthentic));
    }

    #[test]
    fn a_reflected_or_garbage_registration_answer_is_refused() {
        let keys = keys();
        let ada = account(&keys, "ada");
        let (request, state) = OpaqueDevice.begin_registration(&pw("correct horse battery")).unwrap();
        let honest = keys.registration_response(&ada, &request).unwrap();
        // The server echoes the blinded element back: the client must not
        // derive its keys from its own input.
        let mut reflected = request.as_bytes().to_vec();
        reflected.extend_from_slice(&honest.as_bytes()[32..]);
        let reflected = RegistrationResponse::from_slice(&reflected).unwrap();
        assert_eq!(
            OpaqueDevice.finish_registration(state, &pw("correct horse battery"), &reflected).unwrap_err(),
            AccessError::NotAuthentic
        );
        let (_, state) = OpaqueDevice.begin_registration(&pw("correct horse battery")).unwrap();
        let garbage = RegistrationResponse::from_slice(&[0xFF; RegistrationResponse::LEN]).unwrap();
        assert_eq!(
            OpaqueDevice.finish_registration(state, &pw("correct horse battery"), &garbage).unwrap_err(),
            AccessError::NotAuthentic
        );
    }

    #[test]
    fn invalid_points_from_a_client_are_refused_by_the_relay() {
        let keys = keys();
        let ada = account(&keys, "ada");
        let junk = access::RegistrationRequest::from_slice(&[0xFF; 32]).unwrap();
        assert_eq!(keys.registration_response(&ada, &junk).unwrap_err(), AccessError::MalformedMessage);
        let junk = access::CredentialRequest::from_slice(&[0xFF; 96]).unwrap();
        assert_eq!(keys.begin_login(&ada, None, &junk).unwrap_err(), AccessError::MalformedMessage);
    }

    #[test]
    fn debug_never_prints_the_relay_keys() {
        assert_eq!(format!("{:?}", keys()), "OpaqueKeys(redacted)");
    }
}
