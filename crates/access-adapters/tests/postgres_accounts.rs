//! Account store contract tests against a real PostgreSQL with the Sigylo
//! migrations, driven through the real OPAQUE adapters.
//!
//! Run through `bash supabase/tests/run.sh`, which starts a throwaway
//! database and sets the two URLs. The store connects as `sigylo_relay`
//! (the Worker's role); time travel uses the owner connection.
#![cfg(feature = "postgres")]

use access::{
    AccessError, AccountId, AccountStore, Gatekeeper, Keyring, KeyringVersion, KeyringWrite, LoginChallenge,
    LoginHandle, Member, OpaqueServer, Password, Session, SessionDigester, Throttle, Tokens, Username,
};
use access_adapters::{HkdfKeyringKdf, OpaqueDevice, OpaqueKeys, PostgresAccounts, RandomTokens, Sha256SessionDigest};
use futures_util::future::join_all;
use tokio_postgres::{Client, NoTls};

async fn connect(var: &str) -> Option<Client> {
    let Ok(url) = std::env::var(var) else {
        eprintln!("{var} not set: run `bash supabase/tests/run.sh`; skipping");
        return None;
    };
    let (client, connection) = tokio_postgres::connect(&url, NoTls).await.expect("database reachable");
    tokio::spawn(connection);
    Some(client)
}

macro_rules! databases {
    ($relay:ident, $admin:ident) => {
        let (Some($relay), Some($admin)) =
            (connect("SIGYLO_TEST_RELAY_URL").await, connect("SIGYLO_TEST_DATABASE_URL").await)
        else {
            return;
        };
    };
}

#[derive(Debug)]
struct Open;

impl Throttle for Open {
    async fn admit(&self, _account: &AccountId) -> bool {
        true
    }
}

fn keys() -> OpaqueKeys {
    OpaqueKeys::from_seed(&[9; 32]).unwrap()
}

type Relay<'a> = Gatekeeper<OpaqueKeys, PostgresAccounts<'a>, RandomTokens, Sha256SessionDigest, Open>;

fn relay(client: &Client) -> Relay<'_> {
    Gatekeeper::new(keys(), PostgresAccounts::new(client), RandomTokens, Sha256SessionDigest, Open)
}

fn device() -> Member<OpaqueDevice, HkdfKeyringKdf> {
    Member::new(OpaqueDevice, HkdfKeyringKdf)
}

fn pw() -> Password {
    Password::new(b"correct horse battery".to_vec()).unwrap()
}

/// A unique name per test run, so tests never collide in the shared database.
fn fresh_name() -> Username {
    let tag: String = RandomTokens.login_handle().unwrap().expose()[..8].iter().map(|b| format!("{b:02x}")).collect();
    Username::new(&format!("user-{tag}")).unwrap()
}

async fn register(relay: &Relay<'_>, name: &Username) {
    let (request, pending) = device().begin_registration(pw()).unwrap();
    let response = relay.registration_response(name, &request).unwrap();
    let (record, _) = device().finish_registration(pending, &response).unwrap();
    relay.register(name, &record).await.unwrap();
}

/// KE1 → KE2 → KE3, returning the challenge and KE3 without finishing.
async fn challenge(relay: &Relay<'_>, name: &Username) -> (LoginChallenge, access::CredentialFinalization) {
    let (request, pending) = device().begin_login(pw()).unwrap();
    let challenge = relay.begin_login(name, &request).await.unwrap();
    let (finalization, _) = device().finish_login(pending, &challenge.response).unwrap();
    (challenge, finalization)
}

async fn login(relay: &Relay<'_>, name: &Username) -> Session {
    let (challenge, finalization) = challenge(relay, name).await;
    relay.finish_login(&challenge.handle, &finalization).await.unwrap()
}

fn keyring(byte: u8) -> Keyring {
    Keyring::new(vec![byte; 500]).unwrap()
}

async fn expire_sessions(admin: &Client, relay: &Relay<'_>, name: &Username) {
    let account = keys().account_of(name);
    let _ = relay;
    admin
        .execute(
            "update access.sessions set expires_at = now() - interval '1 second' where account = $1",
            &[&account.as_bytes().as_slice()],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn register_login_keyring_and_sign_out() {
    databases!(client, _admin);
    let relay = relay(&client);
    let name = fresh_name();
    register(&relay, &name).await;
    let session = login(&relay, &name).await;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!((session.expires_at.0 - now - i64::from(access::SESSION_SECONDS)).abs() < 60);

    let empty = relay.keyring(&session.token).await.unwrap();
    assert_eq!((empty.keyring, empty.version), (None, KeyringVersion::NONE));
    let v1 = relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE).await.unwrap();
    assert_eq!(v1, KeyringVersion(1));
    assert_eq!(
        relay.store_keyring(&session.token, &keyring(2), KeyringVersion::NONE).await.unwrap_err(),
        AccessError::Conflict
    );
    assert_eq!(relay.keyring(&session.token).await.unwrap().keyring, Some(keyring(1)));

    relay.sign_out(&session.token).await.unwrap();
    assert_eq!(relay.keyring(&session.token).await.unwrap_err(), AccessError::Unauthorized);
}

#[tokio::test]
async fn a_taken_name_is_never_overwritten() {
    databases!(client, _admin);
    let relay = relay(&client);
    let name = fresh_name();
    register(&relay, &name).await;
    let (request, pending) =
        device().begin_registration(Password::new(b"attacker password".to_vec()).unwrap()).unwrap();
    let response = relay.registration_response(&name, &request).unwrap();
    let (record, _) = device().finish_registration(pending, &response).unwrap();
    assert_eq!(relay.register(&name, &record).await.unwrap_err(), AccessError::AlreadyRegistered);
    login(&relay, &name).await;
}

#[tokio::test]
async fn sessions_end_by_the_database_clock() {
    databases!(client, admin);
    let relay = relay(&client);
    let name = fresh_name();
    register(&relay, &name).await;
    let session = login(&relay, &name).await;
    expire_sessions(&admin, &relay, &name).await;
    assert_eq!(relay.keyring(&session.token).await.unwrap_err(), AccessError::Unauthorized);
    assert_eq!(
        relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE).await.unwrap_err(),
        AccessError::Unauthorized
    );
    assert_eq!(relay.close_account(&session.token).await.unwrap_err(), AccessError::Unauthorized);
}

#[tokio::test]
async fn an_expired_login_cannot_be_finished() {
    databases!(client, admin);
    let relay = relay(&client);
    let name = fresh_name();
    register(&relay, &name).await;
    let (challenge, finalization) = challenge(&relay, &name).await;
    admin
        .execute(
            "update access.logins set expires_at = now() - interval '1 second' where handle = $1",
            &[&challenge.handle.expose().as_slice()],
        )
        .await
        .unwrap();
    assert_eq!(relay.finish_login(&challenge.handle, &finalization).await.unwrap_err(), AccessError::NotAuthentic);
}

#[tokio::test]
async fn closing_the_account_removes_record_keyring_sessions_and_logins() {
    databases!(client, admin);
    let relay = relay(&client);
    let name = fresh_name();
    register(&relay, &name).await;
    let session = login(&relay, &name).await;
    let other = login(&relay, &name).await;
    let (pending, _) = challenge(&relay, &name).await;
    relay.store_keyring(&session.token, &keyring(3), KeyringVersion::NONE).await.unwrap();
    relay.close_account(&session.token).await.unwrap();

    let account = keys().account_of(&name);
    let left: i64 = admin
        .query_one(
            "select (select count(*) from access.accounts where account = $1)
                  + (select count(*) from access.sessions where account = $1)
                  + (select count(*) from access.logins where account = $1)",
            &[&account.as_bytes().as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, 0);
    assert_eq!(relay.keyring(&other.token).await.unwrap_err(), AccessError::Unauthorized);
    let _ = pending;
    // The name is free again.
    register(&relay, &name).await;
}

#[tokio::test]
async fn purge_removes_only_what_expired() {
    databases!(client, admin);
    let relay = relay(&client);
    let name = fresh_name();
    register(&relay, &name).await;
    let stale = login(&relay, &name).await;
    let live = login(&relay, &name).await;
    let digest = Sha256SessionDigest.digest(&stale.token);
    admin
        .execute(
            "update access.sessions set expires_at = now() - interval '1 second' where digest = $1",
            &[&digest.as_bytes().as_slice()],
        )
        .await
        .unwrap();
    assert!(relay.purge_expired().await.unwrap() >= 1);
    let gone: i64 = admin
        .query_one("select count(*) from access.sessions where digest = $1", &[&digest.as_bytes().as_slice()])
        .await
        .unwrap()
        .get(0);
    assert_eq!(gone, 0);
    assert!(relay.keyring(&live.token).await.is_ok());
}

mod adversary {
    use super::*;

    #[tokio::test]
    async fn concurrent_finishes_of_one_login_open_one_session() {
        databases!(client, admin);
        let relay = relay(&client);
        let name = fresh_name();
        register(&relay, &name).await;
        let (challenge, finalization) = challenge(&relay, &name).await;
        // 12 connections race to finish the same login with the genuine KE3.
        let mut clients = Vec::new();
        for _ in 0..12 {
            clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
        }
        let handle = challenge.handle.clone();
        let outcomes = join_all(clients.iter().map(|c| {
            let handle: LoginHandle = handle.clone();
            let finalization = finalization.clone();
            async move { self::relay(c).finish_login(&handle, &finalization).await }
        }))
        .await;
        assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
        assert!(outcomes.iter().filter(|o| o.is_err()).all(|o| *o.as_ref().unwrap_err() == AccessError::NotAuthentic));
        let account = keys().account_of(&name);
        let sessions: i64 = admin
            .query_one("select count(*) from access.sessions where account = $1", &[&account.as_bytes().as_slice()])
            .await
            .unwrap()
            .get(0);
        assert_eq!(sessions, 1);
    }

    #[tokio::test]
    async fn concurrent_keyring_writes_from_one_version_store_exactly_one() {
        databases!(client, _admin);
        let relay = relay(&client);
        let name = fresh_name();
        register(&relay, &name).await;
        let session = login(&relay, &name).await;
        let digest = Sha256SessionDigest.digest(&session.token);
        let mut clients = Vec::new();
        for _ in 0..12 {
            clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
        }
        let outcomes = join_all(clients.iter().enumerate().map(|(i, c)| async move {
            PostgresAccounts::new(c).store_keyring(&digest, &keyring(i as u8 + 1), KeyringVersion::NONE).await
        }))
        .await;
        let stored: Vec<_> = outcomes.iter().filter(|o| matches!(o, Ok(KeyringWrite::Stored(_)))).collect();
        assert_eq!(stored.len(), 1);
        assert!(
            outcomes.iter().all(|o| matches!(o, Ok(KeyringWrite::Stored(KeyringVersion(1)) | KeyringWrite::Stale)))
        );
        assert_eq!(relay.keyring(&session.token).await.unwrap().version, KeyringVersion(1));
    }

    #[tokio::test]
    async fn unknown_names_park_a_login_like_real_ones() {
        databases!(client, admin);
        let relay = relay(&client);
        let ghost = fresh_name();
        let (request, _) = device().begin_login(pw()).unwrap();
        let challenge = relay.begin_login(&ghost, &request).await.unwrap();
        let parked: i64 = admin
            .query_one("select count(*) from access.logins where handle = $1", &[&challenge.handle.expose().as_slice()])
            .await
            .unwrap()
            .get(0);
        assert_eq!(parked, 1);
    }

    #[tokio::test]
    async fn the_database_holds_neither_names_nor_tokens() {
        databases!(client, admin);
        let relay = relay(&client);
        let name = fresh_name();
        register(&relay, &name).await;
        let session = login(&relay, &name).await;
        let found: i64 = admin
            .query_one(
                "select (select count(*) from access.accounts where position($1 in account || record) > 0)
                      + (select count(*) from access.sessions where position($2 in digest) > 0)",
                &[&name.as_bytes(), &session.token.expose().as_slice()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(found, 0);
    }
}
