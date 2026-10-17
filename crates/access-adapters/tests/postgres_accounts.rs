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
use access_adapters::{
    HkdfKeyringKdf, HmacSessionDigest, OpaqueDevice, OpaqueKeys, PostgresAccounts, PostgresThrottle, RandomTokens,
};
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

type Relay<'a> = Gatekeeper<OpaqueKeys, PostgresAccounts<'a>, RandomTokens, HmacSessionDigest, Open>;

fn relay(client: &Client) -> Relay<'_> {
    Gatekeeper::new(keys(), PostgresAccounts::new(client), RandomTokens, keys().session_digest(), Open)
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
    let response = relay.registration_response(name, &request).await.unwrap();
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
    // A rival started while the name was still free, and finishes second.
    let (request, pending) =
        device().begin_registration(Password::new(b"attacker password".to_vec()).unwrap()).unwrap();
    let response = relay.registration_response(&name, &request).await.unwrap();
    register(&relay, &name).await;
    let (record, _) = device().finish_registration(pending, &response).unwrap();
    assert_eq!(relay.register(&name, &record).await.unwrap_err(), AccessError::AlreadyRegistered);
    // Once taken, the name gets no OPRF evaluation at all.
    let (request, _) = device().begin_registration(pw()).unwrap();
    assert_eq!(relay.registration_response(&name, &request).await.unwrap_err(), AccessError::AlreadyRegistered);
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
    let digest = keys().session_digest().digest(&stale.token);
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
        let digest = keys().session_digest().digest(&session.token);
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

    /// Runs `body` with one account budget (`access.capacity_bytes` or
    /// `access.transient_capacity_bytes`) set to what is used now plus
    /// `headroom`, then puts the real one back.
    async fn with_capacity<F: std::future::Future<Output = ()>>(
        admin: &Client,
        transient: bool,
        headroom: i64,
        body: F,
    ) {
        let (function, column) = if transient {
            ("access.transient_capacity_bytes", "transient")
        } else {
            ("access.capacity_bytes", "stored")
        };
        let original: String = admin
            .query_one(&format!("select pg_get_functiondef('{function}()'::regprocedure)"), &[])
            .await
            .unwrap()
            .get(0);
        // Expired rows left by other tests would otherwise be purged mid-test and free room.
        admin.execute("select access.purge_expired()", &[]).await.unwrap();
        let used: i64 = admin.query_one(&format!("select {column} from access.usage"), &[]).await.unwrap().get(0);
        let tight = format!(
            "create or replace function {function}() returns bigint language plpgsql stable \
             set search_path = '' as $$ begin return {}; end $$",
            used + headroom
        );
        admin.batch_execute(&tight).await.unwrap();
        body.await;
        admin.batch_execute(&original).await.unwrap();
    }

    #[tokio::test]
    async fn a_full_account_store_refuses_new_names_and_bigger_keyrings_but_lets_members_in() {
        // Accounts never expire: a flood of registrations must hit our own
        // ceiling, not the database's 500 MB, where everything turns read-only.
        databases!(client, admin);
        let relay = relay(&client);
        let name = fresh_name();
        register(&relay, &name).await;
        let session = login(&relay, &name).await;
        let v1 = relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE).await.unwrap();
        with_capacity(&admin, false, 0, async {
            let newcomer = fresh_name();
            let (request, pending) = device().begin_registration(pw()).unwrap();
            let response = relay.registration_response(&newcomer, &request).await.unwrap();
            let (record, _) = device().finish_registration(pending, &response).unwrap();
            assert_eq!(relay.register(&newcomer, &record).await, Err(AccessError::StorageFull));
            let bigger = Keyring::new(vec![2; 501]).unwrap();
            assert_eq!(relay.store_keyring(&session.token, &bigger, v1).await, Err(AccessError::StorageFull));
            // Same size, smaller, logging in, reading: all still work.
            let v2 = relay.store_keyring(&session.token, &keyring(3), v1).await.unwrap();
            let smaller = Keyring::new(vec![4; 10]).unwrap();
            relay.store_keyring(&session.token, &smaller, v2).await.unwrap();
            let again = login(&relay, &name).await;
            assert_eq!(relay.keyring(&again.token).await.unwrap().keyring, Some(smaller));
        })
        .await;
    }

    #[tokio::test]
    async fn a_flood_of_logins_fills_only_its_own_budget_and_expired_ones_make_room() {
        databases!(client, admin);
        let relay = relay(&client);
        let name = fresh_name();
        register(&relay, &name).await;
        let (stale, _) = challenge(&relay, &name).await;
        with_capacity(&admin, true, 0, async {
            let (request, _) = device().begin_login(pw()).unwrap();
            assert_eq!(relay.begin_login(&name, &request).await.unwrap_err(), AccessError::StorageFull);
            // Accounts have their own budget: registering still works.
            register(&relay, &fresh_name()).await;
            // A login that expired is purged on the spot to make room.
            admin
                .execute(
                    "update access.logins set expires_at = now() - interval '1 second' where handle = $1",
                    &[&stale.handle.expose().as_slice()],
                )
                .await
                .unwrap();
            login(&relay, &name).await;
        })
        .await;
    }

    #[tokio::test]
    async fn the_usage_counter_is_what_the_tables_weigh() {
        databases!(client, admin);
        let relay = relay(&client);
        let name = fresh_name();
        register(&relay, &name).await;
        let session = login(&relay, &name).await;
        relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE).await.unwrap();
        challenge(&relay, &name).await;
        PostgresThrottle::new(&client, 10).admit(&keys().account_of(&fresh_name())).await;
        let doomed = fresh_name();
        register(&relay, &doomed).await;
        let doomed_session = login(&relay, &doomed).await;
        relay.store_keyring(&doomed_session.token, &keyring(2), KeyringVersion::NONE).await.unwrap();
        relay.close_account(&doomed_session.token).await.unwrap();
        relay.sign_out(&session.token).await.unwrap();
        let row = admin
            .query_one(
                "select u.stored = (select count(*) * 512 + coalesce(sum(octet_length(keyring)), 0) from access.accounts),
                        u.transient = (select count(*) * 384 from access.logins)
                                    + (select count(*) * 192 from access.sessions)
                                    + (select count(*) * 128 from access.attempts)
                 from access.usage u",
                &[],
            )
            .await
            .unwrap();
        assert!(row.get::<_, bool>(0), "stored bytes drifted from the accounts table");
        assert!(row.get::<_, bool>(1), "transient bytes drifted from logins, sessions and attempts");
    }

    #[tokio::test]
    async fn the_login_budget_is_one_count_for_the_whole_world() {
        databases!(client, admin);
        let throttle = PostgresThrottle::new(&client, 10);
        let target = keys().account_of(&fresh_name());
        for i in 0..10 {
            assert!(throttle.admit(&target).await, "attempt {i}");
        }
        assert!(!throttle.admit(&target).await);
        // Another relay instance (another Cloudflare location) shares the count.
        let elsewhere = connect("SIGYLO_TEST_RELAY_URL").await.unwrap();
        assert!(!PostgresThrottle::new(&elsewhere, 10).admit(&target).await);
        assert!(throttle.admit(&keys().account_of(&fresh_name())).await, "other accounts are untouched");
        // A minute later the budget is back, and the cron forgets the old window.
        admin
            .execute(
                "update access.attempts set window_start = now() - interval '61 seconds' where account = $1",
                &[&target.as_bytes().as_slice()],
            )
            .await
            .unwrap();
        assert!(throttle.admit(&target).await);
        admin
            .execute(
                "update access.attempts set window_start = now() - interval '61 seconds' where account = $1",
                &[&target.as_bytes().as_slice()],
            )
            .await
            .unwrap();
        relay(&client).purge_expired().await.unwrap();
        let left: i64 = admin
            .query_one("select count(*) from access.attempts where account = $1", &[&target.as_bytes().as_slice()])
            .await
            .unwrap()
            .get(0);
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn a_burst_from_many_connections_gets_exactly_the_budget() {
        databases!(client, _admin);
        let target = keys().account_of(&fresh_name());
        let mut clients = Vec::new();
        for _ in 0..12 {
            clients.push(connect("SIGYLO_TEST_RELAY_URL").await.unwrap());
        }
        let outcomes = join_all((0..36).map(|i| {
            let c = &clients[i % clients.len()];
            async move { PostgresThrottle::new(c, 10).admit(&target).await }
        }))
        .await;
        assert_eq!(outcomes.iter().filter(|admitted| **admitted).count(), 10);
        let _ = client;
    }

    #[tokio::test]
    async fn the_throttle_fails_closed() {
        databases!(client, _admin);
        // A limit the database refuses stands in for any failure to count.
        assert!(!PostgresThrottle::new(&client, 0).admit(&keys().account_of(&fresh_name())).await);
    }

    #[tokio::test]
    async fn a_session_filed_without_the_relay_secret_opens_nothing() {
        // A stolen relay credential can call open_session for an account it
        // knows, but it cannot hold a token whose keyed digest matches.
        databases!(client, _admin);
        let relay = relay(&client);
        let name = fresh_name();
        register(&relay, &name).await;
        let token = RandomTokens.session().unwrap();
        let unkeyed: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(token.expose()).into();
        let account = keys().account_of(&name);
        client
            .query_one(
                "select access.open_session($1, $2, 43200)",
                &[&unkeyed.as_slice(), &account.as_bytes().as_slice()],
            )
            .await
            .unwrap();
        assert_eq!(relay.keyring(&token).await.unwrap_err(), AccessError::Unauthorized);
        assert_eq!(relay.close_account(&token).await.unwrap_err(), AccessError::Unauthorized);
        // Nor can it file one that outlives a real session.
        let long = client
            .query_one(
                "select access.open_session($1, $2, 86400)",
                &[&[7u8; 32].as_slice(), &account.as_bytes().as_slice()],
            )
            .await;
        assert!(long.is_err(), "a 24-hour session was filed");
    }

    #[tokio::test]
    async fn a_login_started_before_a_name_changed_hands_cannot_enter_the_new_account() {
        databases!(client, admin);
        let relay = relay(&client);
        let name = fresh_name();
        register(&relay, &name).await;
        // The first owner has a genuine login in flight...
        let (challenge, finalization) = challenge(&relay, &name).await;
        let parked = admin
            .query_one(
                "select account, state from access.logins where handle = $1",
                &[&challenge.handle.expose().as_slice()],
            )
            .await
            .unwrap();
        let (account, state): (Vec<u8>, Vec<u8>) = (parked.get(0), parked.get(1));
        // ...closes the account, and someone else registers the free name.
        let session = login(&relay, &name).await;
        relay.close_account(&session.token).await.unwrap();
        register(&relay, &name).await;
        // Even with the old login put back, it does not finish into the new account.
        client
            .query_one(
                "select access.park_login($1, $2, $3, 300)",
                &[&challenge.handle.expose().as_slice(), &account, &state],
            )
            .await
            .unwrap();
        assert_eq!(relay.finish_login(&challenge.handle, &finalization).await.unwrap_err(), AccessError::NotAuthentic);
    }
}
