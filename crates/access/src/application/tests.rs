use super::fakes::{CountingThrottle, FakeStore, SequentialTokens, ToyDigest, ToyKdf, ToyOpaque, ToyPasses, block_on};
use super::{AccountStore, Gatekeeper, Member, OpaqueServer, Passes, SessionDigester, Throttle, Tokens};
use crate::core::{
    AccessError, AccountId, Budget, CredentialFinalization, DevicePass, Keyring, KeyringKey, KeyringVersion,
    LOGIN_WINDOW_SECONDS, MAX_SESSIONS, Password, RegistrationRecord, SESSION_SECONDS, Session, Username,
};

struct World {
    opaque: ToyOpaque,
    store: FakeStore,
    tokens: SequentialTokens,
    throttle: CountingThrottle,
    passes: ToyPasses,
}

type Relay<'a> =
    Gatekeeper<&'a ToyOpaque, &'a FakeStore, &'a SequentialTokens, ToyDigest, &'a CountingThrottle, &'a ToyPasses>;

impl World {
    fn new() -> Self {
        Self {
            opaque: ToyOpaque::default(),
            store: FakeStore::default(),
            tokens: SequentialTokens::default(),
            throttle: CountingThrottle::default(),
            passes: ToyPasses,
        }
    }

    fn relay(&self) -> Relay<'_> {
        Gatekeeper::new(&self.opaque, &self.store, &self.tokens, ToyDigest, &self.throttle, &self.passes)
    }

    fn device(&self) -> Member<&ToyOpaque, ToyKdf> {
        Member::new(&self.opaque, ToyKdf)
    }

    fn register(&self, name: &str, password: &str) -> Result<KeyringKey, AccessError> {
        let username = Username::new(name)?;
        let (request, pending) = self.device().begin_registration(pw(password))?;
        let response = block_on(self.relay().registration_response(&username, &request))?;
        let (record, key) = self.device().finish_registration(pending, &response)?;
        block_on(self.relay().register(&username, &record))?;
        Ok(key)
    }

    fn login(&self, name: &str, password: &str) -> Result<(Session, KeyringKey), AccessError> {
        self.login_with(name, password, None)
    }

    /// A login from a device that shows the pass of an earlier login.
    fn login_with(
        &self,
        name: &str,
        password: &str,
        pass: Option<&DevicePass>,
    ) -> Result<(Session, KeyringKey), AccessError> {
        let username = Username::new(name)?;
        let (request, pending) = self.device().begin_login(pw(password))?;
        let challenge = block_on(self.relay().begin_login(&username, &request, pass))?;
        let (finalization, key) = self.device().finish_login(pending, &challenge.response)?;
        let session = block_on(self.relay().finish_login(&challenge.handle, &finalization))?;
        Ok((session, key))
    }
}

fn pw(s: &str) -> Password {
    Password::new(s.as_bytes().to_vec()).unwrap()
}

fn keyring(byte: u8) -> Keyring {
    Keyring::new(vec![byte; 300]).unwrap()
}

#[test]
fn login_opens_a_session_and_recovers_the_registration_keyring_key() {
    let world = World::new();
    let registered = world.register("ada", "correct horse battery").unwrap();
    let (session, key) = world.login("ada", "correct horse battery").unwrap();
    assert_eq!(key, registered);
    assert_eq!(session.expires_at.0, i64::from(SESSION_SECONDS));
    assert_eq!(block_on(world.relay().keyring(&session.token)).unwrap().version, KeyringVersion::NONE);
}

#[test]
fn usernames_are_case_insensitive() {
    let world = World::new();
    world.register("Ada", "correct horse battery").unwrap();
    assert!(world.login("ADA", "correct horse battery").is_ok());
}

#[test]
fn a_wrong_password_opens_nothing() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    assert_eq!(world.login("ada", "correct horse battery!").unwrap_err(), AccessError::NotAuthentic);
    assert!(world.store.sessions.borrow().is_empty());
}

#[test]
fn an_unknown_user_gets_an_answer_and_then_the_same_failure() {
    let world = World::new();
    let username = Username::new("nobody").unwrap();
    let (request, pending) = world.device().begin_login(pw("whatever123")).unwrap();
    // The relay answers as if the account existed...
    let challenge = block_on(world.relay().begin_login(&username, &request, None)).unwrap();
    // ...and the failure is the one a wrong password gives.
    assert_eq!(world.device().finish_login(pending, &challenge.response).unwrap_err(), AccessError::NotAuthentic);
    let forged = CredentialFinalization::from_slice(&[0; CredentialFinalization::LEN]).unwrap();
    assert_eq!(
        block_on(world.relay().finish_login(&challenge.handle, &forged)).unwrap_err(),
        AccessError::NotAuthentic
    );
}

#[test]
fn a_taken_username_is_never_overwritten() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    assert_eq!(world.register("ADA", "attacker password").unwrap_err(), AccessError::AlreadyRegistered);
    assert!(world.login("ada", "correct horse battery").is_ok());
    assert_eq!(world.login("ada", "attacker password").unwrap_err(), AccessError::NotAuthentic);
}

#[test]
fn a_login_must_finish_within_its_window() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    let username = Username::new("ada").unwrap();
    let (request, pending) = world.device().begin_login(pw("correct horse battery")).unwrap();
    let challenge = block_on(world.relay().begin_login(&username, &request, None)).unwrap();
    let (finalization, _) = world.device().finish_login(pending, &challenge.response).unwrap();
    world.store.advance(LOGIN_WINDOW_SECONDS);
    assert_eq!(
        block_on(world.relay().finish_login(&challenge.handle, &finalization)).unwrap_err(),
        AccessError::NotAuthentic
    );
}

#[test]
fn sessions_expire() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    let (session, _) = world.login("ada", "correct horse battery").unwrap();
    world.store.advance(SESSION_SECONDS - 1);
    assert!(block_on(world.relay().keyring(&session.token)).is_ok());
    world.store.advance(1);
    assert_eq!(block_on(world.relay().keyring(&session.token)).unwrap_err(), AccessError::Unauthorized);
}

#[test]
fn signing_out_ends_the_session_only() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    let (laptop, _) = world.login("ada", "correct horse battery").unwrap();
    let (phone, _) = world.login("ada", "correct horse battery").unwrap();
    block_on(world.relay().sign_out(&laptop.token)).unwrap();
    assert_eq!(block_on(world.relay().keyring(&laptop.token)).unwrap_err(), AccessError::Unauthorized);
    assert!(block_on(world.relay().keyring(&phone.token)).is_ok());
}

#[test]
fn signing_out_everywhere_ends_every_session_of_the_account_only() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    world.register("bob", "another long password").unwrap();
    let (laptop, _) = world.login("ada", "correct horse battery").unwrap();
    let (phone, _) = world.login("ada", "correct horse battery").unwrap();
    let (bob, _) = world.login("bob", "another long password").unwrap();
    block_on(world.relay().sign_out_everywhere(&phone.token)).unwrap();
    for gone in [&laptop, &phone] {
        assert_eq!(block_on(world.relay().keyring(&gone.token)).unwrap_err(), AccessError::Unauthorized);
    }
    assert!(block_on(world.relay().keyring(&bob.token)).is_ok());
    // The account and its keyring stay; logging in again works.
    assert!(world.login("ada", "correct horse battery").is_ok());
}

#[test]
fn signing_out_everywhere_needs_a_live_session() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    let (session, _) = world.login("ada", "correct horse battery").unwrap();
    let (other, _) = world.login("ada", "correct horse battery").unwrap();
    block_on(world.relay().sign_out(&session.token)).unwrap();
    assert_eq!(block_on(world.relay().sign_out_everywhere(&session.token)).unwrap_err(), AccessError::Unauthorized);
    assert!(block_on(world.relay().keyring(&other.token)).is_ok());
}

#[test]
fn an_account_keeps_at_most_max_sessions_and_the_oldest_goes_first() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    let sessions: Vec<Session> = (0..=MAX_SESSIONS)
        .map(|_| {
            world.store.advance(1);
            world.login("ada", "correct horse battery").unwrap().0
        })
        .collect();
    assert_eq!(world.store.sessions.borrow().len(), MAX_SESSIONS as usize);
    assert_eq!(block_on(world.relay().keyring(&sessions[0].token)).unwrap_err(), AccessError::Unauthorized);
    for live in &sessions[1..] {
        assert!(block_on(world.relay().keyring(&live.token)).is_ok());
    }
}

#[test]
fn keyring_writes_name_the_version_they_read() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    let (session, _) = world.login("ada", "correct horse battery").unwrap();
    let relay = world.relay();
    let v1 = block_on(relay.store_keyring(&session.token, &keyring(1), KeyringVersion::NONE)).unwrap();
    assert_eq!(v1, KeyringVersion(1));
    // A second device that read version 0 cannot clobber version 1.
    assert_eq!(
        block_on(relay.store_keyring(&session.token, &keyring(2), KeyringVersion::NONE)).unwrap_err(),
        AccessError::Conflict
    );
    let snapshot = block_on(relay.keyring(&session.token)).unwrap();
    assert_eq!((snapshot.keyring, snapshot.version), (Some(keyring(1)), v1));
    assert_eq!(block_on(relay.store_keyring(&session.token, &keyring(2), v1)).unwrap(), KeyringVersion(2));
}

#[test]
fn closing_the_account_removes_everything_and_frees_the_name() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    let (session, _) = world.login("ada", "correct horse battery").unwrap();
    let (other, _) = world.login("ada", "correct horse battery").unwrap();
    block_on(world.relay().store_keyring(&session.token, &keyring(1), KeyringVersion::NONE)).unwrap();
    block_on(world.relay().close_account(&session.token)).unwrap();
    assert_eq!(world.store.account_count(), 0);
    assert_eq!(block_on(world.relay().keyring(&other.token)).unwrap_err(), AccessError::Unauthorized);
    assert_eq!(world.login("ada", "correct horse battery").unwrap_err(), AccessError::NotAuthentic);
    assert!(world.register("ada", "a new password").is_ok());
}

#[test]
fn closing_needs_a_live_session() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    let (session, _) = world.login("ada", "correct horse battery").unwrap();
    block_on(world.relay().sign_out(&session.token)).unwrap();
    assert_eq!(block_on(world.relay().close_account(&session.token)).unwrap_err(), AccessError::Unauthorized);
    assert_eq!(world.store.account_count(), 1);
}

#[test]
fn purge_removes_expired_logins_and_sessions() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    world.login("ada", "correct horse battery").unwrap();
    let (request, _) = world.device().begin_login(pw("correct horse battery")).unwrap();
    block_on(world.relay().begin_login(&Username::new("ada").unwrap(), &request, None)).unwrap();
    world.store.advance(SESSION_SECONDS);
    assert_eq!(block_on(world.relay().purge_expired()).unwrap(), 2);
    assert_eq!(world.store.account_count(), 1);
}

#[test]
fn failures_of_the_world_surface_as_such() {
    let world = World::new();
    world.register("ada", "correct horse battery").unwrap();
    world.tokens.broken.set(true);
    assert_eq!(world.login("ada", "correct horse battery").unwrap_err(), AccessError::RandomnessUnavailable);
    world.tokens.broken.set(false);
    world.store.broken.set(true);
    assert_eq!(world.login("ada", "correct horse battery").unwrap_err(), AccessError::StoreUnavailable);
}

mod adversary {
    use super::*;

    #[test]
    fn a_record_no_login_could_use_is_never_filed() {
        // register/finish needs no register/start: a forged record would
        // take the name for good, with no login that could ever close it.
        let world = World::new();
        let username = Username::new("ada").unwrap();
        let forged = RegistrationRecord::from_slice(&[0xFF; RegistrationRecord::LEN]).unwrap();
        assert_eq!(block_on(world.relay().register(&username, &forged)), Err(AccessError::MalformedMessage));
        world.register("ada", "correct horse battery").unwrap();
    }

    #[test]
    fn a_taken_name_gets_no_oprf_evaluation() {
        // Otherwise register/start answers OPRF(k_account, guess) for the
        // victim's own key, and one KE2 lets anyone test guesses offline.
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let (request, _) = world.device().begin_registration(pw("guess number one")).unwrap();
        for name in ["ada", "ADA"] {
            let username = Username::new(name).unwrap();
            assert_eq!(
                block_on(world.relay().registration_response(&username, &request)).unwrap_err(),
                AccessError::AlreadyRegistered
            );
        }
    }

    #[test]
    fn a_taken_name_is_refused_before_any_budget_is_spent() {
        // "Taken" is what register/start says anyway, so it costs nothing:
        // otherwise anyone could lock the owner out by registering their name.
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        world.throttle.limit.set(0);
        let before = world.throttle.spent_total();
        let (request, _) = world.device().begin_registration(pw("guess number one")).unwrap();
        let username = Username::new("ada").unwrap();
        for _ in 0..5 {
            assert_eq!(
                block_on(world.relay().registration_response(&username, &request)).unwrap_err(),
                AccessError::AlreadyRegistered
            );
        }
        assert_eq!(world.throttle.spent_total(), before);
    }

    #[test]
    fn registrations_and_logins_have_budgets_of_their_own() {
        let world = World::new();
        world.throttle.limit.set(1);
        let username = Username::new("eve").unwrap();
        let (request, _) = world.device().begin_registration(pw("correct horse battery")).unwrap();
        block_on(world.relay().registration_response(&username, &request)).unwrap();
        assert_eq!(
            block_on(world.relay().registration_response(&username, &request)).unwrap_err(),
            AccessError::Throttled
        );
        // A flood of registrations for a name leaves its logins alone, and back.
        let (request, _) = world.device().begin_login(pw("correct horse battery")).unwrap();
        block_on(world.relay().begin_login(&username, &request, None)).unwrap();
        assert_eq!(block_on(world.relay().begin_login(&username, &request, None)).unwrap_err(), AccessError::Throttled);
    }

    #[test]
    fn a_flood_of_guesses_cannot_lock_out_a_device_that_logged_in_before() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let (session, _) = world.login("ada", "correct horse battery").unwrap();
        world.throttle.limit.set(3);
        // The attacker spends the name's shared budget...
        for _ in 0..3 {
            let _ = world.login("ada", "guess guess guess");
        }
        assert_eq!(world.login("ada", "correct horse battery").unwrap_err(), AccessError::Throttled);
        // ...but the owner's device has an allowance of its own.
        assert!(world.login_with("ada", "correct horse battery", Some(&session.pass)).is_ok());
    }

    #[test]
    fn a_pass_buys_nothing_for_another_account_or_a_forged_one() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        world.register("bob", "another long password").unwrap();
        let (ada, _) = world.login("ada", "correct horse battery").unwrap();
        let forged = DevicePass::from_array([7; DevicePass::LEN]);
        world.throttle.limit.set(1);
        assert!(world.login_with("bob", "guess guess guess", Some(&ada.pass)).is_err());
        assert_eq!(
            world.login_with("bob", "another long password", Some(&ada.pass)).unwrap_err(),
            AccessError::Throttled
        );
        assert_eq!(
            world.login_with("bob", "another long password", Some(&forged)).unwrap_err(),
            AccessError::Throttled
        );
    }

    #[test]
    fn a_pass_from_before_the_name_changed_hands_is_void() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let (old, _) = world.login("ada", "correct horse battery").unwrap();
        block_on(world.relay().close_account(&old.token)).unwrap();
        world.register("ada", "the new owner's password").unwrap();
        world.throttle.limit.set(1);
        let _ = world.login("ada", "guess guess guess");
        assert_eq!(world.login_with("ada", "guess number two", Some(&old.pass)).unwrap_err(), AccessError::Throttled);
    }

    #[test]
    fn a_pass_is_bound_to_its_account() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let (ada, _) = world.login("ada", "correct horse battery").unwrap();
        let account = world.opaque.account_of(&Username::new("nobody").unwrap());
        let record =
            block_on(world.store.record(&world.opaque.account_of(&Username::new("ada").unwrap()))).unwrap().unwrap();
        assert!(!world.passes.admits(&ada.pass, &account, &record));
    }

    #[test]
    fn an_unknown_account_spends_the_shared_budget_whatever_pass_it_shows() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let (ada, _) = world.login("ada", "correct horse battery").unwrap();
        world.throttle.limit.set(1);
        assert!(world.login_with("nobody", "whatever123", Some(&ada.pass)).is_err());
        assert_eq!(world.login("nobody", "whatever123").unwrap_err(), AccessError::Throttled);
    }

    #[test]
    fn a_login_handle_works_once_even_with_the_right_password() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let username = Username::new("ada").unwrap();
        let (request, pending) = world.device().begin_login(pw("correct horse battery")).unwrap();
        let challenge = block_on(world.relay().begin_login(&username, &request, None)).unwrap();
        let (finalization, _) = world.device().finish_login(pending, &challenge.response).unwrap();
        // An eavesdropper replays KE3 after the real client used it.
        assert!(block_on(world.relay().finish_login(&challenge.handle, &finalization)).is_ok());
        assert_eq!(
            block_on(world.relay().finish_login(&challenge.handle, &finalization)).unwrap_err(),
            AccessError::NotAuthentic
        );
    }

    #[test]
    fn a_wrong_guess_burns_the_handle() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let username = Username::new("ada").unwrap();
        let (request, pending) = world.device().begin_login(pw("correct horse battery")).unwrap();
        let challenge = block_on(world.relay().begin_login(&username, &request, None)).unwrap();
        let (finalization, _) = world.device().finish_login(pending, &challenge.response).unwrap();
        let mut flipped = finalization.as_bytes().to_vec();
        flipped[0] ^= 1;
        let flipped = CredentialFinalization::from_slice(&flipped).unwrap();
        assert_eq!(
            block_on(world.relay().finish_login(&challenge.handle, &flipped)).unwrap_err(),
            AccessError::NotAuthentic
        );
        // One guess per handle: the genuine KE3 no longer helps.
        assert_eq!(
            block_on(world.relay().finish_login(&challenge.handle, &finalization)).unwrap_err(),
            AccessError::NotAuthentic
        );
        assert_eq!(world.store.parked_logins(), 0);
    }

    #[test]
    fn logins_beyond_the_throttle_cost_no_opaque_work_and_park_nothing() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        world.throttle.limit.set(1);
        assert!(world.login("ada", "correct horse battery").is_ok());
        assert_eq!(world.login("ada", "correct horse battery").unwrap_err(), AccessError::Throttled);
        assert_eq!(world.store.parked_logins(), 0);
    }

    #[test]
    fn the_throttle_counts_per_account_not_per_name_spelling() {
        // The throttle sees the account, so "ADA" and "ada" share one budget.
        #[derive(Debug, Default)]
        struct Recorder(core::cell::RefCell<Vec<crate::core::AccountId>>);
        impl Throttle for Recorder {
            async fn admit(&self, account: &crate::core::AccountId, budget: &Budget) -> bool {
                assert_eq!(*budget, Budget::Login);
                self.0.borrow_mut().push(*account);
                true
            }
        }
        let world = World::new();
        let recorder = Recorder::default();
        let relay = Gatekeeper::new(&world.opaque, &world.store, &world.tokens, ToyDigest, &recorder, &world.passes);
        let (request, _) = world.device().begin_login(pw("whatever123")).unwrap();
        for name in ["ada", "ADA", "Ada"] {
            block_on(relay.begin_login(&Username::new(name).unwrap(), &request, None)).unwrap();
        }
        let seen = recorder.0.borrow();
        assert!(seen.iter().all(|a| *a == seen[0]));
    }

    #[test]
    fn a_login_begun_before_the_name_changed_hands_cannot_finish() {
        // close_account races a login/start that already read the old record
        // and parks its state only after the close; meanwhile someone else
        // registers the free name. The old owner must not get into it.
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let (session, _) = world.login("ada", "correct horse battery").unwrap();
        let account = world.opaque.account_of(&Username::new("ada").unwrap());
        let old_record = block_on(world.store.record(&account)).unwrap();
        let (request, pending) = world.device().begin_login(pw("correct horse battery")).unwrap();
        let (response, state) = world.opaque.begin_login(&account, old_record.as_ref(), &request).unwrap();
        block_on(world.relay().close_account(&session.token)).unwrap();
        world.register("ada", "the new owner's password").unwrap();
        let handle = world.tokens.login_handle().unwrap();
        block_on(world.store.park_login(&handle, &account, &state, LOGIN_WINDOW_SECONDS)).unwrap();
        let (finalization, _) = world.device().finish_login(pending, &response).unwrap();
        assert_eq!(
            block_on(world.relay().finish_login(&handle, &finalization)).unwrap_err(),
            AccessError::NotAuthentic
        );
    }

    #[test]
    fn two_throttles_admit_only_what_both_admit() {
        // A cheap first filter (Cloudflare's, per location) before the global
        // count: the second is not spent on what the first already refused.
        let first = CountingThrottle::default();
        let second = CountingThrottle::default();
        first.limit.set(1);
        second.limit.set(5);
        let both = (&first, &second);
        let account = AccountId::from_array([1; 32]);
        assert!(block_on(both.admit(&account, &Budget::Login)));
        assert!(!block_on(both.admit(&account, &Budget::Login)));
        assert_eq!(second.spent_total(), 1);
        let other = AccountId::from_array([2; 32]);
        second.limit.set(0);
        assert!(!block_on(both.admit(&other, &Budget::Login)));
    }

    #[test]
    fn the_store_never_holds_a_session_token() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        let (session, _) = world.login("ada", "correct horse battery").unwrap();
        let sessions = world.store.sessions.borrow();
        assert_eq!(sessions.len(), 1);
        let stored = sessions.keys().next().unwrap();
        assert_ne!(stored.as_bytes(), session.token.expose());
        assert_eq!(*stored, ToyDigest.digest(&session.token));
    }

    #[test]
    fn one_session_cannot_reach_another_accounts_keyring() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        world.register("bob", "another long password").unwrap();
        let (ada, _) = world.login("ada", "correct horse battery").unwrap();
        let (bob, _) = world.login("bob", "another long password").unwrap();
        block_on(world.relay().store_keyring(&ada.token, &keyring(1), KeyringVersion::NONE)).unwrap();
        assert_eq!(block_on(world.relay().keyring(&bob.token)).unwrap().keyring, None);
        block_on(world.relay().close_account(&bob.token)).unwrap();
        assert_eq!(block_on(world.relay().keyring(&ada.token)).unwrap().keyring, Some(keyring(1)));
    }

    #[test]
    fn a_forged_session_token_opens_nothing() {
        let world = World::new();
        world.register("ada", "correct horse battery").unwrap();
        world.login("ada", "correct horse battery").unwrap();
        let forged = world.tokens.session().unwrap();
        assert_eq!(block_on(world.relay().keyring(&forged)).unwrap_err(), AccessError::Unauthorized);
        assert_eq!(
            block_on(world.relay().store_keyring(&forged, &keyring(9), KeyringVersion::NONE)).unwrap_err(),
            AccessError::Unauthorized
        );
    }

    #[test]
    fn pending_states_do_not_print_the_password() {
        let world = World::new();
        let (_, pending) = world.device().begin_registration(pw("correct horse battery")).unwrap();
        let (_, login) = world.device().begin_login(pw("correct horse battery")).unwrap();
        let rendered = format!("{pending:?} {login:?}");
        assert!(!rendered.contains("horse"));
    }
}
