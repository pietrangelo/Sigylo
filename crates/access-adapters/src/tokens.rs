use access::{AccessError, LoginHandle, SessionDigest, SessionDigester, SessionToken, Tokens};
use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Session tokens (256 bits) and login handles (128 bits) from the CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomTokens;

impl Tokens for RandomTokens {
    fn session(&self) -> Result<SessionToken, AccessError> {
        let mut bytes = Zeroizing::new([0u8; SessionToken::LEN]);
        getrandom::fill(&mut *bytes).map_err(|_| AccessError::RandomnessUnavailable)?;
        Ok(SessionToken::from_array(*bytes))
    }

    fn login_handle(&self) -> Result<LoginHandle, AccessError> {
        let mut bytes = Zeroizing::new([0u8; LoginHandle::LEN]);
        getrandom::fill(&mut *bytes).map_err(|_| AccessError::RandomnessUnavailable)?;
        Ok(LoginHandle::from_array(*bytes))
    }
}

/// The digest the store keeps instead of a session token: HMAC-SHA256 under
/// a key derived from the relay secret ([`crate::OpaqueKeys::session_digest`]).
/// The token is uniformly random, so there is nothing to brute-force; the key
/// is there for whoever can write the database without the relay secret (a
/// stolen relay credential): they can file a session row, but can never hold
/// a token whose digest matches it.
#[derive(Clone)]
pub struct HmacSessionDigest {
    key: Zeroizing<[u8; 32]>,
}

impl HmacSessionDigest {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Zeroizing::new(key) }
    }
}

impl fmt::Debug for HmacSessionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacSessionDigest(redacted)")
    }
}

impl SessionDigester for HmacSessionDigest {
    fn digest(&self, token: &SessionToken) -> SessionDigest {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.key).expect("HMAC takes any key length");
        mac.update(token.expose());
        SessionDigest::from_array(mac.finalize().into_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn tokens_never_repeat() {
        let tokens: HashSet<[u8; 32]> = (0..10_000).map(|_| *RandomTokens.session().unwrap().expose()).collect();
        assert_eq!(tokens.len(), 10_000);
        let handles: HashSet<[u8; 16]> = (0..10_000).map(|_| *RandomTokens.login_handle().unwrap().expose()).collect();
        assert_eq!(handles.len(), 10_000);
    }

    #[test]
    fn digest_matches_the_hmac_sha256_known_answer() {
        // RFC 4231 has no all-zero case; this value is HMAC-SHA256(key = 32 × 0x07, msg = 32 × 0x00).
        let token = SessionToken::from_array([0; 32]);
        let hex: String =
            HmacSessionDigest::new([7; 32]).digest(&token).as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, KNOWN_ANSWER);
    }

    const KNOWN_ANSWER: &str = "2218b7858ad25437f7c681339eb7624b36ae3578527e72bb7ceff3870e208f33";

    mod adversary {
        use super::*;

        #[test]
        fn the_digest_is_not_the_plain_hash_a_database_thief_could_compute() {
            let token = SessionToken::from_array([0; 32]);
            let plain = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";
            let hex: String =
                HmacSessionDigest::new([7; 32]).digest(&token).as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            assert_ne!(hex, plain);
            assert_ne!(HmacSessionDigest::new([7; 32]).digest(&token), HmacSessionDigest::new([8; 32]).digest(&token));
        }

        #[test]
        fn debug_never_prints_the_key() {
            assert_eq!(format!("{:?}", HmacSessionDigest::new([7; 32])), "HmacSessionDigest(redacted)");
        }
    }
}
