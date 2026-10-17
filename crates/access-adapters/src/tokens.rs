use access::{AccessError, LoginHandle, SessionDigest, SessionDigester, SessionToken, Tokens};
use sha2::{Digest, Sha256};
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

/// SHA-256 of the 256-bit session token. The token is uniformly random, so
/// a plain hash is enough: there is nothing to brute-force.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256SessionDigest;

impl SessionDigester for Sha256SessionDigest {
    fn digest(&self, token: &SessionToken) -> SessionDigest {
        SessionDigest::from_array(Sha256::digest(token.expose()).into())
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
    fn digest_matches_the_sha256_known_answer() {
        let token = SessionToken::from_array([0; 32]);
        let expected = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";
        let hex: String = Sha256SessionDigest.digest(&token).as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }
}
