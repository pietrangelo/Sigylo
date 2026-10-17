use custody::{RevocationDigest, RevocationToken, TokenDigest};
use sha2::{Digest, Sha256};

/// SHA-256 of the 256-bit revocation token. The token is uniformly random,
/// so a plain hash is enough: there is nothing to brute-force.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256TokenDigest;

impl TokenDigest for Sha256TokenDigest {
    fn digest(&self, token: &RevocationToken) -> RevocationDigest {
        RevocationDigest::from_array(Sha256::digest(token.expose()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_sha256_known_answer() {
        // SHA-256 of 32 zero bytes.
        let token = RevocationToken::from_slice(&[0; 32]).unwrap();
        let expected = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";
        let hex: String = Sha256TokenDigest.digest(&token).as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }
}
