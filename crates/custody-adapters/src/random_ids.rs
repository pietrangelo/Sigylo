use custody::{ClaimToken, CustodyError, DropId, IdSource};

/// 128-bit ids and 256-bit claim tokens from the operating system CSPRNG; in
/// a Worker, `crypto.getRandomValues`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomIds;

impl IdSource for RandomIds {
    fn fresh(&self) -> Result<DropId, CustodyError> {
        let mut bytes = [0u8; DropId::LEN];
        getrandom::fill(&mut bytes).map_err(|_| CustodyError::RandomnessUnavailable)?;
        DropId::from_slice(&bytes)
    }

    fn fresh_claim(&self) -> Result<ClaimToken, CustodyError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CustodyError::RandomnessUnavailable)?;
        Ok(ClaimToken::from_array(bytes))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn ids_never_repeat() {
        let ids: HashSet<[u8; DropId::LEN]> = (0..10_000).map(|_| *RandomIds.fresh().unwrap().as_bytes()).collect();
        assert_eq!(ids.len(), 10_000);
    }

    #[test]
    fn claims_never_repeat() {
        let claims: HashSet<[u8; 32]> = (0..10_000).map(|_| *RandomIds.fresh_claim().unwrap().expose()).collect();
        assert_eq!(claims.len(), 10_000);
    }
}
