use custody::{CustodyError, DropId, IdSource};

/// 128-bit ids from the operating system CSPRNG; in a Worker,
/// `crypto.getRandomValues`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomIds;

impl IdSource for RandomIds {
    fn fresh(&self) -> Result<DropId, CustodyError> {
        let mut bytes = [0u8; DropId::LEN];
        getrandom::fill(&mut bytes).map_err(|_| CustodyError::RandomnessUnavailable)?;
        DropId::from_slice(&bytes)
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
}
