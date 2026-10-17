use access::AccessError;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use zeroize::Zeroizing;

/// A ChaCha20 CSPRNG seeded from the operating system (in a browser or a
/// Worker, `crypto.getRandomValues`). opaque-ke's RNG interface cannot
/// report failure, so the one fallible step happens here, up front.
pub fn fresh() -> Result<ChaCha20Rng, AccessError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| AccessError::RandomnessUnavailable)?;
    Ok(ChaCha20Rng::from_seed(*seed))
}
