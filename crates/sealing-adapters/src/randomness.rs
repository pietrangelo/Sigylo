use sealing::{SealError, application::Randomness};

/// The operating system CSPRNG; in the browser, `crypto.getRandomValues`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRandomness;

impl Randomness for SystemRandomness {
    fn fill(&self, buf: &mut [u8]) -> Result<(), SealError> {
        getrandom::fill(buf).map_err(|_| SealError::RandomnessUnavailable)
    }
}
