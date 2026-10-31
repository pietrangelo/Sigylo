use argon2::{Algorithm, Argon2, Block, Params, Version};
use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};
use zeroize::Zeroizing;

/// Argon2id cost of the password hardening: the same as a sealed passphrase.
pub const HARDENING_MEMORY_KIB: u32 = 64 * 1024;
pub const HARDENING_PASSES: u32 = 3;
pub const HARDENING_LANES: u32 = 1;

/// The OPAQUE suite of Sigylo v1.
#[derive(Debug, Clone, Copy)]
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Hardening;
}

/// Argon2id v1.3 over the OPRF output, on the device. It makes every guess
/// cost 64 MiB and three passes even to someone who stole the relay's whole
/// state. The salt is fixed, as RFC 9807 prescribes: the input is already
/// unique per account and password.
#[derive(Debug, Clone, Copy, Default)]
pub struct Hardening;

impl Ksf for Hardening {
    fn hash<L: ArrayLength<u8>>(&self, input: GenericArray<u8, L>) -> Result<GenericArray<u8, L>, InternalError> {
        let params = Params::new(HARDENING_MEMORY_KIB, HARDENING_PASSES, HARDENING_LANES, Some(L::USIZE))
            .map_err(|_| InternalError::KsfError)?;
        let mut memory = wiped_blocks(&params).ok_or(InternalError::KsfError)?;
        let mut output = GenericArray::default();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(&input, &[0; 16], &mut output, memory.as_mut_slice())
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

/// The Argon2id working memory, allocated here rather than inside `argon2`:
/// its own buffer is freed without being wiped, and in Wasm `dlmalloc` never
/// gives memory back, so the blocks (a key-equivalent of the hardened
/// password) would stay readable. `Zeroizing` wipes every block on drop. The
/// allocation is fallible: a device without the memory gets a KSF error, it
/// does not abort.
fn wiped_blocks(params: &Params) -> Option<Zeroizing<Vec<Block>>> {
    let count = params.block_count();
    let mut blocks = Vec::new();
    blocks.try_reserve_exact(count).ok()?;
    blocks.resize(count, Block::default());
    Some(Zeroizing::new(blocks))
}
