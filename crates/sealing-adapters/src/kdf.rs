use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use sealing::{
    KdfCost, Passphrase, SealError, SymmetricKey,
    application::{KeyDerivation, PassphraseStretcher},
    core::Salt,
};
use sha3::Sha3_256;
use zeroize::Zeroizing;

/// Argon2id (RFC 9106), version 1.3.
#[derive(Debug, Clone, Copy, Default)]
pub struct Argon2idStretcher;

impl PassphraseStretcher for Argon2idStretcher {
    fn stretch(&self, passphrase: &Passphrase, salt: &Salt, cost: &KdfCost) -> Result<SymmetricKey, SealError> {
        let params = Params::new(cost.memory_kib(), cost.iterations(), cost.lanes(), Some(32))
            .map_err(|_| SealError::KdfCostOutOfRange)?;
        let mut memory = wiped_blocks(&params).ok_or(SealError::KdfCostOutOfRange)?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(passphrase.expose(), salt.as_bytes(), &mut *out, memory.as_mut_slice())
            .map_err(|_| SealError::KdfCostOutOfRange)?;
        Ok(SymmetricKey::from_array(*out))
    }
}

/// The Argon2id working memory, allocated here rather than inside `argon2`:
/// its own buffer is freed without being wiped, and in Wasm `dlmalloc` never
/// gives memory back, so the blocks (a key-equivalent of the stretched
/// secret) would stay readable. `Zeroizing` wipes every block on drop. The
/// allocation is fallible: a cost the device cannot afford is refused, it does
/// not abort.
fn wiped_blocks(params: &Params) -> Option<Zeroizing<Vec<Block>>> {
    let count = params.block_count();
    let mut blocks = Vec::new();
    blocks.try_reserve_exact(count).ok()?;
    blocks.resize(count, Block::default());
    Some(Zeroizing::new(blocks))
}

/// HKDF (RFC 5869) instantiated with SHA3-256.
#[derive(Debug, Clone, Copy, Default)]
pub struct HkdfSha3;

impl KeyDerivation for HkdfSha3 {
    fn derive(&self, salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> SymmetricKey {
        let mut out = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha3_256>::new(Some(salt), ikm)
            .expand_multi_info(info, &mut *out)
            .expect("32 bytes is a valid HKDF-SHA3-256 output length");
        SymmetricKey::from_array(*out)
    }
}
