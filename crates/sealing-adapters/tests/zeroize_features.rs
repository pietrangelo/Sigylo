//! Adversary: RustCrypto types wipe their state on drop only when their crate
//! is built with its `zeroize` feature, and feature unification could hide a
//! manifest that forgot it, so both the property and this crate's
//! declarations are checked.
//!
//! * `XChaCha20Poly1305` keeps its own copy of the key.
//! * A hash or XOF state holds what it absorbed and, once finalized, what it
//!   squeezed out: the X25519 and ML-KEM secrets expanded from a recipient
//!   seed (SHAKE256 in `sha3`), the combined shared secret (SHA3-256), the
//!   HKDF pseudorandom key (HMAC over SHA3-256), the ML-DSA secrets expanded
//!   from a sender seed (SHAKE256 in `shake`), the Ed25519 expanded secret key
//!   (SHA-512 in `sha2`) and Argon2id's initial hash H0 (BLAKE2b in `blake2`),
//!   from which the stretched key follows without the passphrase.

use chacha20poly1305::XChaCha20Poly1305;

fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn the_cipher_wipes_its_copy_of_the_key_on_drop() {
    wipes_on_drop::<XChaCha20Poly1305>();
}

#[test]
fn hash_and_xof_states_wipe_what_they_hold_on_drop() {
    use sha3::digest::consts::{U0, U136};

    wipes_on_drop::<sha3::Sha3_256>();
    wipes_on_drop::<shake::Shake256>();
    wipes_on_drop::<sha2::Sha512>();
    // `sha3::Shake256`, its reader and `blake2::Blake2b512` do not carry the
    // marker themselves; their block buffers wipe on drop with `digest`'s
    // `zeroize`, and their cores, checked here, wipe the state.
    const SHAKE_PAD: u8 = 0x1f;
    wipes_on_drop::<sha3::block_api::Sha3HasherCore<U136, U0, SHAKE_PAD>>();
    wipes_on_drop::<sha3::block_api::Sha3ReaderCore<U136>>();
    wipes_on_drop::<blake2::Blake2bVarCore>();
}

#[test]
fn the_manifest_asks_every_primitive_for_zeroize() {
    let manifest = include_str!("../Cargo.toml");
    for name in [
        "chacha20poly1305",
        "ml-kem",
        "ml-dsa",
        "x25519-dalek",
        "ed25519-dalek",
        "argon2",
        "sha3",
        "sha2",
        "shake",
        "blake2",
    ] {
        let declaration = manifest
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{name} ")))
            .unwrap_or_else(|| panic!("{name} is a dependency"));
        assert!(declaration.contains(r#""zeroize""#), "{name} without zeroize: {declaration}");
    }
}
