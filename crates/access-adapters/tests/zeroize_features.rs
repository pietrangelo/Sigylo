//! Adversary: `XChaCha20Poly1305` keeps its own copy of the key, and wipes it
//! on drop only when `chacha20poly1305` is built with its `zeroize` feature.
//! Feature unification could hide a manifest that forgot it, so both the
//! property and this crate's declaration are checked.

use chacha20poly1305::XChaCha20Poly1305;

fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn the_cipher_wipes_its_copy_of_the_key_on_drop() {
    wipes_on_drop::<XChaCha20Poly1305>();
}

#[test]
fn the_manifest_asks_chacha20poly1305_for_zeroize() {
    let manifest = include_str!("../Cargo.toml");
    let declaration = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("chacha20poly1305 "))
        .expect("chacha20poly1305 is a dependency");
    assert!(declaration.contains(r#""zeroize""#), "chacha20poly1305 without zeroize: {declaration}");
}
