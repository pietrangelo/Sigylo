//! Adversary: the Argon2id working memory is a key-equivalent of the stretched
//! passphrase (with one lane, its last block is the whole Argon2 state). In
//! Wasm, `dlmalloc` never gives memory back, so whatever is freed without
//! being wiped stays readable for the life of the page. This binary installs
//! an allocator that inspects every freed block of 1 MiB or more and asserts
//! the 64 MiB of a RECOMMENDED stretch come back as zeros.

use heap_probe::WipeProbe;
use sealing::{KdfCost, Passphrase, application::PassphraseStretcher, core::Salt};
use sealing_adapters::Argon2idStretcher;

#[global_allocator]
static PROBE: WipeProbe = WipeProbe::new(1 << 20);

// One test function: the probe's counters are global to the binary.
#[test]
fn a_recommended_stretch_frees_its_working_memory_wiped() {
    let passphrase = Passphrase::new(b"cavallo-corretto-batteria-graffetta".to_vec()).unwrap();
    let salt = Salt::from_array([7; Salt::LEN]);
    PROBE.reset();

    let key = Argon2idStretcher.stretch(&passphrase, &salt, &KdfCost::RECOMMENDED).unwrap();
    drop(key);

    assert!(PROBE.inspected() >= 1, "the 64 MiB of Argon2id memory went back to the allocator");
    assert_eq!(PROBE.dirty_bytes(), 0, "Argon2id memory was freed without being wiped");
}
