//! Adversary: the OPAQUE key stretching function runs Argon2id over the OPRF
//! output, so its working memory is a key-equivalent of the password's
//! randomized form. In Wasm, `dlmalloc` never gives memory back, so whatever
//! is freed without being wiped stays readable for the life of the page. This
//! binary installs an allocator that inspects every freed block of 1 MiB or
//! more and asserts the 64 MiB of the hardening come back as zeros.

use access_adapters::Hardening;
use heap_probe::WipeProbe;
use opaque_ke::generic_array::GenericArray;
use opaque_ke::generic_array::typenum::U64;
use opaque_ke::ksf::Ksf;

#[global_allocator]
static PROBE: WipeProbe = WipeProbe::new(1 << 20);

// One test function: the probe's counters are global to the binary.
#[test]
fn the_hardening_frees_its_working_memory_wiped() {
    let input = GenericArray::<u8, U64>::from([0x42; 64]);
    PROBE.reset();

    let output = Hardening.hash(input).unwrap();
    assert_eq!(output.len(), 64);

    assert!(PROBE.inspected() >= 1, "the 64 MiB of Argon2id memory went back to the allocator");
    assert_eq!(PROBE.dirty_bytes(), 0, "Argon2id memory was freed without being wiped");
}
