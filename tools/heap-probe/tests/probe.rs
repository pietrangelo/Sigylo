//! The probe must catch a large block freed with data in it, and pass one
//! wiped before it is freed; otherwise a wipe test proves nothing.

use heap_probe::WipeProbe;
use zeroize::Zeroizing;

#[global_allocator]
static PROBE: WipeProbe = WipeProbe::new(1 << 20);

const BIG: usize = 2 << 20;

// One test function: the counters are global, and the harness runs tests in parallel.
#[test]
fn the_probe_counts_what_a_freed_block_still_holds() {
    PROBE.reset();
    drop(vec![0xA5u8; BIG]);
    assert_eq!(PROBE.inspected(), 1, "a 2 MiB block was freed");
    assert_eq!(PROBE.dirty_bytes(), BIG, "every byte was left behind");

    PROBE.reset();
    drop(Zeroizing::new(vec![0xA5u8; BIG]));
    assert_eq!(PROBE.inspected(), 1);
    assert_eq!(PROBE.dirty_bytes(), 0, "Zeroizing wipes before freeing");

    PROBE.reset();
    let mut grown = vec![0x5Au8; BIG];
    grown.reserve_exact(BIG);
    assert_eq!(PROBE.dirty_bytes(), BIG, "a reallocation leaves the old block behind");
    drop(Zeroizing::new(grown));

    PROBE.reset();
    drop(vec![0xA5u8; 1024]);
    assert_eq!(PROBE.inspected(), 0, "small blocks are not inspected");

    // A large block freed before it was written holds nothing of its own, and
    // the probe must not read whatever the allocator left in it: a dirty block
    // is freed first, so a fresh one of the same size is likely to reuse it.
    drop(vec![0xA5u8; BIG]);
    PROBE.reset();
    drop(Vec::<u8>::with_capacity(BIG));
    assert_eq!(PROBE.inspected(), 1);
    assert_eq!(PROBE.dirty_bytes(), 0, "a block never written was never dirty");

    // The same for the unwritten tail of a small block that grows into a
    // large one: `realloc` copies all of it, written or not.
    const SMALL: usize = 64 << 10;
    drop(vec![0xA5u8; SMALL]);
    let mut grown = Vec::<u8>::with_capacity(SMALL);
    grown.push(0);
    PROBE.reset();
    grown.reserve_exact(BIG);
    drop(grown);
    assert_eq!(PROBE.inspected(), 1);
    assert_eq!(PROBE.dirty_bytes(), 0, "a small block's unwritten tail was never dirty");
}
