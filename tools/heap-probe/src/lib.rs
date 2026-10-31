//! A global allocator for tests that checks secret working memory is wiped
//! before it goes back to the allocator.
//!
//! In Wasm, `dlmalloc` never returns memory to the host: whatever a freed
//! block held stays readable in linear memory. [`WipeProbe`] wraps the system
//! allocator and, every time a block of at least `threshold` bytes is freed,
//! counts how many of its bytes are not zero. A test installs it in its own
//! integration test binary, runs the code under test and asserts that the
//! probe inspected the block and found nothing left in it:
//!
//! ```text
//! #[global_allocator]
//! static PROBE: heap_probe::WipeProbe = heap_probe::WipeProbe::new(1 << 20);
//! ```
//!
//! `realloc` is left to the default `GlobalAlloc` implementation (allocate,
//! copy, free), so a large block abandoned by a reallocation is inspected too.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The system allocator, plus an inspection of every large block it frees.
#[derive(Debug)]
pub struct WipeProbe {
    threshold: usize,
    inspected: AtomicUsize,
    dirty_bytes: AtomicUsize,
}

impl WipeProbe {
    /// A probe that inspects every freed block of at least `threshold` bytes.
    pub const fn new(threshold: usize) -> Self {
        Self { threshold, inspected: AtomicUsize::new(0), dirty_bytes: AtomicUsize::new(0) }
    }

    /// Large blocks freed since the last [`reset`](Self::reset).
    pub fn inspected(&self) -> usize {
        self.inspected.load(Ordering::SeqCst)
    }

    /// Non-zero bytes found in those blocks.
    pub fn dirty_bytes(&self) -> usize {
        self.dirty_bytes.load(Ordering::SeqCst)
    }

    /// Start counting again from zero.
    pub fn reset(&self) {
        self.inspected.store(0, Ordering::SeqCst);
        self.dirty_bytes.store(0, Ordering::SeqCst);
    }
}

// SAFETY: every allocation and deallocation is forwarded unchanged to
// `System`; the probe only reads a block before handing it back.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for WipeProbe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which `System` shares.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= self.threshold {
            let mut dirty = 0;
            for i in 0..layout.size() {
                // SAFETY: `ptr` is a live block of `layout.size()` bytes until
                // the `System.dealloc` below. The read is volatile so that the
                // compiler assumes nothing about bytes never written.
                if unsafe { ptr.add(i).read_volatile() } != 0 {
                    dirty += 1;
                }
            }
            self.inspected.fetch_add(1, Ordering::SeqCst);
            self.dirty_bytes.fetch_add(dirty, Ordering::SeqCst);
        }
        // SAFETY: `ptr` was allocated by `System` (through `alloc` above) with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }
}
