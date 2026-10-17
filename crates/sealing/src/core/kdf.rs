//! Argon2id parameters for passphrase stretching.

use core::ops::RangeInclusive;

use super::SealError;

/// Argon2id costs. The accepted range is enforced on construction, so an
/// envelope written by a hostile relay cannot make a browser allocate
/// gigabytes, nor talk it into a uselessly cheap setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl KdfCost {
    /// Cost used when sealing: 64 MiB, 3 passes, 1 lane.
    pub const RECOMMENDED: Self = Self { memory_kib: 64 * 1024, iterations: 3, lanes: 1 };
    /// The cheapest accepted cost (OWASP floor: 19 MiB, 2 passes).
    pub const MINIMUM: Self = Self { memory_kib: 19 * 1024, iterations: 2, lanes: 1 };

    const MEMORY_KIB: RangeInclusive<u32> = (19 * 1024)..=(256 * 1024);
    const ITERATIONS: RangeInclusive<u32> = 2..=10;
    const LANES: RangeInclusive<u32> = 1..=4;

    pub fn new(memory_kib: u32, iterations: u32, lanes: u32) -> Result<Self, SealError> {
        if Self::MEMORY_KIB.contains(&memory_kib)
            && Self::ITERATIONS.contains(&iterations)
            && Self::LANES.contains(&lanes)
        {
            Ok(Self { memory_kib, iterations, lanes })
        } else {
            Err(SealError::KdfCostOutOfRange)
        }
    }

    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn lanes(&self) -> u32 {
        self.lanes
    }
}

/// A 128-bit random salt for Argon2id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Salt([u8; Salt::LEN]);

impl Salt {
    pub const LEN: usize = 16;

    pub fn from_array(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_inside_the_accepted_range() {
        for preset in [KdfCost::RECOMMENDED, KdfCost::MINIMUM] {
            assert_eq!(KdfCost::new(preset.memory_kib, preset.iterations, preset.lanes), Ok(preset));
        }
    }

    mod adversary {
        use super::*;

        #[test]
        fn hostile_costs_are_rejected() {
            for (m, t, p) in [
                (4 * 1024 * 1024, 3, 1), // 4 GiB: memory exhaustion
                (1024, 3, 1),            // 1 MiB: too cheap
                (64 * 1024, 1, 1),       // single pass
                (64 * 1024, 1_000, 1),   // CPU exhaustion
                (64 * 1024, 3, 0),
                (64 * 1024, 3, 64),
            ] {
                assert_eq!(KdfCost::new(m, t, p), Err(SealError::KdfCostOutOfRange), "{m} {t} {p}");
            }
        }
    }
}
