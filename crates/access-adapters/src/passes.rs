use access::{AccessError, AccountId, Budget, DevicePass, PASS_SECONDS, Passes, RegistrationRecord, UnixTime};
use core::fmt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const EXPIRY_LEN: usize = 8;
const NONCE_LEN: usize = 16;

/// Device passes: `expiry (i64, big endian) ‖ nonce 16 B ‖ HMAC-SHA256 tag`,
/// the tag over expiry, nonce, account and SHA-256 of the record, keyed by
/// a key derived from the relay secret ([`crate::OpaqueKeys::passes`]).
/// Nothing is stored: the relay recognises its own passes, and a new record
/// (the name changed hands) voids every pass of the old one.
#[derive(Clone)]
pub struct HmacPasses {
    key: Zeroizing<[u8; 32]>,
    now: UnixTime,
}

impl HmacPasses {
    /// `now` is the relay's clock, which dates new passes and expires old ones.
    pub fn new(key: [u8; 32], now: UnixTime) -> Self {
        Self { key: Zeroizing::new(key), now }
    }

    fn tag(&self, expiry: &[u8], nonce: &[u8], account: &AccountId, record: &RegistrationRecord) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.key).expect("HMAC takes any key length");
        mac.update(b"sigylo/v1/device-pass\0");
        mac.update(expiry);
        mac.update(nonce);
        mac.update(account.as_bytes());
        mac.update(&Sha256::digest(record.as_bytes()));
        mac
    }
}

impl fmt::Debug for HmacPasses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacPasses(redacted)")
    }
}

impl Passes for HmacPasses {
    fn issue(&self, account: &AccountId, record: &RegistrationRecord) -> Result<DevicePass, AccessError> {
        let expiry = (self.now.0 + i64::from(PASS_SECONDS)).to_be_bytes();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| AccessError::RandomnessUnavailable)?;
        let tag = self.tag(&expiry, &nonce, account, record).finalize().into_bytes();
        DevicePass::from_slice(&[expiry.as_slice(), &nonce, &tag].concat())
    }

    fn admits(&self, pass: &DevicePass, account: &AccountId, record: &RegistrationRecord) -> bool {
        let (expiry, rest) = pass.expose().split_at(EXPIRY_LEN);
        let (nonce, tag) = rest.split_at(NONCE_LEN);
        let expires = i64::from_be_bytes(expiry.try_into().expect("fixed layout"));
        let in_date = expires > self.now.0 && expires <= self.now.0 + i64::from(PASS_SECONDS);
        // Checked whatever the date, in constant time.
        let genuine = self.tag(expiry, nonce, account, record).verify_slice(tag).is_ok();
        in_date && genuine
    }
}

/// The 32-byte key under which a throttle counts an attempt: the account
/// itself for the shared login budget, and a separate hash of it for each
/// other budget, so that no two budgets ever share a count.
pub fn throttle_bucket(account: &AccountId, budget: &Budget) -> [u8; 32] {
    match budget {
        Budget::Login => *account.as_bytes(),
        Budget::Registration => Sha256::new()
            .chain_update(b"sigylo/v1/throttle/registration\0")
            .chain_update(account.as_bytes())
            .finalize()
            .into(),
        Budget::Device(pass) => Sha256::new()
            .chain_update(b"sigylo/v1/throttle/device\0")
            .chain_update(account.as_bytes())
            .chain_update(pass.expose())
            .finalize()
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(byte: u8) -> RegistrationRecord {
        RegistrationRecord::from_slice(&[byte; RegistrationRecord::LEN]).unwrap()
    }

    fn ada() -> AccountId {
        AccountId::from_array([1; 32])
    }

    fn passes_at(now: i64) -> HmacPasses {
        HmacPasses::new([9; 32], UnixTime(now))
    }

    #[test]
    fn a_pass_admits_its_account_until_it_expires() {
        let pass = passes_at(1_000).issue(&ada(), &record(1)).unwrap();
        assert!(passes_at(1_000).admits(&pass, &ada(), &record(1)));
        assert!(passes_at(1_000 + i64::from(PASS_SECONDS) - 1).admits(&pass, &ada(), &record(1)));
        assert!(!passes_at(1_000 + i64::from(PASS_SECONDS)).admits(&pass, &ada(), &record(1)));
    }

    #[test]
    fn every_pass_is_new() {
        let passes = passes_at(1_000);
        assert_ne!(passes.issue(&ada(), &record(1)).unwrap(), passes.issue(&ada(), &record(1)).unwrap());
    }

    #[test]
    fn budgets_never_share_a_bucket() {
        let pass = passes_at(1_000).issue(&ada(), &record(1)).unwrap();
        let other = passes_at(1_000).issue(&ada(), &record(1)).unwrap();
        let buckets = [
            throttle_bucket(&ada(), &Budget::Login),
            throttle_bucket(&ada(), &Budget::Registration),
            throttle_bucket(&ada(), &Budget::Device(pass.clone())),
            throttle_bucket(&ada(), &Budget::Device(other)),
            throttle_bucket(&AccountId::from_array([2; 32]), &Budget::Device(pass)),
        ];
        for (i, a) in buckets.iter().enumerate() {
            for b in &buckets[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // The shared login budget keeps the key it always had.
        assert_eq!(buckets[0], *ada().as_bytes());
    }

    mod adversary {
        use super::*;

        #[test]
        fn a_pass_admits_no_other_account_record_or_key() {
            let pass = passes_at(1_000).issue(&ada(), &record(1)).unwrap();
            assert!(!passes_at(1_000).admits(&pass, &AccountId::from_array([2; 32]), &record(1)));
            assert!(!passes_at(1_000).admits(&pass, &ada(), &record(2)));
            assert!(!HmacPasses::new([8; 32], UnixTime(1_000)).admits(&pass, &ada(), &record(1)));
        }

        #[test]
        fn every_flipped_bit_voids_a_pass() {
            let pass = passes_at(1_000).issue(&ada(), &record(1)).unwrap();
            for bit in 0..DevicePass::LEN * 8 {
                let mut bytes = *pass.expose();
                bytes[bit / 8] ^= 1 << (bit % 8);
                let flipped = DevicePass::from_array(bytes);
                assert!(!passes_at(1_000).admits(&flipped, &ada(), &record(1)), "bit {bit}");
            }
        }

        #[test]
        fn a_pass_dated_beyond_its_lifetime_is_refused_even_with_the_key() {
            // Only a relay that issued it far in the future could have made it.
            let pass = passes_at(10_000_000).issue(&ada(), &record(1)).unwrap();
            assert!(!passes_at(1_000).admits(&pass, &ada(), &record(1)));
        }

        #[test]
        fn debug_never_prints_the_key() {
            assert_eq!(format!("{:?}", passes_at(0)), "HmacPasses(redacted)");
        }
    }
}
