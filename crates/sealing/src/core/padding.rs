//! Length-hiding padding.
//!
//! The relay sees how long a ciphertext is, so the plaintext is framed as
//! `u32 BE length || bytes || zeros` and padded to a bucket: at least 256
//! bytes, then the next power of two. "hunter2" and a 200-character note
//! produce envelopes of the same size.

use zeroize::Zeroizing;

use super::{MAX_PLAINTEXT_LEN, Plaintext, SealError};

const MIN_BUCKET: usize = 256;
const FRAME_LEN: usize = 4;

fn bucket_for(framed_len: usize) -> usize {
    framed_len.max(MIN_BUCKET).next_power_of_two()
}

pub fn pad(plaintext: &Plaintext) -> Zeroizing<Vec<u8>> {
    let bytes = plaintext.expose();
    let bucket = bucket_for(FRAME_LEN + bytes.len());
    let mut out = Zeroizing::new(Vec::with_capacity(bucket));
    // Plaintext::new caps the length far below u32::MAX.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out.resize(bucket, 0);
    out
}

pub fn unpad(padded: &[u8]) -> Result<Plaintext, SealError> {
    let (frame, rest) = padded.split_first_chunk::<FRAME_LEN>().ok_or(SealError::MalformedEnvelope)?;
    let len = u32::from_be_bytes(*frame) as usize;
    if len > rest.len() || len > MAX_PLAINTEXT_LEN || padded.len() != bucket_for(FRAME_LEN + len) {
        return Err(SealError::MalformedEnvelope);
    }
    Plaintext::new(rest[..len].to_vec()).map_err(|_| SealError::MalformedEnvelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plaintext(len: usize) -> Plaintext {
        Plaintext::new(vec![0xAB; len]).unwrap()
    }

    #[test]
    fn roundtrip_at_bucket_edges() {
        for len in [1usize, 100, 252, 253, 1000, 4096, MAX_PLAINTEXT_LEN] {
            let padded = pad(&plaintext(len));
            assert!(padded.len().is_power_of_two() && padded.len() >= MIN_BUCKET);
            assert_eq!(unpad(&padded).unwrap(), plaintext(len));
        }
    }

    #[test]
    fn short_secrets_share_a_bucket() {
        assert_eq!(pad(&plaintext(7)).len(), pad(&plaintext(200)).len());
        assert_eq!(pad(&plaintext(MAX_PLAINTEXT_LEN)).len(), 64 * 1024);
    }

    mod adversary {
        use super::*;

        #[test]
        fn lying_length_frames_are_rejected() {
            let mut padded = pad(&plaintext(3));
            for lie in [u32::MAX, 253, 0] {
                padded[..4].copy_from_slice(&lie.to_be_bytes());
                assert_eq!(unpad(&padded), Err(SealError::MalformedEnvelope), "length {lie}");
            }
        }

        #[test]
        fn non_canonical_bucket_is_rejected() {
            let mut padded = pad(&plaintext(3)).to_vec();
            padded.extend_from_slice(&[0; 256]);
            assert_eq!(unpad(&padded), Err(SealError::MalformedEnvelope));
            assert_eq!(unpad(&[0, 0]), Err(SealError::MalformedEnvelope));
        }
    }
}
