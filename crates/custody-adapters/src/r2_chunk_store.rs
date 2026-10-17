//! The chunk store on Cloudflare R2, through the Worker's bucket binding.
//!
//! Each sealed chunk is one object named by the hex of its random
//! [`ObjectName`]: the bucket holds opaque ciphertext under names that say
//! nothing of the deposit, the index or the file.

use custody::ObjectName;

/// The R2 key of an object: 32 lowercase hex digits.
pub fn object_key(object: &ObjectName) -> String {
    object.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(target_arch = "wasm32")]
mod bucket {
    use custody::{ChunkStore, CustodyError, ObjectName, SealedChunk};
    use worker::Bucket;

    use super::object_key;

    /// Chunks in an R2 bucket.
    #[derive(Debug)]
    pub struct R2ChunkStore {
        bucket: Bucket,
    }

    impl R2ChunkStore {
        pub fn new(bucket: Bucket) -> Self {
            Self { bucket }
        }
    }

    fn unavailable<E>(_: E) -> CustodyError {
        CustodyError::VaultUnavailable
    }

    impl ChunkStore for R2ChunkStore {
        async fn put(&self, object: &ObjectName, chunk: &SealedChunk) -> Result<(), CustodyError> {
            self.bucket.put(object_key(object), chunk.as_bytes().to_vec()).execute().await.map_err(unavailable)?;
            Ok(())
        }

        async fn get(&self, object: &ObjectName) -> Result<Option<SealedChunk>, CustodyError> {
            let Some(found) = self.bucket.get(object_key(object)).execute().await.map_err(unavailable)? else {
                return Ok(None);
            };
            let Some(body) = found.body() else { return Ok(None) };
            let bytes = body.bytes().await.map_err(unavailable)?;
            SealedChunk::new(bytes).map(Some).map_err(unavailable)
        }

        async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
            // One call takes up to 1000 keys, as many as one garbage batch.
            for batch in objects.chunks(1000) {
                let keys: Vec<String> = batch.iter().map(object_key).collect();
                self.bucket.delete_multiple(keys).await.map_err(unavailable)?;
            }
            Ok(())
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use bucket::R2ChunkStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_the_hex_of_the_random_name_and_nothing_else() {
        let mut bytes = [0u8; ObjectName::LEN];
        bytes[0] = 0xAB;
        bytes[15] = 0x01;
        let key = object_key(&ObjectName::from_array(bytes));
        assert_eq!(key, "ab000000000000000000000000000001");
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn distinct_names_never_share_a_key() {
        let a = object_key(&ObjectName::from_array([0x10; ObjectName::LEN]));
        let b = object_key(&ObjectName::from_array([0x01; ObjectName::LEN]));
        assert_ne!(a, b);
        assert_eq!((a.len(), b.len()), (32, 32));
    }
}
