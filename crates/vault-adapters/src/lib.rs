//! Adapters for the Vault ports, on Cloudflare.
//!
//! * [`DurableKv`]: the Durable Object's synchronous key-value storage, each
//!   ledger step one `transactionSync`.
//! * [`R2Payloads`]: sealed payloads in the R2 bucket of the chunks, under
//!   the same kind of random names.
//! * [`DurableLink`]: the relay's way to its vault, one fetch per call, to
//!   the one Durable Object in the EU jurisdiction.
//! * [`WorkerClock`]: the vault's clock.
//!
//! All but the object key need the Workers runtime (wasm32).

/// The R2 key of an object: 32 lowercase hex digits, exactly as the chunk
/// store names chunks, since payloads and chunks share one bucket and one
/// garbage collector.
pub fn object_key(object: &custody::ObjectName) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut key = String::with_capacity(2 * custody::ObjectName::LEN);
    for byte in object.as_bytes() {
        key.push(char::from(HEX[usize::from(byte >> 4)]));
        key.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    key
}

/// The one vault: every deposit, request and chunk record lives in this
/// Durable Object, so each step of the ledger sees all of them.
pub const VAULT_NAME: &str = "vault";

/// Where the vault runs and keeps its records.
pub const JURISDICTION: &str = "eu";

#[cfg(target_arch = "wasm32")]
mod cloudflare;

#[cfg(target_arch = "wasm32")]
pub use cloudflare::{DurableKv, DurableLink, Placement, R2Payloads, WorkerClock};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_keys_are_named_like_chunk_keys() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xAB;
        bytes[15] = 0x01;
        assert_eq!(object_key(&custody::ObjectName::from_array(bytes)), "ab000000000000000000000000000001");
    }
}
