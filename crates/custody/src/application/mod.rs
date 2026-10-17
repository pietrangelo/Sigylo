//! Application ring: the vault port and the custodian use cases.

mod custodian;
mod ports;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use custodian::{Answer, Custodian};
pub use ports::{ChunkStore, IdSource, TokenDigest, Vault};
