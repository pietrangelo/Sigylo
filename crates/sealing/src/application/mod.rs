//! Application ring: the ports the domain needs and the use cases built on them.

mod ports;
mod sealer;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use ports::{Aead, CryptoSuite, HybridKem, HybridSigner, KeyDerivation, PassphraseStretcher, Randomness};
pub use sealer::{NewRecipient, NewSender, Received, SealedFile, Sealer};
