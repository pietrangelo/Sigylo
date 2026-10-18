//! Application ring: the ports and the use cases of both sides, the relay's
//! [`Gatekeeper`] and the device's [`Member`].

mod gatekeeper;
mod member;
mod ports;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use gatekeeper::{Gatekeeper, LoginChallenge};
pub use member::{Member, PendingLogin, PendingRegistration};
pub use ports::{
    AccountStore, KeyringKdf, KeyringWrite, OpaqueClient, OpaqueServer, Passes, SessionDigester, Throttle, Tokens,
};
