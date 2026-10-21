//! Ports of the Vault context.

use access::{AccessError, AccountId, AccountStore};
use custody::{CustodyError, ObjectName, SealedPayload, UnixTime};

use crate::core::Class;

/// An ordered key-value store whose calls are synchronous: a Durable
/// Object's storage, where a run of calls with no `await` between them
/// commits as one.
pub trait KeyValue {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CustodyError>;

    fn put(&self, key: &str, value: &[u8]) -> Result<(), CustodyError>;

    fn delete(&self, key: &str) -> Result<(), CustodyError>;

    /// Up to `limit` entries with `start <= key < end`, in key order.
    fn range(&self, start: &str, end: &str, limit: usize) -> Result<Vec<(String, Vec<u8>)>, CustodyError>;

    /// Runs `step` as one transaction: if it fails, none of its writes stay.
    fn atomically<T>(&self, step: impl FnOnce() -> Result<T, CustodyError>) -> Result<T, CustodyError>;
}

/// Where sealed payloads live, apart from the records (Cloudflare R2, the
/// bucket of the chunks): there a deletion is final, while a Durable Object
/// keeps 30 days of history for point-in-time recovery.
#[allow(async_fn_in_trait)]
pub trait PayloadStore {
    async fn put(&self, object: &ObjectName, payload: &SealedPayload) -> Result<(), CustodyError>;

    async fn get(&self, object: &ObjectName) -> Result<Option<SealedPayload>, CustodyError>;

    /// Deletes the objects; deleting one that is not there is no error.
    async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError>;
}

/// The vault's own clock, authoritative for every expiry.
pub trait Clock {
    fn now(&self) -> UnixTime;
}

/// How the relay reaches the vault: one encoded [`crate::Call`] in, one
/// encoded [`crate::Reply`] out (a fetch to the Durable Object).
#[allow(async_fn_in_trait)]
pub trait Link {
    async fn call(&self, call: Vec<u8>) -> Result<Vec<u8>, CustodyError>;
}

/// The accounts object as the relay reaches it: the Access store, and the
/// attempt counters it keeps in memory, so the throttle counts once for the
/// whole world. Only an attempt's bucket reaches the object, never a pass.
#[allow(async_fn_in_trait)]
pub trait Accounts: AccountStore {
    /// Counts an attempt on `class`'s budget, filed under `bucket`, and says
    /// whether it is within `limit` (1 to [`crate::core::ATTEMPT_LIMIT_CEILING`])
    /// for the current window. An error is never an admission.
    async fn admit(
        &self,
        account: &AccountId,
        bucket: &[u8; 32],
        class: Class,
        limit: u16,
    ) -> Result<bool, AccessError>;
}

impl<K: KeyValue> KeyValue for &K {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CustodyError> {
        (**self).get(key)
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), CustodyError> {
        (**self).put(key, value)
    }

    fn delete(&self, key: &str) -> Result<(), CustodyError> {
        (**self).delete(key)
    }

    fn range(&self, start: &str, end: &str, limit: usize) -> Result<Vec<(String, Vec<u8>)>, CustodyError> {
        (**self).range(start, end, limit)
    }

    fn atomically<T>(&self, step: impl FnOnce() -> Result<T, CustodyError>) -> Result<T, CustodyError> {
        (**self).atomically(step)
    }
}

impl<P: PayloadStore> PayloadStore for &P {
    async fn put(&self, object: &ObjectName, payload: &SealedPayload) -> Result<(), CustodyError> {
        (**self).put(object, payload).await
    }

    async fn get(&self, object: &ObjectName) -> Result<Option<SealedPayload>, CustodyError> {
        (**self).get(object).await
    }

    async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        (**self).delete(objects).await
    }
}

impl<C: Clock> Clock for &C {
    fn now(&self) -> UnixTime {
        (**self).now()
    }
}

impl<L: Link> Link for &L {
    async fn call(&self, call: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        (**self).call(call).await
    }
}

impl<A: Accounts> Accounts for &A {
    async fn admit(
        &self,
        account: &AccountId,
        bucket: &[u8; 32],
        class: Class,
        limit: u16,
    ) -> Result<bool, AccessError> {
        (**self).admit(account, bucket, class, limit).await
    }
}
