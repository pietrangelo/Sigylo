use core::cell::RefCell;

use custody::{CustodyError, ObjectName, SealedPayload, UnixTime};
use js_sys::{Array, Object, Reflect, Uint8Array};
use vault::{Clock, KeyValue, Link, PayloadStore};
use wasm_bindgen::prelude::*;
use worker::{Bucket, Env, Method, ObjectNamespace, Request, RequestInit, Stub};

use super::{JURISDICTION, VAULT_NAME, object_key};

#[wasm_bindgen]
extern "C" {
    /// `ctx.storage` of a SQLite-backed Durable Object.
    type SyncStorage;

    #[wasm_bindgen(method, getter)]
    fn kv(this: &SyncStorage) -> SyncKv;

    #[wasm_bindgen(method, catch, js_name = transactionSync)]
    fn transaction_sync(
        this: &SyncStorage,
        step: &mut dyn FnMut() -> Result<JsValue, JsValue>,
    ) -> Result<JsValue, JsValue>;

    /// `ctx.storage.kv`: synchronous, so a run of calls is one write.
    type SyncKv;

    #[wasm_bindgen(method, catch)]
    fn get(this: &SyncKv, key: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn put(this: &SyncKv, key: &str, value: &Uint8Array) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch)]
    fn delete(this: &SyncKv, key: &str) -> Result<bool, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn list(this: &SyncKv, options: &Object) -> Result<JsValue, JsValue>;
}

fn unavailable<E>(_: E) -> CustodyError {
    CustodyError::VaultUnavailable
}

/// The Durable Object's own storage, through its synchronous API.
#[derive(Debug)]
pub struct DurableKv {
    storage: SyncStorage,
    kv: SyncKv,
}

impl DurableKv {
    pub fn new(state: &worker::State) -> Self {
        let raw: JsValue = AsRef::<JsValue>::as_ref(state.storage().as_raw()).clone();
        let storage: SyncStorage = raw.unchecked_into();
        let kv = storage.kv();
        Self { storage, kv }
    }
}

impl core::fmt::Debug for SyncStorage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SyncStorage")
    }
}

impl core::fmt::Debug for SyncKv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SyncKv")
    }
}

impl KeyValue for DurableKv {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CustodyError> {
        let value = self.kv.get(key).map_err(unavailable)?;
        if value.is_undefined() {
            return Ok(None);
        }
        Ok(Some(Uint8Array::new(&value).to_vec()))
    }

    fn put(&self, key: &str, value: &[u8]) -> Result<(), CustodyError> {
        self.kv.put(key, &Uint8Array::from(value)).map_err(unavailable)
    }

    fn delete(&self, key: &str) -> Result<(), CustodyError> {
        self.kv.delete(key).map(drop).map_err(unavailable)
    }

    fn range(&self, start: &str, end: &str, limit: usize) -> Result<Vec<(String, Vec<u8>)>, CustodyError> {
        let options = Object::new();
        Reflect::set(&options, &"start".into(), &start.into()).map_err(unavailable)?;
        Reflect::set(&options, &"end".into(), &end.into()).map_err(unavailable)?;
        Reflect::set(&options, &"limit".into(), &(limit as f64).into()).map_err(unavailable)?;
        let listed = self.kv.list(&options).map_err(unavailable)?;
        let entries = js_sys::try_iter(&listed).map_err(unavailable)?.ok_or(CustodyError::VaultUnavailable)?;
        let mut out = Vec::new();
        for entry in entries {
            let pair: Array = entry.map_err(unavailable)?.unchecked_into();
            let key = pair.get(0).as_string().ok_or(CustodyError::VaultUnavailable)?;
            out.push((key, Uint8Array::new(&pair.get(1)).to_vec()));
        }
        Ok(out)
    }

    fn atomically<T>(&self, step: impl FnOnce() -> Result<T, CustodyError>) -> Result<T, CustodyError> {
        let mut step = Some(step);
        let outcome = RefCell::new(None);
        let mut run = || {
            let result = step.take().map(|step| step());
            let failed = !matches!(result, Some(Ok(_)));
            *outcome.borrow_mut() = result;
            // Throwing is how a transaction is rolled back.
            if failed { Err(JsValue::from_str("rolled back")) } else { Ok(JsValue::UNDEFINED) }
        };
        let committed = self.storage.transaction_sync(&mut run);
        match (outcome.into_inner(), committed) {
            (Some(Ok(value)), Ok(_)) => Ok(value),
            (Some(Err(error)), _) => Err(error),
            _ => Err(CustodyError::VaultUnavailable),
        }
    }
}

/// Payloads in the R2 bucket of the chunks.
#[derive(Debug)]
pub struct R2Payloads {
    bucket: Bucket,
}

impl R2Payloads {
    pub fn new(bucket: Bucket) -> Self {
        Self { bucket }
    }
}

impl PayloadStore for R2Payloads {
    async fn put(&self, object: &ObjectName, payload: &SealedPayload) -> Result<(), CustodyError> {
        self.bucket.put(object_key(object), payload.as_bytes().to_vec()).execute().await.map_err(unavailable)?;
        Ok(())
    }

    async fn get(&self, object: &ObjectName) -> Result<Option<SealedPayload>, CustodyError> {
        let Some(found) = self.bucket.get(object_key(object)).execute().await.map_err(unavailable)? else {
            return Ok(None);
        };
        let Some(body) = found.body() else { return Ok(None) };
        let bytes = body.bytes().await.map_err(unavailable)?;
        SealedPayload::new(bytes).map(Some).map_err(unavailable)
    }

    async fn delete(&self, objects: &[ObjectName]) -> Result<(), CustodyError> {
        for batch in objects.chunks(1000) {
            let keys: Vec<String> = batch.iter().map(object_key).collect();
            self.bucket.delete_multiple(keys).await.map_err(unavailable)?;
        }
        Ok(())
    }
}

/// The relay's line to the vault: the Durable Object named [`VAULT_NAME`]
/// in the [`JURISDICTION`], so its records never leave the EU.
#[derive(Debug)]
pub struct DurableLink {
    stub: Stub,
}

/// Where the vault lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// In the [`JURISDICTION`]: always, on Cloudflare.
    Jurisdiction,
    /// Anywhere: only for the local runtime (`wrangler dev`, workerd), which
    /// does not implement jurisdictions.
    Local,
}

impl DurableLink {
    pub fn new(env: &Env, binding: &str, placement: Placement) -> worker::Result<Self> {
        let namespace = env.durable_object(binding)?;
        let stub = match placement {
            Placement::Jurisdiction => {
                let jurisdiction = Reflect::get(namespace.as_ref(), &"jurisdiction".into())?;
                let restricted = jurisdiction
                    .unchecked_into::<js_sys::Function>()
                    .call1(namespace.as_ref(), &JURISDICTION.into())?;
                restricted.unchecked_into::<ObjectNamespace>().get_by_name(VAULT_NAME)?
            }
            Placement::Local => namespace.get_by_name(VAULT_NAME)?,
        };
        Ok(Self { stub })
    }
}

impl Link for DurableLink {
    async fn call(&self, call: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        let mut init = RequestInit::new();
        init.with_method(Method::Post).with_body(Some(Uint8Array::from(call.as_slice()).into()));
        // The host means nothing: a stub's fetch never leaves Cloudflare.
        let request = Request::new_with_init("https://vault/call", &init).map_err(unavailable)?;
        let mut response = self.stub.fetch_with_request(request).await.map_err(unavailable)?;
        if response.status_code() != 200 {
            return Err(CustodyError::VaultUnavailable);
        }
        response.bytes().await.map_err(unavailable)
    }
}

/// The Workers runtime's clock (frozen within one request, as Cloudflare
/// keeps it, which is all the vault needs).
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerClock;

impl Clock for WorkerClock {
    fn now(&self) -> UnixTime {
        UnixTime((worker::Date::now().as_millis() / 1000) as i64)
    }
}
