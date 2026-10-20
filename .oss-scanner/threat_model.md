# Threat model: Sigylo

## What this project does and where untrusted input enters

Sigylo shares secrets (credentials, keys, files up to 10 MiB) end to end encrypted. The sender seals the
secret in the browser (Rust compiled to Wasm), a Cloudflare Worker relay stores only opaque envelopes, and
the recipient opens it once (burn after reading) or until it expires. The live service is https://sigylo.net.
CLAUDE.md is the full specification; SECURITY.md is the disclosure policy.

Treat all of the following as attacker-controlled:

- **Everything the relay receives** (`worker/src/api.rs`): every route under `/api/` (secrets, chunks,
  requests, account), JSON bodies, base64url fields, raw chunk bodies, `Content-Length`, `Origin`,
  `Authorization`, `CF-Connecting-IP`, path ids and chunk indexes, and the order and concurrency of calls.
- **Everything the client receives from the relay**: a hostile relay must not learn or change a secret.
  Envelopes, file manifests and chunks (`crates/sealing/src/core/{envelope,file,signed}.rs`), recipient
  public keys and their fingerprints, Argon2id costs inside an envelope, account keyrings, OPAQUE messages,
  and every HTTP status the client acts on (`web/src/lib/*.ts`).
- **Links**: the URL fragment (`#/…`) the web client and the desktop app parse, including file names inside
  sealed manifests (path separators, bidi/invisible characters, Windows reserved names).
- **The storage layer**: the Durable Object vault (`crates/vault`, records in `core/records.rs`), the
  PostgreSQL functions in `supabase/migrations/` (called only via `SECURITY DEFINER` functions by the
  `sigylo_relay` role), and R2 objects. A stolen relay database credential must not read secrets or mint
  sessions.
- **The desktop app's IPC** (`app/src/relay.rs`, `navigation.rs`): a compromised page must not reach any
  host other than `https://sigylo.net/api` or call routes outside the allow-list.

Security goals: the relay never sees a key or plaintext; burn-after-reading delivers at most once even under
concurrent opens; missing, expired, burned and revoked look identical (404); wrong key, wrong passphrase,
wrong recipient, bad signature and tampering are all `NotAuthentic`; ids are chosen by the relay, never by
the client; secrets in memory are zeroized and `Debug` never prints them; per-address rate limits and global
storage ceilings hold; OPAQUE login leaks nothing about the password and unknown user equals wrong password.

## Components that matter most / least

- Most: `crates/sealing` (envelope format, hybrid X25519+ML-KEM-768 KEM, Ed25519+ML-DSA-65 signatures,
  XChaCha20-Poly1305, HKDF-SHA3-256, Argon2id, chunked files), `crates/sealing-adapters`,
  `crates/sigylo-wasm` (secret handoff to JS, stack scrubbing), `crates/custody`, `crates/vault`,
  `crates/vault-adapters`, `worker/src`, `crates/access` + `crates/access-adapters` (OPAQUE, sessions,
  throttle, device passes), `supabase/migrations`, `app/src`.
- Also in scope: `web/src` (Svelte client: link parsing, file download handling, keyring rollback check),
  `web/public/_headers` (CSP) and `web/vite-plugin-*.ts` (SRI, app CSP).
- Least: `tools/architecture-guard` (CI-only static check), `scripts/`, `docs/`, the golden-ratio styling.

## How to exercise it

Everything is built in the image; cargo and npm run offline.

- `cargo test --workspace --locked`: domains, adapters, the relay API, `adversary` test groups (bit flips,
  truncation, key substitution, hostile parameters, races) and `format_pin` byte pins.
- `bash supabase/tests/run.sh`: migrations, privileges and the vault contract on a throwaway PostgreSQL.
- `cd web && npm test`: unit tests, including `engine-memory.test.ts`, which scans Wasm memory for leftovers.
- `bash scripts/e2e.sh`: the real Worker under `wrangler dev` (workerd) at 127.0.0.1:8787 with PostgreSQL
  and local R2, driven by Chromium. While it runs you can call the API with curl to try attacks end to end.
- `cd app && cargo test`: the desktop shell's relay allow-list and navigation rules.

## How you rate severity

- Critical: the relay, a network attacker or another user reads a plaintext secret or a key; a forged or
  substituted envelope or signature that opens as authentic; reading or replacing a burn-after-reading
  secret a second time; login without the password or into another account; remote code execution in the
  Worker, the page or the app.
- High: delivering a secret after expiry or revocation, or to someone without the link; destroying, burning
  or revoking someone else's secret without their link or revocation token; telling apart wrong key vs
  tampering vs missing; a secret left un-zeroized in Wasm memory or printed by `Debug`; offline password
  guessing against OPAQUE records; bypassing CSP/SRI or the app's IPC allow-list; reaching another host from
  the app.
- Medium: bypassing a rate limit or a storage ceiling so that one actor can fill the service for everyone;
  metadata leaks (linking two answers of the same sender, revealing whether a username exists outside the
  documented `409` on registration); crashes or panics on hostile input in the relay.
- Low: denial of service needing many distinct addresses, or only affecting the attacker's own data.

## Anything to leave alone

Known, documented limits (CLAUDE.md, "Known limit"; do not report them unless you break them further):
whoever controls the hosting can serve a different `index.html` (SRI covers sub-resources only); JS strings
and `Uint8Array`s may persist in GC copies; malware or XSS in the sender's browser can read the signing
seed from `localStorage`; without an expected sender, whoever has the request link can answer first (it is
detected by the sender code); registration reveals that a username is taken (`409`); OPAQUE/3DH are not
post-quantum; a device that never saw an account cannot detect a rolled-back keyring. `VAULT_PLACEMENT=local`
and `DB_TLS=disable` are local-only settings that the deploy refuses. Do not test against sigylo.net:
everything runs locally.
