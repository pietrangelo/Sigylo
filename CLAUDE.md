# Sigylo

## MISSIONE
Condividere dati segreti (credenziali, chiavi, codici) nel modo più sicuro possibile e più semplice possibile. Il mittente sigilla il segreto nel browser, il server custodisce solo dati illeggibili, il destinatario apre il sigillo una volta (oppure fino alla scadenza scelta) e poi il segreto sparisce.

- **Nome:** Sigylo, da *sigillo / sigillum*: il timbro che per secoli ha garantito che una lettera non fosse stata aperta prima dell'arrivo. Verifiche su marchi (TMview, WIPO, classi di Nizza 9 e 42), domini e handle ancora da fare.
- **Lingue:** italiano e inglese fin dal primo commit (`web/src/lib/i18n.ts`), lingua scelta dal browser.
- **Principio guida:** semplicità prima di tutto. Un campo, due scelte (quando distruggerlo, quando scade), un pulsante. La sicurezza non deve chiedere nulla all'utente.

---

## 0. METODO DI SVILUPPO (stesso di ModusNote, su Rust)

* **TDD:** prima il test, poi il codice. Ogni PR dice quanti test aggiunge e cosa coprono.
* **Rosetta:** ogni bounded context è un crate di dominio puro con due anelli, `core` (value object immutabili, deterministici: niente I/O, orologio o casualità) dentro `application` (use case e port). Tutto ciò che tocca il mondo vive in crate `<contesto>-adapters` separati; i **shell** (Wasm, Worker, web) collegano soltanto.
* **DDD:** linguaggio ubiquo (sigillare, aprire, custodire, bruciare, revocare, richiesta), value object che si validano alla costruzione, errori del dominio come enum.
* **Adversary:** ogni contesto ha gruppi di test `adversary` che attaccano il codice: bit flip, troncamenti, sostituzione di chiavi, parametri ostili, corse concorrenti, `Debug` che non deve mai stampare segreti.
* **Guardiano dell'architettura:** `tools/architecture-guard` fa fallire la CI se:
  - un membro del workspace non dichiara `[package.metadata.rosette] role` (`domain`, `adapters`, `shell`, `tool`);
  - un dominio dipende da qualcosa che non sia `zeroize` o un altro dominio (anche se il nome è camuffato con `package = "…"`, pure in `[workspace.dependencies]`), ha dipendenze per target, di build o un `build.rs`;
  - un crate `-adapters` dipende da un altro `-adapters` o da uno shell;
  - il `lib.rs` di un dominio non ha `#![forbid(unsafe_code)]` o dichiara moduli diversi da `core` e `application`;
  - `core` raggiunge `application` (anche via `super::super`, o dentro una macro), o un anello raggiunge item della radice del crate;
  - un dominio usa `std::{fs, net, io, process, env, thread, time, os, path}`, rinomina o importa con glob `std`, usa `include!`/`include_str!`/`include_bytes!`/`env!`/`option_env!` o `#[path]` (anche dentro `cfg_attr`);
  - un file non si analizza (fail closed).

## 1. STRUTTURA DEL REPOSITORY E COMANDI

```text
crates/sealing/            Dominio puro "Sealing": buste, schedule delle chiavi, port crittografici
crates/sealing-adapters/   RustCrypto: X25519 + ML-KEM-768, XChaCha20-Poly1305, Argon2id, HKDF-SHA3-256, CSPRNG
crates/custody/            Dominio puro "Custody": custodia cieca, burn-after-reading, scadenza, revoca, richieste
crates/custody-adapters/   PostgresVault (tokio-postgres, anche via Hyperdrive), digest SHA-256 dei token
crates/sigylo-wasm/        Shell browser: Sealing + RustCrypto esposti a JavaScript (wasm-bindgen)
worker/                    Shell Cloudflare Worker (workers-rs): relay cieco HTTP → Custody → PostgreSQL
web/                       Client Svelte 5 + TypeScript strict, solo dipendenze di sviluppo, nessuna a runtime
supabase/migrations/       Schema SQL e funzioni atomiche della custodia
supabase/tests/            Test dei privilegi SQL + test di contratto del vault su un PostgreSQL usa e getta
tools/architecture-guard/  Verifica statica della rosetta
scripts/e2e.sh             End-to-end: Worker reale (workerd) + PostgreSQL + Chromium
```

Comandi (dalla radice):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p sigylo-relay --target wasm32-unknown-unknown -- -D warnings
cargo run -p architecture-guard                      # la rosetta è intatta?
cargo test --workspace                               # domini, adapter, guardiano, API del relay
bash supabase/tests/run.sh                           # migrazioni + privilegi + contratto del vault su PostgreSQL reale
(cd web && npm ci && npm run build && npm run check && npm test)
bash scripts/e2e.sh                                  # tutto lo stack nel browser
```

Strumenti: Rust stabile con target `wasm32-unknown-unknown`, `wasm-bindgen-cli` alla versione esatta fissata in `crates/sigylo-wasm/Cargo.toml` (oggi 0.2.129), `worker-build` 0.8.7, Node 22, PostgreSQL 15+ (binari `initdb`/`pg_ctl` per i test).

## 2. CRITTOGRAFIA (contesto Sealing)

Tutto avviene sul dispositivo, in Rust compilato a Wasm. Le implementazioni sono RustCrypto pure (tempo costante, niente C), quindi lo stesso codice gira nei test nativi e nel browser.

| Funzione | Algoritmo | Note |
|---|---|---|
| KEM (modalità richiesta) | X25519 + ML-KEM-768 (FIPS 203) | Costruzione stile X-Wing: un seed di 32 byte espanso con SHAKE256; `ss = SHA3-256(ss_mlkem ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519 ‖ etichetta)`. Sicuro finché regge almeno uno dei due. |
| Cifratura | XChaCha20-Poly1305 | Nonce casuale di 192 bit, header intero come dati associati. |
| KDF | HKDF-SHA3-256 | `key = HKDF(salt="sigylo/v1", ikm = base ‖ Argon2id(passphrase), info = "sigylo/v1/aead" ‖ modo)`. |
| Passphrase | Argon2id v1.3 | 64 MiB, 3 passate, 1 corsia. In apertura si accettano solo costi tra 19 e 256 MiB, 2–10 passate, 1–4 corsie: un server ostile non può né esaurire la RAM né abbassare la difesa. |
| Riempimento | Bucket a potenza di 2 da 256 B | Il server non distingue "hunter2" da una frase di 200 caratteri. Massimo 64 KiB. |

**Due modalità:**
* **Link (predefinita):** una chiave casuale di 256 bit per segreto, solo nel frammento dell'URL (`#…`), che i browser non inviano mai ai server. Le chiavi simmetriche a 256 bit sono già post-quantistiche (Grover lascia 2^128).
* **Richiesta (post-quantistica ibrida):** il destinatario genera sul proprio dispositivo una coppia X25519 + ML-KEM-768 e pubblica solo la chiave pubblica; nel link per il mittente c'è l'impronta SHA3 della chiave, così un relay che sostituisce la chiave viene scoperto prima di cifrare (`FingerprintMismatch`). Nessuna chiave di lettura viaggia mai su alcun canale, e il traffico registrato oggi resta segreto contro un futuro computer quantistico (HNDL).

**Busta (`crates/sealing/src/core/envelope.rs`):** `"SGY" | versione 1 | modo | flag | [salt + costi Argon2id] | [incapsulamento 1120 B] | nonce 24 B | ciphertext + tag`. Il parser è stretto e canonico. I test `format_pin` fissano i byte: se cambiano, si alza la versione, non si aggiornano le costanti.

**Errori indistinguibili:** chiave sbagliata, passphrase sbagliata, destinatario sbagliato e busta manomessa danno tutti `NotAuthentic`.

**Memoria:** chiavi, seed, passphrase e testo in chiaro sono tipi `Zeroize` con `Debug` oscurato. Limite noto del browser: ciò che passa in una stringa o `Uint8Array` JS può restare in copie del garbage collector.

## 3. CUSTODIA (contesto Custody) E RELAY CIECO

* **Il relay è cieco:** riceve buste già sigillate (byte opachi), id casuali di 128 bit scelti dal client e, per la revoca, un token di cui conserva solo lo SHA-256. Non registra id, payload o indirizzi.
* **Regole:** durata da 5 minuti a 7 giorni; `BurnAfterReading` restituisce la busta **al massimo una volta** anche con letture concorrenti; `UntilExpiry` è leggibile fino alla scadenza; inesistente, scaduto, già letto e revocato sono indistinguibili (`404 NotFound`); un id vivo non si sovrascrive; una richiesta riceve al massimo una risposta, salvata sotto lo stesso id.
* **API (`worker/src/api.rs`):** `POST /api/secrets`, `POST /api/secrets/{id}/open`, `POST /api/secrets/{id}/revoke`, `POST /api/requests`, `GET /api/requests/{id}`, `POST /api/requests/{id}/answer`. Aprire è sempre una POST: anteprime dei link e prefetch (GET) non possono bruciare un segreto. Campi binari in base64url senza padding.
* **Rate limit:** binding `WRITE_LIMITER` di Cloudflare sulle POST per indirizzo, in memoria di Cloudflare, mai salvato da noi.

## 4. PERSISTENZA (Supabase PostgreSQL via Hyperdrive)

* Schema `custody` con due tabelle e **8 colonne in tutto** (verificato dai test): niente orari di creazione, niente IP, niente account. Colonne `bytea`, vincoli di lunghezza nel database.
* Ogni operazione è una funzione `SECURITY DEFINER` con `search_path` vuoto; burn-after-reading è un solo `DELETE … RETURNING` atomico; l'orologio che decide la scadenza è solo `now()` del database.
* Il Worker si collega come `sigylo_relay`, che può **solo eseguire le funzioni**: nessun privilegio sulle tabelle, quindi una credenziale del relay rubata non può elencare o scaricare i segreti. `PUBLIC` (e quindi `anon`/`authenticated` di Supabase) non ha nulla. RLS attiva e forzata.
* Disattivati per scelta: Supabase Auth, supabase-js nel browser, Vault/pgsodium (la crittografia non avviene mai nel database), PostgREST sullo schema `custody`.
* Un cron ogni 15 minuti (`purge_expired`) cancella fisicamente ciò che è scaduto.

## 5. CLIENT WEB E INTEGRITÀ DEL CODICE

* Svelte 5 (runes) + TypeScript strict; nessuna dipendenza a runtime oltre al codice compilato.
* Servito dal Worker stesso (Workers Static Assets): una sola origine, quindi `connect-src 'self'` e niente CORS.
* **CSP** (`web/public/_headers`): `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, più `Referrer-Policy: no-referrer`, COOP, CORP, HSTS, `nosniff`, `X-Frame-Options: DENY`. Nessun `unsafe-inline`: niente script o stili inline.
* **SRI** (`web/vite-plugin-integrity.ts`): `integrity` sha384 su script e fogli di stile, e il `.wasm` si scarica con `fetch(url, { integrity })`.
* Dopo l'apertura la chiave viene tolta dalla barra degli indirizzi (`history.replaceState`).
* **UI:** spaziature e tipografia sulla scala aurea (φ) da 8 px; palette "ceralacca" (rosso sigillo su inchiostro e pergamena), tema chiaro e scuro.
* **Limite noto:** chi controlla l'hosting può servire un `index.html` diverso. SRI protegge le sotto-risorse, non la pagina stessa: per gli utenti più esigenti servirà un client verificabile (Tauri o estensione firmata, vedi §7).

## 6. DEPLOY

1. Supabase: applicare `supabase/migrations/*.sql`, poi `alter role sigylo_relay login password '<password forte>';`.
2. Cloudflare: `npx wrangler hyperdrive create sigylo-db --connection-string="postgres://sigylo_relay:<password>@<host>:5432/postgres"` e mettere l'id in `worker/wrangler.toml`.
3. `(cd web && npm ci && npm run build)` poi `(cd worker && npx wrangler deploy)`.
4. Disattivare tutte le funzioni Cloudflare che modificano l'HTML (Rocket Loader, Email Obfuscation, Web Analytics automatico): romperebbero CSP e SRI.

## 7. RINVIATO (non nell'MVP)

* **Account e autenticazione:** OPAQUE o challenge firmate con Ed25519 + ML-DSA-65, MEK/chiave di autenticazione derivate con Argon2id + HKDF. L'MVP non ha account: il link è la capacità.
* **Client verificabile:** app Tauri con chiavi in Secure Enclave / TPM, oppure estensione browser firmata.
* **File e allegati:** suddivisione in chunk cifrati su storage (Supabase Storage o R2).
* **Blind index:** non serve finché non esistono ricerche lato server.
* **Naming:** verifiche su marchi, domini e handle.
