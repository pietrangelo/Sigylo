# Sigylo

## MISSIONE
Condividere dati segreti (credenziali, chiavi, codici, file fino a 10 MiB) nel modo più sicuro possibile e più semplice possibile. Il mittente sigilla il segreto nel browser, il server custodisce solo dati illeggibili, il destinatario apre il sigillo una volta (oppure fino alla scadenza scelta) e poi il segreto sparisce.

- **Nome:** Sigylo, da *sigillo / sigillum*: il timbro che per secoli ha garantito che una lettera non fosse stata aperta prima dell'arrivo. Dominio: **sigylo.net** (registrato su Cloudflare il 2026-10-17, unica origine di produzione). Verifiche su marchi (TMview, WIPO, classi di Nizza 9 e 42) e handle ancora da fare.
- **Lingue:** italiano, inglese, francese, spagnolo e tedesco (`web/src/lib/i18n.ts`). Vale la prima lingua del browser tra queste, altrimenti l'inglese.
- **Principio guida:** semplicità prima di tutto. Un campo (testo o file), due scelte (quando distruggerlo, quando scade), un pulsante. La sicurezza non deve chiedere nulla all'utente.

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
  - un dominio usa `std::{fs, net, io, process, env, thread, time, os, path}`, rinomina o importa con glob `std`, usa `include!`/`include_str!`/`include_bytes!`/`env!`/`option_env!` o `#[path]` (anche dentro `cfg_attr`), o scrive sulla console (`print!`, `println!`, `eprint!`, `eprintln!`, `dbg!`);
  - un crate escluso dal workspace (`exclude`, oggi solo `app/`) non è uno shell o un tool;
  - un file non si analizza (fail closed).

## 1. STRUTTURA DEL REPOSITORY E COMANDI

```text
crates/sealing/            Dominio puro "Sealing": buste, schedule delle chiavi, port crittografici
crates/sealing-adapters/   RustCrypto: X25519 + ML-KEM-768, XChaCha20-Poly1305, Argon2id, HKDF-SHA3-256, CSPRNG
crates/custody/            Dominio puro "Custody": custodia cieca, burn-after-reading, scadenza, revoca, richieste
crates/custody-adapters/   PostgresVault (tokio-postgres, anche via Hyperdrive), R2ChunkStore (blocchi dei file su Cloudflare R2), digest SHA-256 dei token
crates/sigylo-wasm/        Shell browser: Sealing + RustCrypto esposti a JavaScript (wasm-bindgen)
worker/                    Shell Cloudflare Worker (workers-rs): relay cieco HTTP → Custody → PostgreSQL + R2
web/                       Client Svelte 5 + TypeScript strict, solo dipendenze di sviluppo, nessuna a runtime
app/                       Shell Tauri 2 (workspace a parte): client web e motore Wasm installati, relay solo verso sigylo.net
supabase/migrations/       Schema SQL e funzioni atomiche della custodia
supabase/tests/            Test dei privilegi SQL + test di contratto del vault su un PostgreSQL usa e getta
tools/architecture-guard/  Verifica statica della rosetta
scripts/e2e.sh             End-to-end: Worker reale (workerd) + PostgreSQL + Chromium
scripts/app-smoke.sh       L'app vera in Xvfb, guidata via WebDriver (tauri-driver)
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
(cd web && npm run build:app) && (cd app && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
bash scripts/app-smoke.sh                            # l'app Tauri nella webview vera
```

Strumenti: Rust stabile con target `wasm32-unknown-unknown`, `wasm-bindgen-cli` alla versione esatta fissata in `crates/sigylo-wasm/Cargo.toml` (oggi 0.2.129), `worker-build` 0.8.7, Node 22, PostgreSQL 15+ (binari `initdb`/`pg_ctl` per i test).

## 2. CRITTOGRAFIA (contesto Sealing)

Tutto avviene sul dispositivo, in Rust compilato a Wasm. Le implementazioni sono RustCrypto pure (tempo costante, niente C), quindi lo stesso codice gira nei test nativi e nel browser.

| Funzione | Algoritmo | Note |
|---|---|---|
| KEM (modalità richiesta) | X25519 + ML-KEM-768 (FIPS 203) | Costruzione stile X-Wing: un seed di 32 byte espanso con SHAKE256; `ss = SHA3-256(ss_mlkem ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519 ‖ etichetta)`. Sicuro finché regge almeno uno dei due. |
| Firma (modalità richiesta) | Ed25519 + ML-DSA-65 (FIPS 204) | Un seed di 32 byte espanso con SHAKE256; entrambe le metà firmano `etichetta ‖ chiave pubblica ibrida ‖ messaggio` e devono verificare entrambe. ML-DSA in variante deterministica. |
| Cifratura | XChaCha20-Poly1305 | Nonce casuale di 192 bit, header intero come dati associati. |
| KDF | HKDF-SHA3-256 | `key = HKDF(salt="sigylo/v1", ikm = base ‖ Argon2id(passphrase), info = "sigylo/v1/aead" ‖ modo)`. |
| Passphrase | Argon2id v1.3 | 64 MiB, 3 passate, 1 corsia. In apertura si accettano solo costi tra 19 e 256 MiB, 2–10 passate, 1–4 corsie: un server ostile non può né esaurire la RAM né abbassare la difesa. |
| Riempimento | Bucket a potenza di 2 da 256 B | Il server non distingue "hunter2" da una frase di 200 caratteri. Massimo 64 KiB. |

**Due modalità:**
* **Link (predefinita):** una chiave casuale di 256 bit per segreto, solo nel frammento dell'URL (`#…`), che i browser non inviano mai ai server. Le chiavi simmetriche a 256 bit sono già post-quantistiche (Grover lascia 2^128).
* **Richiesta (post-quantistica ibrida):** il destinatario genera sul proprio dispositivo una coppia X25519 + ML-KEM-768 e pubblica solo la chiave pubblica; nel link per il mittente c'è l'impronta SHA3 della chiave, così un relay che sostituisce la chiave viene scoperto prima di cifrare (`FingerprintMismatch`). Nessuna chiave di lettura viaggia mai su alcun canale, e il traffico registrato oggi resta segreto contro un futuro computer quantistico (HNDL).

**Firma del mittente (`crates/sealing/src/core/signed.rs`):** ogni risposta a una richiesta è firmata con l'identità del mittente, un seed di 32 byte creato e tenuto nel `localStorage` del suo browser (`web/src/lib/identity.ts`), mai inviato. Il testo in chiaro sigillato diventa `chiave pubblica 1984 B ‖ firma 3373 B ‖ segreto` (limite del segreto firmato: 64 KiB − 4 − 5357 B) e la firma copre `"sigylo/v1/signed-answer" ‖ impronta del destinatario ‖ header della busta ‖ segreto`: non si può risigillare per un altro destinatario né cambiare un byte della busta. Tutto sta dentro l'AEAD, quindi il relay non vede chi firma né collega due risposte dello stesso mittente. Il destinatario, solo dopo che la firma ha verificato, vede il **codice mittente**: i primi 100 bit dell'impronta SHA3 della chiave in base32 Crockford, `XXXX-XXXX-XXXX-XXXX-XXXX`, da confrontare a voce o per telefono; il mittente vede lo stesso codice nella pagina di risposta. Una firma non valida dà `NotAuthentic`, come una busta manomessa.

**File a blocchi (`crates/sealing/src/core/file.rs`):** un file è un *manifest* sigillato in una normale busta v1 (link o richiesta, con o senza passphrase), più i suoi *blocchi*. Il manifest è `0xFF "SGYF" | versione 1 | chiave del file 32 B | dimensione u64 | lunghezza nome | nome UTF-8`: `0xFF` non compare mai in UTF-8, quindi nessun testo viene scambiato per un file, e le buste v1 già emesse si aprono come prima. Ogni file ha una chiave casuale propria; i blocchi da 1 MiB sono XChaCha20-Poly1305 con chiave `HKDF(salt="sigylo/v1", file key, info="sigylo/v1/chunk")`, nonce `"SGYC" ‖ indice` e dati associati `"SGYC" ‖ versione ‖ indice ‖ numero di blocchi`: riordinare, togliere, duplicare, troncare blocchi o prenderli da un altro file dà `NotAuthentic`. L'ultimo blocco è riempito a una potenza di 2 da almeno 256 B. Massimo 10 MiB (10 blocchi). Il nome non può contenere separatori di percorso, caratteri di controllo o invisibili/bidirezionali (`fattura\u{202E}fdp.exe`); il browser lo scarica sempre come `application/octet-stream`, mai aperto nella pagina, così un HTML o SVG sigillato non gira con l'origine di Sigylo. Una risposta con un file si firma come una di testo: la firma copre il manifest, che porta la chiave del file, quindi ogni blocco.

**Mittente atteso (facoltativo):** chi crea la richiesta può scrivere il codice del mittente che aspetta (il mittente lo trova su `#/me`). Nei link di richiesta e di lettura finisce solo il **pin** `HKDF-SHA3-256(salt = "sigylo/v1", ikm = 100 bit del codice, info = "sigylo/v1/expected-sender" ‖ impronta del destinatario)`, diverso per ogni richiesta: dal link non si risale al codice e due richieste allo stesso mittente non si collegano. In apertura una risposta non firmata o firmata da altri dà `UnexpectedSender` e il testo in chiaro viene azzerato senza essere mostrato; la pagina di risposta avvisa subito un mittente diverso, così non consuma l'unica risposta della richiesta. Il codice si accetta come lo detta una persona: maiuscole o minuscole, con o senza trattini, I/L per 1 e O per 0.

**Busta (`crates/sealing/src/core/envelope.rs`):** `"SGY" | versione 1 | modo | flag | [salt + costi Argon2id] | [incapsulamento 1120 B] | nonce 24 B | ciphertext + tag`. Flag: bit 0 passphrase, bit 1 firmata (solo in modalità richiesta); il flag è nell'header autenticato, quindi non si può togliere né aggiungere. Una busta senza il bit 1 è identica byte per byte a quelle della prima versione, e i vecchi link si aprono ancora. Il parser è stretto e canonico. I test `format_pin` fissano i byte: se cambiano, si alza la versione, non si aggiornano le costanti.

**Errori indistinguibili:** chiave sbagliata, passphrase sbagliata, destinatario sbagliato, firma non valida e busta manomessa danno tutti `NotAuthentic`.

**Memoria:** chiavi, seed, passphrase e testo in chiaro sono tipi `Zeroize` con `Debug` oscurato. La shell Wasm li consegna a JavaScript copiandoli direttamente in un `Uint8Array` (mai come `Vec<u8>` o campo di una struct esportata, che wasm-bindgen sposta o libera senza azzerare) e dopo ogni chiamata sovrascrive 512 KiB di stack (l'espansione della chiave ML-DSA-65 arriva a circa 290 KiB, con i vettori segreti sullo stack), dove gli spostamenti lasciano copie che `Zeroize` non raggiunge. `web/tests/engine-memory.test.ts` scansiona la memoria Wasm dopo ogni operazione e fallisce se ci trova un segreto o un solo byte non azzerato nella parte morta dello stack. Limite noto del browser: ciò che passa in una stringa o `Uint8Array` JS può restare in copie del garbage collector.

## 3. CUSTODIA (contesto Custody) E RELAY CIECO

* **Il relay è cieco:** riceve buste già sigillate (byte opachi) e, per la revoca, un token di cui conserva solo lo SHA-256. Non registra id, payload o indirizzi.
* **Gli id li sceglie il relay, mai il client:** 128 bit casuali (port `IdSource`, adapter `RandomIds`), restituiti nella ricevuta `{id, expires_at}`. Una richiesta che porta un proprio `id` viene rifiutata. Altrimenti chi legge per primo un segreto burn-after-reading potrebbe rimetterne una copia, o un falso sigillato con la chiave del link, sotto lo stesso id, e il destinatario lo aprirebbe senza accorgersi di nulla: il sigillo sarebbe rotto.
* **Regole:** durata da 5 minuti a 7 giorni; `BurnAfterReading` restituisce la busta **al massimo una volta** anche con letture concorrenti; `UntilExpiry` è leggibile fino alla scadenza; inesistente, scaduto, già letto e revocato sono indistinguibili (`404 NotFound`); un id vivo non si sovrascrive; una richiesta riceve al massimo una risposta.
* **Cassetta privata della richiesta:** per ogni richiesta il relay sceglie due id, quello pubblico del link di richiesta e quello della cassetta (`inbox`), che sta solo nel link privato del destinatario; la risposta viene salvata nella cassetta. Così chi legge il link di richiesta mentre viaggia verso il mittente non può né bruciare la risposta prima del destinatario né scaricarla. Le richieste nate prima della cassetta (colonna `inbox_id` vuota) ricevono la risposta sotto il proprio id, come allora. Chi risponde riceve nella ricevuta `{id, expires_at}` l'id della cassetta, e carica lì i blocchi di un file (`custody.answer_into_inbox`): con il solo link di richiesta non si aggiunge né si rovina un blocco.
* **Modalità richiesta e mittente:** con un mittente atteso la risposta di chiunque altro viene rifiutata senza essere letta (ma consuma la richiesta: il destinatario ne crea un'altra). Senza mittente atteso chiunque abbia il link di richiesta può ancora rispondere per primo, ma viene scoperto: il destinatario vede un codice mittente diverso da quello che il mittente legittimo gli legge, e il mittente legittimo vede "richiesta già usata". Il codice va confrontato fuori banda una volta; poi resta lo stesso finché il mittente non cancella i dati del sito. Limite noto: chi controlla il browser del mittente (estensione, XSS) può leggere il seed dal `localStorage` e firmare al suo posto.
* **File:** il deposito (o la risposta) porta il manifest sigillato e `chunks`; i blocchi si caricano dopo, uno per richiesta, una volta sola ciascuno e solo finché nessuno ha aperto il deposito. Un file incompleto non si apre (`404`). Aprire un file `BurnAfterReading` non lo cancella ma lo *reclama*: il relay sceglie un token casuale, ne conserva solo lo SHA-256 e lo restituisce soltanto a chi ha aperto; da quel momento il deposito non si riapre, ogni blocco va solo a chi presenta il token, al massimo una volta, e viene cancellato mentre parte; il deposito se ne va con l'ultimo blocco, e un download abbandonato scade entro un'ora. Un file `UntilExpiry` resta scaricabile da chiunque abbia il link fino alla scadenza.
* **Blocchi su R2, mai nel database:** il relay salva ogni blocco come oggetto nel bucket R2 `sigylo-chunks` (giurisdizione UE) sotto un nome casuale di 128 bit scelto da lui (`IdSource::fresh_object`), che non dice nulla del deposito; poi `custody.put_chunk` decide atomicamente se quel blocco può essere registrato, e un oggetto rifiutato viene cancellato subito. PostgreSQL conserva solo nome e dimensione. Ogni blocco che se ne va (bruciato, revocato, scaduto, anche per cascata) lascia il nome in `custody.garbage`; il cron cancella quegli oggetti da R2 e solo dopo li dimentica, così un errore di R2 non perde traccia di nulla. Un blocco bruciato sparisce da R2 già mentre parte; uno revocato o scaduto entro circa 15 minuti; una regola di ciclo di vita del bucket (8 giorni) fa da rete di sicurezza.
* **API (`worker/src/api.rs`):** `POST /api/secrets`, `POST /api/secrets/{id}/open`, `POST /api/secrets/{id}/revoke`, `POST /api/secrets/{id}/chunks/{n}`, `POST /api/secrets/{id}/chunks/{n}/open`, `POST /api/requests`, `GET /api/requests/{id}`, `POST /api/requests/{id}/answer`. Aprire è sempre una POST: anteprime dei link e prefetch (GET) non possono bruciare un segreto. Campi binari in base64url senza padding, tranne i blocchi, che viaggiano come corpo binario grezzo (nessun base64 da 1 MiB nei 10 ms di CPU del Worker). Il corpo si valida (anche la `Content-Length` dichiarata) prima di aprire una connessione al database.
* **Rate limit:** binding Cloudflare `WRITE_LIMITER` (POST, 30/min) e `READ_LIMITER` (GET, 60/min) su ogni chiamata all'API (anche le GET: ognuna costa una query) per indirizzo, IPv6 per /64 (`limiter_key`), in memoria di Cloudflare, mai salvato da noi.
* **Solo dalle nostre pagine:** una chiamata con un'intestazione `Origin` diversa dall'origine del relay riceve `403` (`check_origin`), così una pagina di un altro sito non può usare i browser dei suoi visitatori per riempire la custodia aggirando il limite per indirizzo. Senza `Origin` (la shell dell'app) si passa.

## 4. PERSISTENZA (Supabase PostgreSQL via Hyperdrive, blocchi su Cloudflare R2)

* Schema `custody` con quattro tabelle (`deposits`, `requests`, `chunks`, `garbage`) e **16 colonne in tutto** (verificato dai test): niente orari di creazione, niente IP, niente account. Colonne `bytea`, vincoli di lunghezza nel database.
* Ogni operazione è una funzione `SECURITY DEFINER` con `search_path` vuoto; burn-after-reading è un solo `DELETE … RETURNING` atomico; l'orologio che decide la scadenza è solo `now()` del database.
* **Nessuna cache di Hyperdrive:** Hyperdrive memorizza per un minuto le `SELECT` che crede di sola lettura e non vede che `custody.open` cancella; una risposta in cache restituirebbe un segreto già bruciato, revocato o scaduto. La configurazione Hyperdrive si crea con `--caching-disabled` e, in più, ogni statement del vault seleziona anche `now()`, che Hyperdrive non mette mai in cache (test in `postgres_vault.rs`).
* Il Worker si collega come `sigylo_relay`, che può **solo eseguire le funzioni**: nessun privilegio sulle tabelle, quindi una credenziale del relay rubata non può elencare o scaricare i segreti. Nessun altro ruolo, né `PUBLIC` né `anon`/`authenticated`/`service_role` di Supabase, ha privilegi nello schema `custody` (verificato sulle ACL dai test, con i ruoli Supabase ricreati). RLS attiva e forzata.
* Disattivati per scelta: Supabase Auth, supabase-js nel browser, Vault/pgsodium (la crittografia non avviene mai nel database), PostgREST sullo schema `custody`.
* Un cron ogni 15 minuti (`purge_expired`) cancella fisicamente ciò che è scaduto; i blocchi seguono il loro deposito (`on delete cascade`). Lo stesso cron del Worker raccoglie poi la `garbage` e cancella gli oggetti da R2 (al massimo 1000 per giro).
* **Tetto della custodia:** il database gratuito si ferma a 500 MB e poi passa in sola lettura (niente si apre più). `custody.ensure_room` (per i depositi in un trigger su `custody.deposits`, così vale qualunque versione di `custody.deposit`) rifiuta ogni nuovo deposito, richiesta o risposta oltre `custody.capacity_bytes()` (300 MB di byte custoditi, contati con `custody.used_bytes()`, non dai file su disco che non si restringono) con SQLSTATE `53100`, che il relay restituisce come `507 StorageFull`. Prima di rifiutare cancella subito ciò che è scaduto; aprire, revocare e pulire funzionano sempre. Ogni nuova tabella che custodisce byte va contata in `used_bytes`.
* **Tetto ai blocchi:** tutti i blocchi insieme non superano 5 GiB (`custody.put_chunk` somma le dimensioni e fallisce con `53100`, il relay risponde `507 StorageFull`), metà dei 10 GB gratuiti di R2. Il database non contiene mai i byte dei blocchi (verificato dai test). Con il limite di 30 POST al minuto per indirizzo, un file da 10 MiB costa 11 richieste per caricarlo e 11 per scaricarlo.
* Le migrazioni sono additive: le funzioni della prima conservano la firma (il vecchio `custody.open(bytea)` ignora i file), così il relay in produzione continua a funzionare mentre si applica una migrazione nuova, prima del deploy.

## 5. CLIENT WEB E INTEGRITÀ DEL CODICE

* Svelte 5 (runes) + TypeScript strict; nessuna dipendenza a runtime oltre al codice compilato.
* Servito dal Worker stesso (Workers Static Assets): una sola origine, quindi `connect-src 'self'` e niente CORS.
* **CSP** (`web/public/_headers`): `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, più `Referrer-Policy: no-referrer`, COOP, CORP, HSTS, `nosniff`, `X-Frame-Options: DENY`. Nessun `unsafe-inline`: niente script o stili inline.
* **SRI** (`web/vite-plugin-integrity.ts`): `integrity` sha384 su script e fogli di stile, e il `.wasm` si scarica con `fetch(url, { integrity })`.
* Dopo l'apertura la chiave viene tolta dalla barra degli indirizzi (`history.replaceState`).
* **UI:** spaziature e tipografia sulla scala aurea (φ) da 8 px; palette "ceralacca" (rosso sigillo su inchiostro e pergamena), tema chiaro e scuro.
* **Termini e privacy** (`web/src/lib/legal.ts`, pagine `#/terms` e `#/privacy`, link nel footer in una nuova scheda così un link segreto aperto non perde il frammento): solo testo, mai `{@html}` (verificato dai test). La Apache License 2.0 copre il codice; i termini coprono solo il servizio su sigylo.net. Titolare e contatto stanno in `operator` e nel file `NOTICE`: un test fa fallire la CI, e quindi il deploy, finché contengono `DA COMPILARE`. Se cambia un testo si aggiorna `LEGAL_UPDATED`; se cambiano fornitori, dati conservati o durata massima, si aggiorna l'informativa.
* **Limite noto:** chi controlla l'hosting può servire un `index.html` diverso. SRI protegge le sotto-risorse, non la pagina stessa. Per chi lo vuole evitare c'è l'app (sotto); le build firmate e verificabili sono rinviate (§7).

**App installabile (`app/`, Tauri 2):**
* `vite build --mode app` (`npm run build:app`, in `web/dist-app`) produce la stessa pagina con il motore Wasm, incorporata nell'app: quando l'app gira nessun codice arriva da un server, e non c'è un updater.
* La pagina non ha rete: la CSP dell'app (`vite-plugin-app.ts`, identica a quella di `tauri.conf.json`, verificato dai test) ha `connect-src 'self' ipc: http://ipc.localhost`. Le chiamate al relay passano dal comando Rust `relay` (`app/src/relay.rs`), che accetta solo le rotte dell'API con il loro metodo e va solo a `https://sigylo.net/api`: niente redirect, niente cookie, solo HTTPS, corpo ≤ 100 KiB, risposta ≤ 128 KiB. I blocchi di un file attraversano l'IPC in base64url canonico (al massimo 1 MiB + 16 byte, indice di una sola cifra) e viaggiano verso il relay come byte grezzi. Così il Worker resta senza CORS.
* La pagina ha due soli permessi (`capabilities/main.json`: `allow-relay`, `allow-open-legal`), nessun permesso di Tauri o dei plugin, niente `withGlobalTauri`, `freezePrototype` attivo; la webview non naviga fuori dal bundle (`navigation.rs`).
* I link creati nell'app sono `https://sigylo.net/#/…` (si aprono in ogni browser); un link ricevuto si incolla nel riquadro dell'app (`linkFragment` accetta solo `https://sigylo.net/` con un frammento di segreto, revoca, richiesta o cassetta). Termini e informativa si aprono nel browser di sistema.
* Rilascio: `.github/workflows/app-release.yml` (tag `app-v*` o a mano) crea installer Linux, macOS e Windows non firmati in una release in bozza. Firma e store richiedono gli account del titolare. Mobile: crate pronto (`mobile_entry_point`), progetti nativi da generare con `cargo tauri android init` / `ios init`.

## 6. DEPLOY

1. Supabase, in un progetto dedicato solo a Sigylo: applicare `supabase/migrations/*.sql` in ordine (una migrazione nuova si applica **prima** di unire la PR che la usa: le migrazioni restano compatibili con il relay già pubblicato), poi `alter role sigylo_relay login password '<password forte>';`.
2. Cloudflare: `npx wrangler hyperdrive create sigylo-db --caching-disabled --connection-string="postgres://sigylo_relay:<password>@<host>:5432/postgres"` e mettere l'id in `worker/wrangler.toml`. `--caching-disabled` è obbligatorio (vedi §4); su una configurazione già creata: `npx wrangler hyperdrive update <id> --caching-disabled`.
   R2: `npx wrangler r2 bucket create sigylo-chunks --jurisdiction eu` e, come rete di sicurezza, `npx wrangler r2 bucket lifecycle add sigylo-chunks backstop --expire-days 8 --jurisdiction eu` (il token del deploy deve poter modificare R2).
3. Pubblicazione su `https://sigylo.net` (custom domain del Worker, `workers.dev` spento; il primo deploy crea record DNS e certificato nella zona). Di norma la fa `.github/workflows/deploy.yml`: parte solo su `main`, solo dopo che la CI è passata su quello stesso commit, mai da una pull request. Segreti del repository: `CLOUDFLARE_API_TOKEN` (modello "Edit Cloudflare Workers", limitato a questo account e alla zona sigylo.net) e `CLOUDFLARE_ACCOUNT_ID`. Ogni azione di GitHub è fissata al commit (`uses: owner/azione@<sha> # tag`, verificato dalla CI): un tag spostato di un'azione di terzi girerebbe accanto al token e alla pagina da pubblicare. A mano: `(cd web && npm ci && npm run build)` poi `(cd worker && npx wrangler deploy)`.
4. Nella zona sigylo.net disattivare tutte le funzioni Cloudflare che modificano l'HTML (Rocket Loader, Email Obfuscation, Web Analytics automatico): romperebbero CSP e SRI. Dopo ogni deploy il workflow verifica che la pagina servita sia identica byte per byte a `web/dist/index.html` e porti la CSP di `_headers`, e fallisce se la zona la riscrive.

## 7. RINVIATO (non nell'MVP)

* **Chiavi di firma non esportabili** nel client verificabile (Tauri, Secure Enclave / TPM); rifiutare la risposta di un mittente non atteso già sul relay richiederebbe che il relay veda chi firma, quindi resta lato client.
* **Account e autenticazione:** OPAQUE o challenge firmate con Ed25519 + ML-DSA-65, MEK/chiave di autenticazione derivate con Argon2id + HKDF. L'MVP non ha account: il link è la capacità.
* **Client verificabile:** build dell'app firmate e riproducibili, chiavi in Secure Enclave / TPM, oppure estensione browser firmata. Aprire i link `https://sigylo.net` direttamente nell'app (universal/app links) richiede gli identificativi degli account sviluppatore.
* **File oltre 10 MiB:** l'archiviazione su R2 c'è già; servirebbero più blocchi per file e, oltre una certa misura, upload multipart.
* **Blind index:** non serve finché non esistono ricerche lato server.
* **Naming:** verifiche su marchi e handle (il dominio sigylo.net c'è già).
