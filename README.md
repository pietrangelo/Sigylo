# Sigylo

Il sigillo digitale per i tuoi segreti. Scrivi una password, scegli se deve distruggersi alla prima lettura o a una scadenza, invia il link. Il segreto viene cifrato nel tuo browser; il server conserva solo dati illeggibili e li distrugge come hai deciso.

Indirizzo di produzione: **https://sigylo.net**.

Specifica, architettura e regole di sviluppo: [CLAUDE.md](CLAUDE.md).

## Come funziona

- **Link:** una chiave casuale di 256 bit, solo nel frammento `#` del link, che i browser non mandano mai ai server. Facoltativa una passphrase (Argon2id) da inviare per un altro canale.
- **Richiesta, post-quantistica:** chi deve ricevere crea una coppia di chiavi ibrida X25519 + ML-KEM-768 sul proprio dispositivo; chi invia sigilla con quella chiave. Nessuna chiave di lettura viaggia mai.
- **File fino a 10 MiB:** un manifest sigillato come qualsiasi segreto porta la chiave del file; il file viaggia in blocchi da 1 MiB autenticati con posizione e numero totale, e un file a lettura unica va solo a chi l'ha aperto, blocco per blocco. I blocchi stanno su Cloudflare R2 (UE) sotto nomi casuali, mai nel database.
- **Relay cieco:** un Cloudflare Worker in Rust custodisce buste opache in PostgreSQL (Supabase, via Hyperdrive). Burn-after-reading atomico, scadenza da 5 minuti a 7 giorni, revoca da parte del mittente.

```text
browser (Svelte + Rust/Wasm)  ──buste sigillate──▶  Worker Rust (relay cieco)  ──funzioni SQL──▶  PostgreSQL
   chiavi e testo in chiaro                          niente chiavi, niente log         solo bytea e scadenze
```

## Avvio rapido

```bash
cargo test --workspace
cargo run -p architecture-guard
bash supabase/tests/run.sh
(cd web && npm ci && npm run build && npm test)
bash scripts/e2e.sh
```

App installabile (Tauri, desktop e predisposta per mobile): vedi [app/README.md](app/README.md).

Licenza del codice: Apache-2.0 (vedi [LICENSE](LICENSE) e [NOTICE](NOTICE)). L'uso del servizio su sigylo.net è regolato dai termini di servizio e dall'informativa sulla privacy, raggiungibili dal piè di pagina del sito.
