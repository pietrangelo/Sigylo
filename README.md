# Sigylo

Il sigillo digitale per i tuoi segreti. Scrivi una password, scegli se deve distruggersi alla prima lettura o a una scadenza, invia il link. Il segreto viene cifrato nel tuo browser; il server conserva solo dati illeggibili e li distrugge come hai deciso.

Indirizzo di produzione: **https://sigylo.net**.

Specifica, architettura e regole di sviluppo: [CLAUDE.md](CLAUDE.md).

## Come funziona

- **Link:** una chiave casuale di 256 bit, solo nel frammento `#` del link, che i browser non mandano mai ai server. Facoltativa una passphrase (Argon2id) da inviare per un altro canale.
- **Richiesta, post-quantistica:** chi deve ricevere crea una coppia di chiavi ibrida X25519 + ML-KEM-768 sul proprio dispositivo; chi invia sigilla con quella chiave. Nessuna chiave di lettura viaggia mai.
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

Licenza: Apache-2.0.
