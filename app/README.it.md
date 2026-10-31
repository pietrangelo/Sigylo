# Sigylo app (Tauri)

[English](README.md) · **Italiano**

La stessa interfaccia di sigylo.net e lo stesso motore Rust/Wasm, ma installati sul dispositivo: quando l'app gira nessun codice arriva da un server, quindi chi controlla l'hosting non può servire una pagina diversa a chi usa l'app. I link creati nell'app restano `https://sigylo.net/#/…` e si aprono in qualunque browser; un link ricevuto si incolla nel riquadro in cima e si apre con il motore dell'app.

## Cosa può fare la pagina

- **Niente rete:** la CSP della pagina permette solo il bundle dell'app (`'self'`) e l'IPC di Tauri. `fetch` verso qualunque indirizzo fallisce.
- **Due comandi soltanto** (`capabilities/main.json`, dichiarati in `build.rs`): `relay`, che accetta solo le chiamate dell'API del relay (segreti, file, richieste e account; il token di sessione solo dove serve, come `Authorization: Bearer`) e le manda solo a `https://sigylo.net/api` (niente redirect, niente cookie, corpo massimo 100 KiB, risposta massima 128 KiB; i blocchi dei file, in base64url, fino a 1 MiB + 16 byte), e `open_legal`, che apre nel browser di sistema solo i termini o l'informativa. Nessun permesso di Tauri o dei plugin è concesso alla pagina, e `window.__TAURI__` non esiste.
- **Niente navigazione:** la webview non lascia mai il bundle (`src/navigation.rs`).
- **Niente aggiornamenti automatici:** il codice cambia solo installando una nuova versione.

## Comandi

```bash
(cd web && npm ci && npm run build:app)   # client per l'app in web/dist-app
cd app
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
cargo tauri dev                           # avvia l'app (serve tauri-cli 2: cargo install tauri-cli --locked)
cargo tauri build                         # installer per il sistema corrente
bash ../scripts/app-smoke.sh              # l'app vera in un display virtuale, guidata via WebDriver
```

Su Linux servono le librerie della webview: `libwebkit2gtk-4.1-dev build-essential file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev` (per lo smoke test anche `xvfb webkit2gtk-driver` e `cargo install tauri-driver --locked`).

## Rilascio

`.github/workflows/app-release.yml` costruisce gli installer per Linux, macOS (Apple silicon e Intel) e Windows e li allega a una release GitHub in bozza, per un tag `app-v*` su un commit di `main` la cui CI è passata, o a mano da `main`. Le build (`cargo tauri build -- --locked`) non ricevono un token di scrittura; solo l'ultimo job, che non costruisce nulla, allega i loro installer alla bozza. Le build non sono firmate: macOS e Windows mostreranno un avviso finché non si aggiungono i certificati (Apple Developer ID, firma del codice per Windows) come segreti del repository.

La build Windows produce anche `Sigylo_<versione>.0_x64.msix` per il Microsoft Store (artefatto del workflow `sigylo-msix`, creato da `msix/pack.ps1` a partire da `msix/AppxManifest.xml`). Porta l'identità che Partner Center ha riservato a Sigylo e si carica lì senza firma: la firma la mette lo Store. Non è allegato alla release, perché un MSIX non firmato non si installa.

## Mobile

Il crate è già pronto per iOS e Android (`#[tauri::mobile_entry_point]`, `staticlib`/`cdylib`). Per generare i progetti nativi serve la toolchain della piattaforma: `cargo tauri android init` (Android SDK e NDK) oppure `cargo tauri ios init` (macOS con Xcode), poi `cargo tauri android dev` / `cargo tauri ios dev`. La pubblicazione negli store richiede gli account sviluppatore del titolare.
