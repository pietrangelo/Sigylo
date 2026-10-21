# Sigylo app (Tauri)

**English** · [Italiano](README.it.md)

The same interface as sigylo.net and the same Rust/Wasm engine, but installed on the device: while the app runs no code comes from a server, so whoever controls the hosting cannot serve a different page to app users. Links created in the app stay `https://sigylo.net/#/…` and open in any browser; a received link is pasted into the box at the top and opened with the app's engine.

## What the page can do

- **No network:** the page's CSP allows only the app bundle (`'self'`) and Tauri's IPC. `fetch` to any address fails.
- **Only two commands** (`capabilities/main.json`, declared in `build.rs`): `relay`, which accepts only relay API calls (secrets, files, requests and accounts; the session token only where needed, as `Authorization: Bearer`) and sends them only to `https://sigylo.net/api` (no redirects, no cookies, body at most 100 KiB, response at most 128 KiB; file chunks, in base64url, up to 1 MiB + 16 bytes), and `open_legal`, which opens only the terms or the privacy notice in the system browser. No Tauri or plugin permission is granted to the page, and `window.__TAURI__` does not exist.
- **No navigation:** the webview never leaves the bundle (`src/navigation.rs`).
- **No automatic updates:** the code changes only by installing a new version.

## Commands

```bash
(cd web && npm ci && npm run build:app)   # app client in web/dist-app
cd app
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
cargo tauri dev                           # run the app (needs tauri-cli 2: cargo install tauri-cli --locked)
cargo tauri build                         # installers for the current system
bash ../scripts/app-smoke.sh              # the real app in a virtual display, driven via WebDriver
```

On Linux the webview libraries are needed: `libwebkit2gtk-4.1-dev build-essential file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev` (for the smoke test also `xvfb webkit2gtk-driver` and `cargo install tauri-driver --locked`).

## Release

`.github/workflows/app-release.yml` builds the installers for Linux, macOS (Apple silicon and Intel) and Windows and attaches them to a draft GitHub release, on an `app-v*` tag or by hand. The builds are unsigned: macOS and Windows will show a warning until the certificates (Apple Developer ID, Windows code signing) are added as repository secrets.

The Windows build also gives `Sigylo_<version>.0_x64.msix` for the Microsoft Store (workflow artifact `sigylo-msix`, built by `msix/pack.ps1` from `msix/AppxManifest.xml`). It carries the identity Partner Center reserved for Sigylo and is uploaded there unsigned: the Store signs it. It is not attached to the release, since an unsigned MSIX does not install.

## Mobile

The crate is already set up for iOS and Android (`#[tauri::mobile_entry_point]`, `staticlib`/`cdylib`). Generating the native projects needs the platform toolchain: `cargo tauri android init` (Android SDK and NDK) or `cargo tauri ios init` (macOS with Xcode), then `cargo tauri android dev` / `cargo tauri ios dev`. Publishing to the stores requires the owner's developer accounts.
