//! # Sigylo app
//!
//! A Tauri shell around the web client. The page and its Rust/Wasm sealing
//! engine are built into the app (`web/dist-app`), so no code is fetched
//! from a server when the app runs: what was installed is what seals. The
//! page cannot reach the network; it can only call the two commands below,
//! and the webview cannot navigate away from the bundle. An opened file is
//! saved to the downloads folder.

pub mod legal;
pub mod navigation;
pub mod relay;

use tauri::{AppHandle, State, WebviewUrl, WebviewWindowBuilder, webview::DownloadEvent};
use tauri_plugin_opener::OpenerExt;

use relay::{Call, Relay, Reply};

/// Forward one call of the relay API to sigylo.net.
#[tauri::command]
async fn relay(
    relay: State<'_, Relay>,
    method: String,
    path: String,
    body: Option<String>,
    session: Option<String>,
) -> Result<Reply, String> {
    let call = Call::new(&method, &path, body, session).map_err(|e| format!("{e:?}"))?;
    relay.send(&call).await.map_err(|e| format!("{e:?}"))
}

/// Open the terms of service or the privacy notice in the system browser.
#[tauri::command]
fn open_legal(app: AppHandle, page: String) -> Result<(), String> {
    let url = legal::page_url(&page).ok_or("UnknownPage")?;
    app.opener().open_url(url, None::<&str>).map_err(|_| "Unavailable".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Relay::production())
        .invoke_handler(tauri::generate_handler![relay, open_legal])
        .setup(|app| {
            let builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .on_navigation(navigation::allows)
                // The destination is the user's downloads folder, never overwriting.
                .on_download(|_, event| match event {
                    DownloadEvent::Requested { url, .. } => navigation::is_app_download(&url),
                    _ => true,
                });
            #[cfg(desktop)]
            let builder = builder.title("Sigylo").inner_size(720.0, 880.0).min_inner_size(360.0, 560.0);
            builder.build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Sigylo could not start");
}
