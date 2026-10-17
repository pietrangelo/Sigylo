// The app's own commands are declared here, so each one needs an explicit
// permission in capabilities/main.json: nothing is reachable from the page
// by default.
fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&["relay", "open_legal"]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest)).expect("tauri-build failed");
}
