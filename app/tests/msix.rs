//! The Microsoft Store package: the MSIX manifest that `msix/pack.ps1` fills
//! with the version and packs around the Windows build. The Store signs it.

use std::{fs, path::Path};

const DIR: &str = env!("CARGO_MANIFEST_DIR");

fn manifest() -> String {
    fs::read_to_string(format!("{DIR}/msix/AppxManifest.xml")).unwrap()
}

/// The value of every `name="…"` attribute in the manifest, in order.
fn attributes(name: &str) -> Vec<String> {
    let needle = format!(" {name}=\"");
    manifest().split(&needle).skip(1).map(|rest| rest.split('"').next().unwrap().to_owned()).collect()
}

fn element(name: &str) -> String {
    let xml = manifest();
    let open = format!("<{name}>");
    let start = xml.find(&open).unwrap() + open.len();
    xml[start..].split("</").next().unwrap().to_owned()
}

fn png_size(path: &Path) -> (u32, u32) {
    let bytes = fs::read(path).unwrap();
    let be = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    (be(16), be(20))
}

#[test]
fn the_package_is_named_as_the_store_reservation() {
    assert_eq!(element("DisplayName"), "Sigylo");
    assert!(attributes("DisplayName").iter().all(|name| name == "Sigylo"));
    for value in attributes("Name").into_iter().chain(attributes("Publisher")) {
        assert!(!value.contains("DA_COMPILARE"), "fill in the Partner Center identity");
    }
    assert!(attributes("Publisher")[0].starts_with("CN="));
    assert!(!element("PublisherDisplayName").contains("DA_COMPILARE"));
}

#[test]
fn the_version_comes_from_tauri_conf_at_pack_time() {
    assert_eq!(attributes("Version"), ["{{VERSION}}"]);
    let pack = fs::read_to_string(format!("{DIR}/msix/pack.ps1")).unwrap();
    assert!(pack.contains("tauri.conf.json"));
    // The Store requires the fourth part to be 0.
    assert!(pack.contains("\"$version.0\""));
}

#[test]
fn the_package_starts_the_app_as_a_desktop_program() {
    assert_eq!(attributes("Executable"), ["Sigylo.exe"]);
    assert_eq!(attributes("EntryPoint"), ["Windows.FullTrustApplication"]);
    assert!(manifest().contains("Name=\"Windows.Desktop\""));
}

#[test]
fn the_package_speaks_the_five_languages_of_the_client() {
    assert_eq!(attributes("Language"), ["en-us", "it-it", "fr-fr", "es-es", "de-de"]);
}

#[test]
fn every_logo_is_in_the_bundle_at_its_size() {
    let pack = fs::read_to_string(format!("{DIR}/msix/pack.ps1")).unwrap();
    for (attribute, side) in [("Logo", 50), ("Square150x150Logo", 150), ("Square44x44Logo", 44)] {
        let logos: Vec<String> = if attribute == "Logo" { vec![element("Logo")] } else { attributes(attribute) };
        assert_eq!(logos.len(), 1, "{attribute}");
        let file = logos[0].strip_prefix("Assets\\").unwrap();
        assert_eq!(png_size(&Path::new(DIR).join("icons").join(file)), (side, side), "{file}");
        assert!(pack.contains(file.trim_end_matches(".png")), "pack.ps1 copies {file}");
    }
}

mod adversary {
    use super::*;

    #[test]
    fn the_package_asks_for_nothing_beyond_running_as_a_desktop_app() {
        // runFullTrust is what every packaged desktop app needs; anything more
        // (file system, camera, other apps' data) the app has no use for.
        let xml = manifest();
        let capabilities = xml.split("<Capabilities>").nth(1).unwrap().split("</Capabilities>").next().unwrap();
        let names: Vec<&str> =
            capabilities.split("Name=\"").skip(1).map(|rest| rest.split('"').next().unwrap()).collect();
        assert_eq!(names, ["runFullTrust"]);
        assert!(!xml.contains("<Extensions>"), "no protocol, file type or startup hooks");
    }

    #[test]
    fn the_only_placeholder_is_the_version() {
        let xml = manifest();
        assert_eq!(xml.matches("{{").count(), 1);
        assert_eq!(xml.matches("}}").count(), 1);
    }
}
