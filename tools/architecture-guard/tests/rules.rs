use std::collections::HashMap;
use std::path::Path;

use architecture_guard::{Ring, Role, Rule, check_lib_root, check_manifest, check_source};

fn rules_in(text: &str, ring: Ring) -> Vec<Rule> {
    check_source(Path::new("x.rs"), text, ring).into_iter().map(|v| v.rule).collect()
}

fn roles() -> HashMap<String, Role> {
    HashMap::from([
        ("sealing".to_string(), Role::Domain),
        ("custody".to_string(), Role::Domain),
        ("sealing-adapters".to_string(), Role::Adapters),
        ("custody-adapters".to_string(), Role::Adapters),
        ("sigylo-relay".to_string(), Role::Shell),
    ])
}

fn manifest_rules(text: &str, has_build_rs: bool) -> Vec<Rule> {
    manifest_rules_with_workspace(text, has_build_rs, "")
}

fn manifest_rules_with_workspace(text: &str, has_build_rs: bool, workspace_deps: &str) -> Vec<Rule> {
    let workspace = workspace_deps.parse::<toml::Table>().unwrap();
    check_manifest(Path::new("Cargo.toml"), text, &roles(), has_build_rs, &workspace)
        .1
        .into_iter()
        .map(|v| v.rule)
        .collect()
}

const DOMAIN_HEADER: &str = "[package]\nname = \"custody\"\n[package.metadata.rosette]\nrole = \"domain\"\n";

#[test]
fn clean_core_file_passes() {
    let text = "use core::fmt;\nuse super::SealError;\nuse crate::core::Salt;\nuse std::collections::HashMap;\n\
                pub fn f() -> Vec<u8> { vec![1, 2] }";
    assert_eq!(rules_in(text, Ring::Core), vec![]);
}

#[test]
fn application_may_use_core_but_core_may_not_use_application() {
    assert_eq!(rules_in("use crate::core::Envelope;", Ring::Application), vec![]);
    assert_eq!(rules_in("use crate::application::Sealer;", Ring::Core), vec![Rule::RingDirection]);
    assert_eq!(rules_in("use crate::Sealer;", Ring::Core), vec![Rule::RingDirection]);
}

#[test]
fn io_and_clock_are_rejected_in_both_rings() {
    for ring in [Ring::Core, Ring::Application] {
        for module in ["fs", "net", "io", "process", "env", "thread", "time"] {
            assert_eq!(rules_in(&format!("use std::{module};"), ring), vec![Rule::ImpureStd], "{module}");
        }
    }
}

#[test]
fn domain_manifest_allows_zeroize_and_sibling_domains_only() {
    let ok = format!("{DOMAIN_HEADER}[dependencies]\nzeroize = \"1\"\nsealing = {{ path = \"../sealing\" }}\n");
    assert_eq!(manifest_rules(&ok, false), vec![]);
    let bad = format!("{DOMAIN_HEADER}[dependencies]\ntokio = \"1\"\n");
    assert_eq!(manifest_rules(&bad, false), vec![Rule::DomainDependency]);
    let adapter = format!("{DOMAIN_HEADER}[dependencies]\nsealing-adapters = {{ path = \"x\" }}\n");
    assert_eq!(manifest_rules(&adapter, false), vec![Rule::DomainDependency]);
}

#[test]
fn every_member_must_declare_its_role() {
    assert_eq!(manifest_rules("[package]\nname = \"x\"\n", false), vec![Rule::UndeclaredRole]);
}

#[test]
fn adapters_may_not_depend_on_adapters_or_shells() {
    let text = "[package]\nname = \"custody-adapters\"\n[package.metadata.rosette]\nrole = \"adapters\"\n\
                [dependencies]\ncustody = \"0\"\nsealing-adapters = \"0\"\n";
    assert_eq!(manifest_rules(text, false), vec![Rule::AdapterDependency]);
}

#[test]
fn lib_root_must_forbid_unsafe_and_declare_only_the_rings() {
    let ok = "#![forbid(unsafe_code)]\npub mod application;\npub mod core;\npub use crate::core::Salt;";
    assert!(check_lib_root(Path::new("lib.rs"), ok).is_empty());
    let rules: Vec<Rule> =
        check_lib_root(Path::new("lib.rs"), "pub mod core;\nmod adapters;").into_iter().map(|v| v.rule).collect();
    assert_eq!(rules, vec![Rule::MissingForbidUnsafe, Rule::RingLayout]);
}

#[test]
fn the_real_workspace_is_clean() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let violations = architecture_guard::check_workspace(&root).unwrap();
    assert!(violations.is_empty(), "{violations:#?}");
}

/// A throwaway workspace on disk with the app crate excluded from it.
fn workspace_with_excluded_app(app_manifest: Option<&str>) -> Vec<Rule> {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!("sigylo-guard-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("app/src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = []\nexclude = [\"app\"]\n").unwrap();
    if let Some(manifest) = app_manifest {
        std::fs::write(root.join("app/Cargo.toml"), manifest).unwrap();
    }
    let rules = architecture_guard::check_workspace(&root).unwrap().into_iter().map(|v| v.rule).collect();
    std::fs::remove_dir_all(&root).unwrap();
    rules
}

fn app_with_role(role: &str) -> String {
    format!("[package]\nname = \"sigylo-app\"\n[package.metadata.rosette]\nrole = \"{role}\"\n")
}

#[test]
fn a_crate_outside_the_workspace_may_be_a_shell() {
    assert_eq!(workspace_with_excluded_app(Some(&app_with_role("shell"))), vec![]);
    assert_eq!(workspace_with_excluded_app(None), vec![], "an excluded folder without a crate holds no code");
}

mod adversary {
    use super::*;

    #[test]
    fn domains_and_adapters_cannot_escape_the_guard_by_leaving_the_workspace() {
        assert_eq!(workspace_with_excluded_app(Some(&app_with_role("domain"))), vec![Rule::ExcludedCrate]);
        assert_eq!(workspace_with_excluded_app(Some(&app_with_role("adapters"))), vec![Rule::ExcludedCrate]);
        assert_eq!(workspace_with_excluded_app(Some("[package]\nname = \"sigylo-app\"\n")), vec![Rule::UndeclaredRole]);
        assert_eq!(workspace_with_excluded_app(Some("[package")), vec![Rule::Unparsable]);
    }

    #[test]
    fn grouped_and_nested_imports_are_seen() {
        assert_eq!(rules_in("use std::{collections::HashMap, fs::File};", Ring::Core), vec![Rule::ImpureStd]);
        assert_eq!(rules_in("use std::{io::{self, Read}};", Ring::Core).first(), Some(&Rule::ImpureStd));
    }

    #[test]
    fn fully_qualified_paths_in_expressions_are_seen() {
        let text = "pub fn f() { let _ = ::std::fs::read(\"/etc/passwd\"); }";
        assert_eq!(rules_in(text, Ring::Core), vec![Rule::ImpureStd]);
        let clock = "pub fn now() -> u64 { std::time::SystemTime::now().elapsed().unwrap().as_secs() }";
        assert_eq!(rules_in(clock, Ring::Application), vec![Rule::ImpureStd]);
    }

    #[test]
    fn renaming_or_globbing_std_is_rejected() {
        assert!(rules_in("use std as s;\npub fn f() { s::fs::read(\"x\"); }", Ring::Core).contains(&Rule::StdAlias));
        assert!(rules_in("use std::{self as s};", Ring::Core).contains(&Rule::StdAlias));
        assert!(rules_in("use std::*;", Ring::Core).contains(&Rule::StdAlias));
        assert!(rules_in("extern crate std as s;", Ring::Core).contains(&Rule::StdAlias));
    }

    #[test]
    fn macros_cannot_smuggle_impure_paths() {
        let text = "macro_rules! sneaky { () => { std::net::TcpStream::connect(\"evil:1\") } }";
        assert_eq!(rules_in(text, Ring::Core), vec![Rule::ImpureStd]);
        let inside = "pub fn f() -> String { format!(\"{:?}\", std::env::var(\"KEY\")) }";
        assert_eq!(rules_in(inside, Ring::Core), vec![Rule::ImpureStd]);
        let ring = "macro_rules! up { () => { crate::application::Sealer::new } }";
        assert_eq!(rules_in(ring, Ring::Core), vec![Rule::RingDirection]);
    }

    #[test]
    fn compile_time_io_macros_are_rejected() {
        for mac in ["include_str!(\"/etc/hosts\")", "include_bytes!(\"k\")", "env!(\"HOME\")", "option_env!(\"X\")"] {
            let text = format!("pub const X: &str = {mac};");
            assert_eq!(rules_in(&text, Ring::Core), vec![Rule::CompileTimeIo], "{mac}");
        }
        assert_eq!(rules_in("include!(\"../../outside.rs\");", Ring::Core), vec![Rule::CompileTimeIo]);
    }

    #[test]
    fn console_output_is_rejected() {
        // Printing is I/O, and the easiest way to leak a key: `dbg!(key.expose())`.
        for mac in ["println!(\"{x:?}\")", "eprintln!(\"x\")", "print!(\"x\")", "eprint!(\"x\")", "dbg!(x)"] {
            let text = format!("pub fn f(x: u8) {{ {mac}; }}");
            assert_eq!(rules_in(&text, Ring::Core), vec![Rule::ConsoleIo], "{mac}");
        }
        assert_eq!(rules_in("pub fn f(k: &[u8]) { std::dbg!(k); }", Ring::Application), vec![Rule::ConsoleIo]);
        assert_eq!(rules_in("pub fn f() -> String { format!(\"ok\") }", Ring::Core), vec![]);
    }

    #[test]
    fn path_attributes_are_rejected_even_behind_cfg_attr() {
        assert_eq!(rules_in("#[path = \"../../adapters/x.rs\"] mod x;", Ring::Core), vec![Rule::PathAttribute]);
        assert_eq!(rules_in("#[cfg_attr(test, path = \"y.rs\")] mod y;", Ring::Core), vec![Rule::PathAttribute]);
    }

    #[test]
    fn reaching_application_through_super_is_rejected() {
        let text = "use super::super::application::ports::Aead;";
        assert_eq!(rules_in(text, Ring::Core), vec![Rule::RingDirection]);
        let nested = "mod inner { pub fn f() { crate::application::Sealer::touch(); } }";
        assert_eq!(rules_in(nested, Ring::Core), vec![Rule::RingDirection]);
    }

    #[test]
    fn renamed_dependencies_are_judged_by_their_real_package() {
        let disguised =
            format!("{DOMAIN_HEADER}[dependencies]\nzeroize = {{ package = \"getrandom\", version = \"0.4\" }}\n");
        assert_eq!(manifest_rules(&disguised, false), vec![Rule::DomainDependency]);
        let via_workspace = format!("{DOMAIN_HEADER}[dependencies]\nzeroize.workspace = true\n");
        assert_eq!(
            manifest_rules_with_workspace(
                &via_workspace,
                false,
                "zeroize = { package = \"reqwest\", version = \"0\" }"
            ),
            vec![Rule::DomainDependency]
        );
        assert_eq!(manifest_rules_with_workspace(&via_workspace, false, "zeroize = \"1\""), vec![]);
    }

    #[test]
    fn build_time_escape_hatches_are_rejected() {
        let target = format!("{DOMAIN_HEADER}[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n");
        assert_eq!(manifest_rules(&target, false), vec![Rule::DomainBuildTime]);
        let build_deps = format!("{DOMAIN_HEADER}[build-dependencies]\ncc = \"1\"\n");
        assert_eq!(manifest_rules(&build_deps, false), vec![Rule::DomainBuildTime]);
        assert_eq!(manifest_rules(DOMAIN_HEADER, true), vec![Rule::DomainBuildTime]);
        let custom = DOMAIN_HEADER.replace("name = \"custody\"", "name = \"custody\"\nbuild = \"gen.rs\"");
        assert_eq!(manifest_rules(&custom, false), vec![Rule::DomainBuildTime]);
    }

    #[test]
    fn unparsable_files_fail_closed() {
        assert_eq!(rules_in("fn broken( {", Ring::Core), vec![Rule::Unparsable]);
        assert_eq!(manifest_rules("[package", false), vec![Rule::Unparsable]);
    }
}
