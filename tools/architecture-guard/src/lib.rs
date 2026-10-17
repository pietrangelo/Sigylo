//! # Architecture guard
//!
//! Sigylo is a rosette: each bounded context is a pure **domain** crate with
//! two rings, `core` (value objects, deterministic) inside `application`
//! (use cases and ports). Everything that touches the world lives in
//! separate **adapters** crates, and **shells** (Wasm, Worker) only wire.
//! This tool makes CI fail when the code drifts from that shape.
//!
//! Every workspace member declares its role:
//!
//! ```toml
//! [package.metadata.rosette]
//! role = "domain" # or "adapters", "shell", "tool"
//! ```
//!
//! A crate excluded from the workspace (the Tauri app, which needs the
//! system webview) is checked too, and may only be a shell or a tool.

mod manifest;
mod source;

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub use manifest::{Role, check_manifest};
pub use source::{Ring, check_lib_root, check_source};

/// Crates a domain may depend on besides other domains.
pub const DOMAIN_ALLOWED_DEPENDENCIES: &[&str] = &["zeroize"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// A member without `[package.metadata.rosette] role`.
    UndeclaredRole,
    /// A domain depends on something outside the allow-list.
    DomainDependency,
    /// A domain has target-specific or build dependencies, or a build script.
    DomainBuildTime,
    /// An adapters crate depends on another adapters crate or a shell.
    AdapterDependency,
    /// A domain's `lib.rs` lacks `#![forbid(unsafe_code)]`.
    MissingForbidUnsafe,
    /// A domain file sits outside `lib.rs`, `core/` and `application/`.
    RingLayout,
    /// An inner ring reaches outward (core → application, or anything → crate root items).
    RingDirection,
    /// I/O, environment, clock or threads from `std` inside a domain.
    ImpureStd,
    /// `std` renamed or glob-imported, which would hide impure paths.
    StdAlias,
    /// Compile-time I/O macros (`include!`, `env!`, …) inside a domain.
    CompileTimeIo,
    /// Console output (`println!`, `dbg!`, …) inside a domain.
    ConsoleIo,
    /// `#[path]` attributes that could pull files from outside the ring.
    PathAttribute,
    /// A domain or adapters crate excluded from the workspace, out of the guard's reach.
    ExcludedCrate,
    /// A source file that does not parse.
    Unparsable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub file: PathBuf,
    pub rule: Rule,
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}: {}", self.file.display(), self.rule, self.detail)
    }
}

/// Check every member of the workspace rooted at `root`.
pub fn check_workspace(root: &Path) -> std::io::Result<Vec<Violation>> {
    let workspace: toml::Table =
        read(&root.join("Cargo.toml"))?.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let members: Vec<String> = workspace
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .map(|m| m.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let excluded: Vec<String> = workspace
        .get("workspace")
        .and_then(|w| w.get("exclude"))
        .and_then(|m| m.as_array())
        .map(|m| m.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut manifests = Vec::new();
    for member in &members {
        let dir = root.join(member);
        let manifest = read(&dir.join("Cargo.toml"))?;
        manifests.push((dir, manifest));
    }
    let mut outside = Vec::new();
    for path in &excluded {
        let dir = root.join(path);
        if dir.join("Cargo.toml").is_file() {
            let manifest = read(&dir.join("Cargo.toml"))?;
            outside.push((dir, manifest));
        }
    }
    let roles = manifest::roles(&[manifests.as_slice(), outside.as_slice()].concat());
    let workspace_dependencies = workspace
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.as_table())
        .cloned()
        .unwrap_or_default();

    let mut violations = Vec::new();
    for (dir, text) in &manifests {
        let file = dir.join("Cargo.toml");
        let (role, found) = check_manifest(&file, text, &roles, dir.join("build.rs").exists(), &workspace_dependencies);
        violations.extend(found);
        if role == Some(Role::Domain) {
            violations.extend(check_domain_sources(&dir.join("src"))?);
        }
    }
    for (dir, text) in &outside {
        let file = dir.join("Cargo.toml");
        let (role, found) = check_manifest(&file, text, &roles, dir.join("build.rs").exists(), &workspace_dependencies);
        violations.extend(found);
        if matches!(role, Some(Role::Domain | Role::Adapters)) {
            violations.push(Violation {
                file,
                rule: Rule::ExcludedCrate,
                detail: "only shells and tools may live outside the workspace".into(),
            });
        }
    }
    Ok(violations)
}

fn check_domain_sources(src: &Path) -> std::io::Result<Vec<Violation>> {
    let mut violations = Vec::new();
    for file in rust_files(src)? {
        let relative = file.strip_prefix(src).unwrap_or(&file);
        let text = read(&file)?;
        let ring = match relative.components().next().and_then(|c| c.as_os_str().to_str()) {
            Some("lib.rs") => {
                violations.extend(check_lib_root(&file, &text));
                continue;
            }
            Some("core") => Ring::Core,
            Some("application") => Ring::Application,
            _ => {
                violations.push(Violation {
                    file: file.clone(),
                    rule: Rule::RingLayout,
                    detail: "domain code must live in lib.rs, core/ or application/".into(),
                });
                continue;
            }
        };
        violations.extend(check_source(&file, &text, ring));
    }
    Ok(violations)
}

fn rust_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            out.extend(rust_files(&path)?);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn read(path: &Path) -> std::io::Result<String> {
    fs::read_to_string(path).map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}
