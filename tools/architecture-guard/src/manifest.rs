//! Rules on `Cargo.toml`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use toml::{Table, Value};

use crate::{DOMAIN_ALLOWED_DEPENDENCIES, Rule, Violation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Domain,
    Adapters,
    Shell,
    Tool,
}

impl Role {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "domain" => Some(Self::Domain),
            "adapters" => Some(Self::Adapters),
            "shell" => Some(Self::Shell),
            "tool" => Some(Self::Tool),
            _ => None,
        }
    }
}

fn package_name(table: &Table) -> Option<&str> {
    table.get("package")?.get("name")?.as_str()
}

fn role(table: &Table) -> Option<Role> {
    Role::parse(table.get("package")?.get("metadata")?.get("rosette")?.get("role")?.as_str()?)
}

/// Package name → role, for every member manifest that parses.
pub(crate) fn roles(manifests: &[(PathBuf, String)]) -> HashMap<String, Role> {
    manifests
        .iter()
        .filter_map(|(_, text)| text.parse::<Table>().ok())
        .filter_map(|t| Some((package_name(&t)?.to_string(), role(&t)?)))
        .collect()
}

/// The real package names a dependency table pulls in, honouring
/// `package = "…"` renames, also when they hide in `[workspace.dependencies]`.
fn dependency_packages(table: Option<&Value>, workspace: &Table) -> Vec<String> {
    let Some(Value::Table(deps)) = table else { return Vec::new() };
    deps.iter()
        .map(|(key, spec)| {
            let inherited = spec.get("workspace").and_then(Value::as_bool) == Some(true);
            let spec = if inherited { workspace.get(key).unwrap_or(spec) } else { spec };
            spec.get("package").and_then(Value::as_str).unwrap_or(key).to_string()
        })
        .collect()
}

/// Check one manifest. Returns the declared role and the violations found.
pub fn check_manifest(
    file: &Path,
    text: &str,
    roles: &HashMap<String, Role>,
    has_build_rs: bool,
    workspace_dependencies: &Table,
) -> (Option<Role>, Vec<Violation>) {
    let violation = |rule, detail: String| Violation { file: file.to_path_buf(), rule, detail };
    let table: Table = match text.parse() {
        Ok(t) => t,
        Err(e) => return (None, vec![violation(Rule::Unparsable, e.to_string())]),
    };
    let Some(role) = role(&table) else {
        return (None, vec![violation(Rule::UndeclaredRole, "missing [package.metadata.rosette] role".into())]);
    };
    let mut violations = Vec::new();
    let deps = dependency_packages(table.get("dependencies"), workspace_dependencies);

    match role {
        Role::Domain => {
            for dep in &deps {
                let allowed =
                    DOMAIN_ALLOWED_DEPENDENCIES.contains(&dep.as_str()) || roles.get(dep) == Some(&Role::Domain);
                if !allowed {
                    violations.push(violation(Rule::DomainDependency, format!("domain depends on `{dep}`")));
                }
            }
            if !dependency_packages(table.get("build-dependencies"), workspace_dependencies).is_empty() {
                violations.push(violation(Rule::DomainBuildTime, "domain has build-dependencies".into()));
            }
            if table.get("target").is_some() {
                violations.push(violation(Rule::DomainBuildTime, "domain has target-specific dependencies".into()));
            }
            if has_build_rs || table.get("package").and_then(|p| p.get("build")).is_some() {
                violations.push(violation(Rule::DomainBuildTime, "domain has a build script".into()));
            }
        }
        Role::Adapters => {
            let all_deps = deps
                .iter()
                .chain(target_dependency_packages(&table, workspace_dependencies).iter())
                .cloned()
                .collect::<Vec<_>>();
            for dep in all_deps {
                if matches!(roles.get(&dep), Some(Role::Adapters | Role::Shell)) {
                    violations.push(violation(Rule::AdapterDependency, format!("adapters crate depends on `{dep}`")));
                }
            }
        }
        Role::Shell | Role::Tool => {}
    }
    (Some(role), violations)
}

fn target_dependency_packages(table: &Table, workspace: &Table) -> Vec<String> {
    let Some(Value::Table(targets)) = table.get("target") else { return Vec::new() };
    targets.values().flat_map(|t| dependency_packages(t.get("dependencies"), workspace)).collect()
}
