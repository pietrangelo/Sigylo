//! Rules on domain source files.

use std::path::Path;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, ItemExternCrate, Macro, Meta, Path as SynPath, UseTree};

use crate::{Rule, Violation};

/// The two rings of a domain crate, innermost first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ring {
    Core,
    Application,
}

impl Ring {
    /// Top-level modules a path starting with `crate::` may enter from this ring.
    fn reachable(self) -> &'static [&'static str] {
        match self {
            Ring::Core => &["core"],
            Ring::Application => &["core", "application"],
        }
    }
}

/// `std` modules that reach the outside world or the clock.
const IMPURE_STD: &[&str] = &["fs", "net", "io", "process", "env", "thread", "time", "os", "path"];
/// Macros that read files or the environment at compile time.
const COMPILE_TIME_IO: &[&str] = &["include", "include_str", "include_bytes", "env", "option_env"];
/// Macros that write to stdout or stderr: I/O, and the shortest way to leak a key.
const CONSOLE_IO: &[&str] = &["print", "println", "eprint", "eprintln", "dbg"];

/// Check a file of the `core` or `application` ring.
pub fn check_source(file: &Path, text: &str, ring: Ring) -> Vec<Violation> {
    let mut checker = Checker { file, ring: Some(ring), violations: Vec::new() };
    match syn::parse_file(text) {
        Ok(ast) => checker.visit_file(&ast),
        Err(e) => checker.push(Rule::Unparsable, e.to_string()),
    }
    checker.violations
}

/// Check a domain's `lib.rs`: it must forbid unsafe code, declare only the
/// two rings as modules, and obey the same purity rules.
pub fn check_lib_root(file: &Path, text: &str) -> Vec<Violation> {
    let mut checker = Checker { file, ring: None, violations: Vec::new() };
    let ast = match syn::parse_file(text) {
        Ok(ast) => ast,
        Err(e) => {
            checker.push(Rule::Unparsable, e.to_string());
            return checker.violations;
        }
    };
    let forbids_unsafe = ast.attrs.iter().any(|a| {
        a.path().is_ident("forbid") && a.meta.require_list().is_ok_and(|l| l.tokens.to_string() == "unsafe_code")
    });
    if !forbids_unsafe {
        checker.push(Rule::MissingForbidUnsafe, "lib.rs must start with #![forbid(unsafe_code)]".into());
    }
    for item in &ast.items {
        if let syn::Item::Mod(m) = item {
            let name = m.ident.to_string();
            if m.content.is_some() || (name != "core" && name != "application") {
                checker.push(
                    Rule::RingLayout,
                    format!("lib.rs may only declare `mod core;` and `mod application;`, found `{name}`"),
                );
            }
        }
    }
    checker.visit_file(&ast);
    checker.violations
}

struct Checker<'a> {
    file: &'a Path,
    /// `None` for lib.rs, which may re-export from both rings.
    ring: Option<Ring>,
    violations: Vec<Violation>,
}

impl Checker<'_> {
    fn push(&mut self, rule: Rule, detail: String) {
        self.violations.push(Violation { file: self.file.to_path_buf(), rule, detail });
    }

    /// Judge a path given as its segments (leading `::` already stripped).
    fn check_segments(&mut self, segments: &[String]) {
        let Some(first) = segments.first() else { return };
        if first == "std"
            && let Some(module) = segments.get(1).filter(|m| IMPURE_STD.contains(&m.as_str()))
        {
            self.push(Rule::ImpureStd, format!("`std::{module}` is not allowed in a domain"));
        }
        if let Some(ring) = self.ring {
            if first == "crate"
                && let Some(next) = segments.get(1).filter(|n| !ring.reachable().contains(&n.as_str()))
            {
                self.push(Rule::RingDirection, format!("{ring:?} ring may not reach `crate::{next}`"));
            }
            if ring == Ring::Core && first == "super" && segments.iter().any(|s| s == "application") {
                self.push(Rule::RingDirection, "core ring may not reach the application ring".into());
            }
        }
    }

    fn check_use_tree(&mut self, prefix: &mut Vec<String>, tree: &UseTree) {
        match tree {
            UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.check_use_tree(prefix, &p.tree);
                prefix.pop();
            }
            UseTree::Name(n) => {
                let mut full = prefix.clone();
                if n.ident != "self" {
                    full.push(n.ident.to_string());
                }
                self.check_segments(&full);
            }
            UseTree::Rename(r) => {
                let mut full = prefix.clone();
                if r.ident != "self" {
                    full.push(r.ident.to_string());
                }
                if full == ["std"] {
                    self.push(Rule::StdAlias, format!("`std` renamed to `{}`", r.rename));
                }
                self.check_segments(&full);
            }
            UseTree::Glob(_) => {
                if prefix.as_slice() == ["std"] {
                    self.push(Rule::StdAlias, "glob import of `std`".into());
                }
                self.check_segments(prefix);
            }
            UseTree::Group(g) => {
                for item in &g.items {
                    self.check_use_tree(prefix, item);
                }
            }
        }
    }

    /// Macro bodies are not parsed as paths, so scan their tokens for
    /// `std :: <impure>` and `crate :: <outer ring>` sequences.
    fn check_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (i, tree) in trees.iter().enumerate() {
            if let TokenTree::Group(group) = tree {
                self.check_tokens(group.stream());
                continue;
            }
            let TokenTree::Ident(first) = tree else { continue };
            let is_path_sep = |j: usize| matches!((trees.get(j), trees.get(j + 1)), (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b))) if a.as_char() == ':' && b.as_char() == ':');
            if is_path_sep(i + 1)
                && let Some(TokenTree::Ident(second)) = trees.get(i + 3)
            {
                self.check_segments(&[first.to_string(), second.to_string()]);
            }
        }
    }

    fn check_attributes(&mut self, attrs: &[Attribute]) {
        for attr in attrs {
            let hides_path = match &attr.meta {
                Meta::NameValue(nv) => nv.path.is_ident("path"),
                Meta::List(list) if list.path.is_ident("cfg_attr") => {
                    list.tokens.clone().into_iter().any(|t| matches!(t, TokenTree::Ident(i) if i == "path"))
                }
                _ => false,
            };
            if hides_path {
                self.push(Rule::PathAttribute, "#[path] is not allowed in a domain".into());
            }
        }
    }
}

impl<'ast> Visit<'ast> for Checker<'_> {
    fn visit_use_tree(&mut self, tree: &'ast UseTree) {
        self.check_use_tree(&mut Vec::new(), tree);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.check_segments(&segments);
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if let Some(name) = mac.path.segments.last().map(|s| s.ident.to_string())
            && COMPILE_TIME_IO.contains(&name.as_str())
        {
            self.push(Rule::CompileTimeIo, format!("`{name}!` reads outside the source at compile time"));
        }
        if let Some(name) = mac.path.segments.last().map(|s| s.ident.to_string())
            && CONSOLE_IO.contains(&name.as_str())
        {
            self.push(Rule::ConsoleIo, format!("`{name}!` writes to the console from a domain"));
        }
        self.check_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        if item.ident == "std" && item.rename.is_some() {
            self.push(Rule::StdAlias, "`extern crate std as …`".into());
        }
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        self.check_attributes(std::slice::from_ref(attr));
        visit::visit_attribute(self, attr);
    }
}
