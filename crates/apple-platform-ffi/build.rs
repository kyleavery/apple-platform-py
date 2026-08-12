//! Stamp upstream provenance (crate versions, git commit/describe) and build
//! metadata into rustc-env vars surfaced by `apple_platform_versions`.
//!
//! Must never fail the build: sdist builds have the submodule *files* but no
//! git metadata, so all git-derived values degrade to "unknown".

use std::path::{Path, PathBuf};
use std::process::Command;

const UPSTREAM_CRATES: &[(&str, &str)] = &[
    ("apple-codesign", "APPLE_CODESIGN"),
    ("apple-bundles", "APPLE_BUNDLES"),
    ("apple-dmg", "APPLE_DMG"),
    ("apple-flat-package", "APPLE_FLAT_PACKAGE"),
];

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let upstream = manifest_dir.join("../apple-platform-rs");

    println!(
        "cargo:rustc-env=APPLE_PLATFORM_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=APPLE_PLATFORM_PROFILE={}",
        std::env::var("PROFILE").unwrap_or_default()
    );

    for (crate_name, env_suffix) in UPSTREAM_CRATES {
        let toml = upstream.join(crate_name).join("Cargo.toml");
        println!("cargo:rerun-if-changed={}", toml.display());
        let version = package_version(&toml).unwrap_or_else(|| "unknown".to_string());
        println!("cargo:rustc-env=APPLE_PLATFORM_UPSTREAM_{env_suffix}={version}");
    }

    let commit = git(&upstream, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let describe =
        git(&upstream, &["describe", "--tags", "--always"]).unwrap_or_else(|| commit.clone());
    println!("cargo:rustc-env=APPLE_PLATFORM_UPSTREAM_COMMIT={commit}");
    println!("cargo:rustc-env=APPLE_PLATFORM_UPSTREAM_DESCRIBE={describe}");

    // Rebuild when the submodule pin moves. For submodules, `.git` is a file
    // pointing into the superproject's .git/modules; watching it catches
    // checkouts. Absent (sdist), there is nothing to watch.
    let git_link = upstream.join(".git");
    if git_link.exists() {
        println!("cargo:rerun-if-changed={}", git_link.display());
    }
}

/// `version = "..."` from a Cargo.toml `[package]` section. Line-based on
/// purpose: no TOML parser dependency, and upstream's manifests are rustfmt'd.
fn package_version(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = line.strip_prefix("version") {
            let rest = rest.trim_start();
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}
