//! Capture build identity without runtime Git access; archive builds report unknown revision.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::unreachable,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo
    )
)]

use std::{env, io, path::Path, process::Command};

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
        .map(|value| value.trim().to_owned())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = env::var("CARGO_MANIFEST_DIR")?;
    let root = Path::new(&manifest);
    for name in [
        "ASTER_BUILD_REVISION",
        "ASTER_BUILD_TIME",
        "SOURCE_DATE_EPOCH",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    // Watch actual source/index/HEAD paths, never target/, so rebuild metadata stays
    // accurate without rebuilding solely because Cargo produced another artifact.
    if let Some(top) = git(root, &["rev-parse", "--show-toplevel"]) {
        for args in [
            ["rev-parse", "--git-path", "HEAD"],
            ["rev-parse", "--git-path", "index"],
        ] {
            if let Some(path) = git(root, &args) {
                println!("cargo:rerun-if-changed={}", root.join(path).display());
            }
        }
        if let Some(branch) = git(root, &["symbolic-ref", "-q", "HEAD"])
            && let Some(path) = git(root, &["rev-parse", "--git-path", &branch])
        {
            println!("cargo:rerun-if-changed={}", root.join(path).display());
        }
        if let Some(files) = git(Path::new(&top), &["ls-files", "-co", "--exclude-standard"]) {
            for file in files.lines() {
                println!(
                    "cargo:rerun-if-changed={}",
                    Path::new(&top).join(file).display()
                );
            }
        }
    }
    let revision = match env::var("ASTER_BUILD_REVISION") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => {
            git(root, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into())
        }
        Err(error) => return Err(error.into()),
    };
    if revision != "unknown"
        && (!(7..=64).contains(&revision.len())
            || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(io::Error::other(
            "ASTER_BUILD_REVISION must be unknown or a 7–64 character hexadecimal revision",
        )
        .into());
    }
    let dirty = match git(root, &["status", "--porcelain", "--untracked-files=normal"]) {
        Some(status) if status.is_empty() => "false",
        Some(_) => "true",
        None => "unknown",
    };
    let built = match env::var("ASTER_BUILD_TIME") {
        Ok(value) => {
            time::OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)?;
            value
        }
        Err(env::VarError::NotPresent) => {
            let instant = match env::var("SOURCE_DATE_EPOCH") {
                Ok(value) => time::OffsetDateTime::from_unix_timestamp(value.parse()?)?,
                Err(env::VarError::NotPresent) => time::OffsetDateTime::now_utc(),
                Err(error) => return Err(error.into()),
            };
            instant.format(&time::format_description::well_known::Rfc3339)?
        }
        Err(error) => return Err(error.into()),
    };
    let mut features: Vec<_> = env::vars()
        .filter_map(|(key, _)| {
            key.strip_prefix("CARGO_FEATURE_")
                .map(|feature| feature.to_ascii_lowercase().replace('_', "-"))
        })
        .collect();
    features.sort();
    for (key, value) in [
        ("REVISION", revision),
        ("DIRTY", dirty.to_owned()),
        ("TARGET", env::var("TARGET")?),
        ("PROFILE", env::var("PROFILE")?),
        ("FEATURES", features.join(",")),
        ("TIME", built),
    ] {
        println!("cargo:rustc-env=ASTER_BUILD_{key}={value}");
    }
    Ok(())
}
