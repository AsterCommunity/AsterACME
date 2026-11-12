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

fn watch_repository(root: &Path, repository: Option<&str>) {
    if let Some(top) = repository {
        for args in [
            ["rev-parse", "--git-path", "HEAD"],
            ["rev-parse", "--git-path", "index"],
            ["rev-parse", "--git-path", "packed-refs"],
            ["rev-parse", "--git-path", "logs/HEAD"],
        ] {
            if let Some(path) = git(root, &args) {
                let path = root.join(path);
                if path.exists() {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
        if let Some(branch) = git(root, &["symbolic-ref", "-q", "HEAD"])
            && let Some(path) = git(root, &["rev-parse", "--git-path", &branch])
        {
            let path = root.join(path);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
        if let Some(files) = git(Path::new(top), &["ls-files"]) {
            for file in files.lines() {
                println!(
                    "cargo:rerun-if-changed={}",
                    Path::new(top).join(file).display()
                );
            }
        }
    }
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
    let repository = git(root, &["rev-parse", "--show-toplevel"]).filter(|top| {
        git(
            Path::new(top),
            &[
                "ls-files",
                "--error-unmatch",
                "crates/aster_acme_cli/build.rs",
            ],
        )
        .is_some()
            && root.canonicalize().ok()
                == Path::new(top)
                    .join("crates/aster_acme_cli")
                    .canonicalize()
                    .ok()
    });
    watch_repository(root, repository.as_deref());
    let revision = match env::var("ASTER_BUILD_REVISION") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => repository
            .as_ref()
            .and_then(|_| git(root, &["rev-parse", "HEAD"]))
            .unwrap_or_else(|| "unknown".into()),
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
    let dirty = match repository
        .as_ref()
        .and_then(|_| git(root, &["status", "--porcelain", "--untracked-files=no"]))
    {
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
