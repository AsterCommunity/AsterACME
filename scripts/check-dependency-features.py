"""Audit Cargo's resolved production features, including transitive feature unification."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
# Intentional allowlists: adding a dependency or changing a transitive feature must
# not silently install a second TLS/crypto backend or unused HTTP/UI capabilities.
ALLOWED = {
    "process-wrap": {"tokio1", "process-group", "job-object", "kill-on-drop"},
    "hyper": {"default", "client", "http1", "server"},
    "hyper-util": {"default", "client", "client-legacy", "client-proxy", "client-proxy-system", "http1", "tokio"},
    "http-body-util": {"default"},
    "aster_forge_http": {"json", "rustls", "rustls-aws-lc-rs", "system-proxy"},
    "aster_forge_panic": set(),
    "reqwest": {"__rustls", "__rustls-aws-lc-rs", "__tls", "json", "rustls", "rustls-no-provider", "system-proxy"},
    "rustls": {"aws-lc-rs", "aws_lc_rs", "std", "tls12"},
    "tokio-rustls": {"aws-lc-rs", "aws_lc_rs", "tls12"},
    "rcgen": {"crypto", "aws_lc_rs", "pem"},
    "inquire": {"crossterm", "fuzzy", "fuzzy-matcher"},
    "tracing-subscriber": {"alloc", "ansi", "env-filter", "fmt", "matchers", "nu-ansi-term", "once_cell", "registry", "sharded-slab", "std", "thread_local", "tracing"},
}
FORBIDDEN = {"native-tls", "tokio-native-tls", "hyper-tls", "openssl", "openssl-sys", "ring", "aster-fs", "fs2", "fs4"}


def audit(tree):
    errors = set()
    for line in tree.splitlines():
        package, separator, features = line.partition("|")
        if not separator:
            continue
        name = package.split()[0]
        if name in FORBIDDEN:
            errors.add(f"Forbidden production dependency: {name}")
        if name in ALLOWED:
            enabled = set(features.removesuffix(" (*)").split(",")) - {""}
            extra = enabled - ALLOWED[name]
            if extra:
                errors.add(f"{name}: forbidden/unreviewed features: {', '.join(sorted(extra))}")
    return sorted(errors)


def main():
    tree = subprocess.run(
        ["cargo", "tree", "--workspace", "--locked", "--edges", "normal,build", "--prefix", "none", "--format", "{p}|{f}"],
        cwd=ROOT, check=True, text=True, encoding="utf-8", capture_output=True,
    ).stdout
    errors = audit(tree)
    if errors:
        raise SystemExit("\n".join(errors))
    print("Production feature policy: reviewed HTTP/TLS/crypto/UI/logging features only")


if __name__ == "__main__":
    main()
