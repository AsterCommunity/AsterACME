"""Enforce rustls across all production targets without mistaking root discovery for TLS."""
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parents[1]
# Audit all resolved packages, including foreign targets and tests, without fetching
# dependencies for platforms that the current runner does not build.
packages = {package["name"] for package in tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))["package"]}
forbidden = packages & {
    "native-tls", "tokio-native-tls", "hyper-tls", "openssl", "openssl-sys",
}
if forbidden:
    raise SystemExit("Non-rustls TLS dependencies enabled: " + ", ".join(sorted(forbidden)))
if "rustls" not in packages or "aws-lc-rs" not in packages:
    raise SystemExit("Expected rustls with the shared AWS-LC backend")
print("TLS backend policy: rustls + AWS-LC; no native-tls/OpenSSL transport")
