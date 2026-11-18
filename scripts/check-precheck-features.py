"""Check optional prechecks independently so workspace feature unification cannot hide bugs."""
from pathlib import Path
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
METADATA = json.loads(subprocess.run(
    ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
    cwd=ROOT, check=True, text=True, encoding="utf-8", capture_output=True,
).stdout)
PACKAGE_FEATURES = {package["name"]: package["features"] for package in METADATA["packages"]}
# Public builtin features select vendors; underscore-prefixed features are internal capabilities.
BUILTIN_FEATURES = tuple(sorted(
    feature for feature in PACKAGE_FEATURES["aster_acme_dns_builtin"]
    if feature != "default" and not feature.startswith("_")
))
CLI_FEATURES = tuple(sorted(
    feature for feature in PACKAGE_FEATURES["aster_acme_cli"] if feature.startswith("dns-")
))
CASES = [
    ("aster_acme", None),
    ("aster_acme", "precheck"),
    ("aster_acme", "precheck-http"),
    ("aster_acme_validation", None),
    ("aster_acme_validation", "dns01"),
    ("aster_acme_validation", "precheck-caa"),
    ("aster_acme_validation", "precheck-dns"),
    ("aster_acme_cli", None),
    *(("aster_acme_cli", feature) for feature in CLI_FEATURES),
    ("aster_acme_dns_builtin", None),
    *(("aster_acme_dns_builtin", feature) for feature in BUILTIN_FEATURES),
]


def main():
    for package, feature in CASES:
        command = ["cargo", "check", "-p", package, "--no-default-features", "--all-targets", "--locked"]
        if feature:
            command += ["--features", feature]
        subprocess.run(command, cwd=ROOT, check=True)
    for feature in [None, "dns01", "precheck-caa", "precheck-dns"]:
        command = ["cargo", "test", "-p", "aster_acme_validation", "--no-default-features", "--locked", "--lib"]
        if feature:
            command += ["--features", feature]
        subprocess.run(command, cwd=ROOT, check=True)
    for package in ("aster_acme", "aster_acme_validation"):
        tree = subprocess.run(
            ["cargo", "tree", "-p", package, "--no-default-features", "--locked", "--edges", "normal", "--prefix", "none", "--format", "{p}"],
            cwd=ROOT, check=True, text=True, encoding="utf-8", capture_output=True,
        ).stdout
        if any(line.split()[0] == "hickory-resolver" for line in tree.splitlines()):
            raise SystemExit(f"{package}: disabled prechecks must not include the DNS resolver")
        if package == "aster_acme_validation" and any(
            line.split()[0] in {"tokio", "tokio-util"} for line in tree.splitlines()
        ):
            raise SystemExit("validation: disabled features must not include an async runtime")
    for feature in [None, *BUILTIN_FEATURES]:
        command = ["cargo", "test", "-p", "aster_acme_dns_builtin", "--no-default-features", "--locked", "--lib"]
        if feature:
            command += ["--features", feature]
        subprocess.run(command, cwd=ROOT, check=True)
    for feature in [None, *CLI_FEATURES]:
        command = ["cargo", "test", "-p", "aster_acme_cli", "--no-default-features", "--locked", "commands::provider::tests::builtin::backend_inventory"]
        if feature:
            command += ["--features", feature]
        subprocess.run(command, cwd=ROOT, check=True)
    for features in [[], ["--all-features"]]:
        tree = subprocess.run(
            ["cargo", "tree", "-p", "aster_acme_dns_builtin", "--no-default-features", "--locked", "--edges", "normal", "--prefix", "none", "--format", "{p}", *features],
            cwd=ROOT, check=True, text=True, encoding="utf-8", capture_output=True,
        ).stdout
        if any(line.split()[0] in {"reqwest", "aster_forge_http"} for line in tree.splitlines()):
            raise SystemExit("builtin provider state machines must not acquire an HTTP client dependency")
    print("Optional precheck/provider features: all configurations compile; disabled libraries exclude Hickory and empty validation excludes Tokio; CLI resolver supports external DNS independently")


if __name__ == "__main__":
    main()
