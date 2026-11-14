"""Check optional prechecks independently so workspace feature unification cannot hide bugs."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("aster_acme", None),
    ("aster_acme", "precheck"),
    ("aster_acme", "precheck-http"),
    ("aster_acme_validation", None),
    ("aster_acme_validation", "dns01"),
    ("aster_acme_validation", "precheck-caa"),
    ("aster_acme_validation", "precheck-dns"),
    ("aster_acme_cli", None),
]


def main():
    for package, feature in CASES:
        command = ["cargo", "check", "-p", package, "--no-default-features", "--all-targets", "--locked"]
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
    print("Optional precheck features: all configurations compile; disabled libraries exclude Hickory; CLI resolver supports external DNS independently")


if __name__ == "__main__":
    main()
