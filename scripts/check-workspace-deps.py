"""Enforce root-owned dependency versions, sources, and features."""
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parents[1]
errors = []


def check(table, path):
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in table.get(section, {}).items():
            if spec != {"workspace": True}:
                errors.append(f"{path}: {section}.{name} must only set workspace = true")
    for target in table.get("target", {}).values():
        check(target, path)


for path in sorted((root / "crates").glob("*/Cargo.toml")):
    manifest = tomllib.loads(path.read_text())
    if not isinstance(manifest.get("package", {}).get("version"), str):
        errors.append(f"{path.relative_to(root)}: package.version must be explicit per crate")
    check(manifest, path.relative_to(root))
if errors:
    raise SystemExit("\n".join(errors))
print("Workspace dependency policy: OK")
