"""Enforce root-owned dependency versions, sources, and features."""
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parents[1]
errors = []


def check(table, path):
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in table.get(section, {}).items():
            # Feature optionality belongs to the consuming crate; versions,
            # sources, default-features and dependency features remain root-owned.
            if (not isinstance(spec, dict) or spec.get("workspace") is not True
                    or not set(spec) <= {"workspace", "optional"}
                    or ("optional" in spec and not isinstance(spec["optional"], bool))):
                errors.append(f"{path}: {section}.{name} must inherit workspace = true (only optional may be set locally)")
    for target in table.get("target", {}).values():
        check(target, path)


def main():
    for path in sorted((root / "crates").glob("*/Cargo.toml")):
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        if not isinstance(manifest.get("package", {}).get("version"), str):
            errors.append(f"{path.relative_to(root)}: package.version must be explicit per crate")
        check(manifest, path.relative_to(root))
    if errors:
        raise SystemExit("\n".join(errors))
    print("Workspace dependency policy: OK")


if __name__ == "__main__":
    main()
