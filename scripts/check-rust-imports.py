"""Keep internal Rust imports anchored at the crate root."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
relative_import = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+super\s*::", re.MULTILINE)
errors = []
for path in sorted((root / "crates").rglob("*.rs")):
    text = path.read_text(encoding="utf-8")
    for match in relative_import.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        errors.append(f"{path.relative_to(root)}:{line}: use crate:: paths instead of use super")
if errors:
    raise SystemExit("\n".join(errors))
print("Rust import ownership policy: OK")
