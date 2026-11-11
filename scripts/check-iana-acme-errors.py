"""Check ProblemKind against the live IANA ACME Error Types registry."""
import csv
from io import StringIO
from pathlib import Path
import re
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_URL = "https://www.iana.org/assignments/acme/acme-error-types.csv"
SOURCE = ROOT / "crates/aster_acme_protocol/src/problem.rs"
TIMEOUT_SECONDS = 30


def problem_kinds(source: str) -> set[str]:
    marker = "pub enum ProblemKind {"
    start = source.find(marker)
    if start < 0:
        raise ValueError("ProblemKind wire enum was not found")
    start = source.index("{", start) + 1
    depth = 1
    end = start
    while depth and end < len(source):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    if depth:
        raise ValueError("ProblemKind wire enum has unbalanced braces")
    return set(re.findall(r'=>\s*"urn:ietf:params:acme:error:([A-Za-z0-9-]+)"', source[start : end - 1]))


def registry_types(csv_text: str) -> set[str]:
    rows = csv.DictReader(StringIO(csv_text))
    if not rows.fieldnames or "Type" not in rows.fieldnames:
        raise ValueError("IANA ACME Error Types CSV has no Type column")
    values = [row["Type"].strip() for row in rows if row.get("Type", "").strip()]
    duplicates = {value for value in values if values.count(value) > 1}
    if duplicates:
        raise ValueError(f"IANA CSV contains duplicate types: {', '.join(sorted(duplicates))}")
    return set(values)


def download_registry() -> str:
    request = Request(REGISTRY_URL, headers={"User-Agent": "AsterACME-IANA-registry-check/1"})
    with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8-sig")


def compare(source: str, csv_text: str) -> tuple[set[str], set[str]]:
    registered = registry_types(csv_text)
    implemented = problem_kinds(source)
    if not implemented:
        raise ValueError("ProblemKind contains no IANA mappings")
    return registered - implemented, implemented - registered


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    missing, stale = compare(source, download_registry())
    if missing or stale:
        lines = ["IANA ACME Error Types and ProblemKind differ."]
        if missing:
            lines.append("Missing ProblemKind mappings: " + ", ".join(sorted(missing)))
        if stale:
            lines.append("No longer IANA-registered: " + ", ".join(sorted(stale)))
        lines.append("Review the RFC/draft and diagnostics before accepting registry drift.")
        raise SystemExit("\n".join(lines))
    print(f"IANA ACME Error Types: {len(problem_kinds(source))} registered types match ProblemKind")


if __name__ == "__main__":
    main()
