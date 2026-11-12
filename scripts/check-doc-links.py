"""Check repository-local documentation links without fetching remote resources."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"!?\[[^\]\n]*\]\(<?([^\s)>]+)>?(?:\s+[^)]*)?\)")
HTML_LINK = re.compile(r"\b(?:href|src)=[\"']([^\"']+)[\"']")


def missing_links(path):
    source = path.read_text(encoding="utf-8")
    source = re.sub(r"```.*?```", "", source, flags=re.S)
    targets = [match.group(1) for pattern in (MARKDOWN_LINK, HTML_LINK) for match in pattern.finditer(source)]
    missing = []
    for target in targets:
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        destination = path.parent / unquote(parsed.path)
        if not destination.exists():
            missing.append(target)
    return missing


def main():
    files = [ROOT / "AGENTS.md", ROOT / "README.md", ROOT / "README.zh.md"]
    files.extend(sorted((ROOT / "docs").rglob("*.md")))
    files.extend(sorted((ROOT / "crates").glob("*/README.md")))
    failures = [f"{path.relative_to(ROOT)}: missing local link {target}" for path in files for target in missing_links(path)]
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"Documentation links: {len(files)} files checked")


if __name__ == "__main__":
    main()
