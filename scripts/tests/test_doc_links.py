"""Local documentation references must follow their owning page after moves."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("doc_links", Path(__file__).resolve().parents[1] / "check-doc-links.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class DocumentationLinks(unittest.TestCase):
    def test_relative_paths_escaped_names_and_remote_or_code_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "子目录").mkdir()
            (root / "a b.md").write_text("target", encoding="utf-8")
            page = root / "子目录" / "index.md"
            page.write_text('[ok](../a%20b.md#section) [missing](missing.md) [web](https://example.com/x) [anchor](#section)\n```md\n[example](fake.md)\n```\n<img src="../a%20b.md">', encoding="utf-8")
            self.assertEqual(policy.missing_links(page), ["missing.md"])


if __name__ == "__main__":
    unittest.main()
