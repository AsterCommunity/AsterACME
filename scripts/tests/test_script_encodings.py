"""CI checks must read repository and Cargo output as strict UTF-8 on every host."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
READ_TEXT = Path.read_text


def cp1252_default(path, encoding=None, errors=None, **kwargs):
    """Emulate a Windows locale without changing process-wide locale or UTF-8 mode."""
    return READ_TEXT(path, encoding=encoding or "cp1252", errors=errors, **kwargs)


class ScriptEncodings(unittest.TestCase):
    def run_policy(self, name, rust_source="// 保留中文注释。\nuse crate::module;\n"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            script = scripts / name
            script.write_text((SCRIPTS / name).read_text(encoding="utf-8"), encoding="utf-8")
            source = root / "crates" / "example" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_bytes(rust_source.encode("utf-8") if isinstance(rust_source, str) else rust_source)
            (source.parent / "Cargo.toml").write_text(
                '# 保留中文注释。\n[package]\nname = "example"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                '# 保留中文注释。\n[[package]]\nname = "rustls"\n[[package]]\nname = "aws-lc-rs"\n',
                encoding="utf-8",
            )
            output = io.StringIO()
            with patch.object(Path, "read_text", cp1252_default), redirect_stdout(output):
                runpy.run_path(str(script), run_name="__main__")
            return output.getvalue()

    def test_repository_checks_accept_utf8_even_when_default_encoding_is_cp1252(self):
        for name in ["check-rust-imports.py", "check-workspace-deps.py", "check-tls-backend.py"]:
            with self.subTest(script=name):
                self.assertTrue(self.run_policy(name).strip())

    def test_non_ascii_comments_do_not_hide_invalid_imports_or_change_line_numbers(self):
        with self.assertRaisesRegex(SystemExit, r"lib\.rs:2: use crate:: paths instead of use super"):
            self.run_policy("check-rust-imports.py", "// 保留中文注释。\nuse super::module;\n")

    def test_invalid_utf8_is_rejected_instead_of_silently_replaced(self):
        with self.assertRaises(UnicodeDecodeError):
            self.run_policy("check-rust-imports.py", b"// invalid UTF-8: \xff\n")

    def test_cargo_output_is_decoded_as_utf8_independently_of_locale(self):
        spec = importlib.util.spec_from_file_location("encoding_features", SCRIPTS / "check-dependency-features.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        encoded = "other v1.0.0 (/workspace/保留)|default\n".encode("utf-8")

        def cargo_output(*args, **kwargs):
            return SimpleNamespace(stdout=encoded.decode(kwargs.get("encoding", "cp1252")))

        with patch.object(policy.subprocess, "run", side_effect=cargo_output) as cargo, redirect_stdout(io.StringIO()):
            policy.main()
        self.assertEqual(cargo.call_args.kwargs["encoding"], "utf-8")
        self.assertTrue(cargo.call_args.kwargs["check"])
        self.assertTrue(cargo.call_args.kwargs["capture_output"])


if __name__ == "__main__":
    unittest.main()
