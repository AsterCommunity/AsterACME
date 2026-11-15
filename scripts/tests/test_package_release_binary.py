import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "package-release-binary.py"
SPEC = importlib.util.spec_from_file_location("package_release_binary", SCRIPT)
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class PackageReleaseBinary(unittest.TestCase):
    def test_macos_preserves_symbols_and_records_uuid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "aster-acme"
            artifacts = root / "artifacts"
            binary.write_bytes(b"binary")

            with patch.object(POLICY, "run", return_value="UUID 123\n") as run, patch.object(
                POLICY.subprocess, "run"
            ) as command:
                artifact = POLICY.package(binary, artifacts, "Darwin")

            self.assertEqual(artifact.read_bytes(), b"binary")
            self.assertEqual((artifacts / "aster-acme.uuid").read_text(encoding="utf-8"), "UUID 123\n")
            command.assert_called_once_with(["strip", str(binary)], check=True)
            run.assert_called_once_with(["dwarfdump", "--uuid", str(binary), str(artifact)])

    def test_linux_keeps_debug_data_and_links_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "aster-acme"
            artifacts = root / "artifacts"
            binary.write_bytes(b"binary")

            with patch.object(POLICY.subprocess, "run") as command:
                artifact = POLICY.package(binary, artifacts, "Linux")

            self.assertEqual(artifact, artifacts / "aster-acme.debug")
            self.assertEqual(command.call_args_list, [
                unittest.mock.call(
                    ["objcopy", "--only-keep-debug", str(binary), str(artifact)], check=True
                ),
                unittest.mock.call(["strip", "--strip-all", str(binary)], check=True),
                unittest.mock.call(
                    ["objcopy", f"--add-gnu-debuglink={artifact}", str(binary)], check=True
                ),
            ])

    def test_windows_requires_an_explicit_pdb_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "aster-acme.exe"
            binary.write_bytes(b"binary")

            with self.assertRaisesRegex(SystemExit, "PDB"):
                POLICY.package(binary, root / "artifacts", "Windows")


if __name__ == "__main__":
    unittest.main()
