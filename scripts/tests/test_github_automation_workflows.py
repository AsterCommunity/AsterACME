"""Static tests for repository label-writer concurrency and risk coverage."""

import importlib.util
import tempfile
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_github_automation_workflows",
    ROOT / "scripts/check-github-automation-workflows.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class GitHubAutomationWorkflows(unittest.TestCase):
    def test_shared_label_writer_contract(self):
        MODULE.main()

    def test_concurrency_values_are_structural_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            path.write_text(
                "concurrency:\n  group: aster-repository-label-writers-extra # aster-repository-label-writers\n"
                "  cancel-in-progress: false\n  queue: max\n",
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                MODULE.main.__globals__["validate_concurrency"](path)
            path.write_text(
                "# concurrency:\n#   group: aster-repository-label-writers\n"
                "concurrency:\n  group: aster-repository-label-writers-wrong\n"
                "  cancel-in-progress: false\n  queue: max\n",
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                MODULE.main.__globals__["validate_concurrency"](path)

    def test_duplicate_workflow_and_concurrency_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            cases = [
                "concurrency:\n  group: wrong\n  group: aster-repository-label-writers\n  cancel-in-progress: false\n  queue: max\n",
                "concurrency:\n  group: aster-repository-label-writers\n  cancel-in-progress: false\n  queue: max\nconcurrency:\n  group: aster-repository-label-writers\n  cancel-in-progress: false\n  queue: max\n",
            ]
            for contents in cases:
                with self.subTest(contents=contents):
                    path.write_text(contents, encoding="utf-8")
                    with self.assertRaises(MODULE.yaml.constructor.ConstructorError):
                        MODULE.main.__globals__["validate_concurrency"](path)


if __name__ == "__main__":
    unittest.main()
