"""Static tests for repository label-writer concurrency and risk coverage."""

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
