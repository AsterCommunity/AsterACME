"""Consumer-owned optionality must not allow local version/feature overrides."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("workspace_deps", Path(__file__).resolve().parents[1] / "check-workspace-deps.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class DependencyOwnership(unittest.TestCase):
    def test_only_workspace_inheritance_and_boolean_optionality_are_allowed(self):
        for definition in ({"workspace": True}, {"workspace": True, "optional": True}, {"workspace": True, "optional": False}):
            policy.errors.clear()
            policy.check({"dependencies": {"example": definition}}, "member")
            self.assertEqual(policy.errors, [])
        for definition in ("1", {"version": "1"}, {"workspace": True, "features": ["precheck"]}, {"workspace": True, "default-features": False}, {"workspace": False}, {"workspace": True, "optional": "yes"}):
            policy.errors.clear()
            policy.check({"dependencies": {"example": definition}}, "member")
            self.assertTrue(policy.errors)


if __name__ == "__main__":
    unittest.main()
