"""Synthetic dependency graphs exercise transitive feature-regression rejection."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("features", Path(__file__).resolve().parents[1] / "check-dependency-features.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class FeaturePolicy(unittest.TestCase):
    def test_reviewed_features_and_repeated_nodes(self):
        self.assertEqual(policy.audit("reqwest v0.13|json,rustls,system-proxy\ninquire v0.9|crossterm,fuzzy (*)\naster_forge_panic v0.1|\nother v1|default"), [])

    def test_transitive_extras_cannot_hide_behind_no_default_features(self):
        for package, feature in [("reqwest", "default-tls"), ("reqwest", "gzip"), ("reqwest", "multipart"), ("rustls", "ring"), ("rcgen", "ring"), ("inquire", "editor"), ("tracing-subscriber", "local-time")]:
            with self.subTest(package=package, feature=feature):
                self.assertTrue(policy.audit(f"{package} v1|{feature}"))
        for package in policy.FORBIDDEN:
            self.assertTrue(policy.audit(f"{package} v1|default"))


if __name__ == "__main__":
    unittest.main()
