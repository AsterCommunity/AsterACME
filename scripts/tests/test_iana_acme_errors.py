"""Offline parser tests; the scheduled workflow checks the live IANA CSV."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "iana_acme_errors",
    Path(__file__).resolve().parents[1] / "check-iana-acme-errors.py",
)
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)


class IanaAcmeErrors(unittest.TestCase):
    def test_csv_parser_handles_quoted_commas_and_multiline_descriptions(self):
        data = 'Type,Description,Reference\nfoo,"text, with comma",[RFC 9999]\nbar,"multiple\nlines",[RFC 9999]\n'
        self.assertEqual(registry.registry_types(data), {"foo", "bar"})

    def test_registry_type_set_matches_wire_enum_and_reports_drift(self):
        source = '''wire_enum! { pub enum ProblemKind {
            Foo => "urn:ietf:params:acme:error:foo",
            Bar => "urn:ietf:params:acme:error:bar",
        } }'''
        data = "Type,Description,Reference\nfoo,existing,[RFC 9999]\nnewType,new,[RFC 9999]\n"
        missing, stale = registry.compare(source, data)
        self.assertEqual(missing, {"newType"})
        self.assertEqual(stale, {"bar"})

    def test_malformed_registry_and_missing_enum_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError, "Type column"):
            registry.registry_types("Wrong,Description\nfoo,bar\n")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            registry.registry_types("Type,Description\nfoo,one\nfoo,two\n")
        with self.assertRaisesRegex(ValueError, "not found"):
            registry.problem_kinds("pub enum Other {}")


if __name__ == "__main__":
    unittest.main()
