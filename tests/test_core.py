import json
import tempfile
import unittest
from pathlib import Path

from bountyrecon import normalize_target
from modules.base import BaseModule
from modules.exploit.payloads import load_string_payloads, load_tuple_payloads, load_triple_payloads
from modules.reporter import generate_report
from modules.scope import ScopeEnforcer


class DummyModule(BaseModule):
    name = "dummy"
    category = "test"

    def run(self):
        return self.get_results()


class CoreTests(unittest.TestCase):
    def test_normalize_target_strips_scheme_path_and_port(self):
        self.assertEqual(
            normalize_target("https://Example.com:8443/path?q=1"),
            "example.com",
        )
        self.assertEqual(normalize_target("api.example.com"), "api.example.com")

    def test_scope_accepts_url_rules_and_filters_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            inscope = Path(tmp) / "inscope.txt"
            outscope = Path(tmp) / "outscope.txt"
            inscope.write_text("https://example.com\n*.api.example.com\n")
            outscope.write_text("https://admin.example.com\n10.0.0.0/8\n")

            scope = ScopeEnforcer(str(inscope), str(outscope))

            self.assertTrue(scope.is_in_scope("https://www.example.com/test"))
            self.assertTrue(scope.is_in_scope("foo.api.example.com"))
            self.assertFalse(scope.is_in_scope("admin.example.com"))
            self.assertFalse(scope.is_in_scope("10.1.2.3"))

    def test_config_get_supports_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = DummyModule(
                output_dir=Path(tmp),
                config={"legacy_key": 25},
                scope=ScopeEnforcer(),
                context={},
            )
            self.assertEqual(module.config_get("new_key", 10, "legacy_key"), 25)
            self.assertEqual(module.config_get("missing", 10), 10)

    def test_report_generation_writes_expected_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            context = {
                "subdomains": ["a.example.com", "b.example.com"],
                "alive_hosts": [{"url": "https://a.example.com", "tech": ["nginx"]}],
                "alive_urls": ["https://a.example.com"],
                "port_results": [{"host": "a.example.com", "port": 443}],
                "dir_findings": [{"url": "https://a.example.com/admin"}],
                "gathered_urls": ["https://a.example.com/admin?id=1"],
                "parameters": [{"url": "https://a.example.com/admin", "param": "id"}],
                "vuln_findings": [{"name": "Test", "severity": "high", "matched_at": "https://a.example.com"}],
            }
            results = [
                {
                    "module": "technologies",
                    "category": "recon",
                    "description": "HTTP probing",
                    "findings_count": 1,
                    "findings": context["alive_hosts"],
                }
            ]

            generate_report(
                domain="example.com",
                output_dir=output_dir,
                context=context,
                results=results,
                scope_stats={"in_scope_domains": 1},
                elapsed=12.3,
            )

            report_json = json.loads((output_dir / "report.json").read_text())
            report_md = (output_dir / "report.md").read_text()

            self.assertEqual(report_json["summary"]["total_subdomains"], 2)
            self.assertEqual(report_json["summary"]["vulnerabilities"], 1)
            self.assertIn("Executive Summary", report_md)

    def test_payload_loaders_support_external_catalogs(self):
        with tempfile.TemporaryDirectory() as tmp:
            string_file = Path(tmp) / "strings.txt"
            tuple_file = Path(tmp) / "pairs.txt"
            triple_file = Path(tmp) / "triples.txt"

            string_file.write_text("# comment\none\ntwo\n")
            tuple_file.write_text("payload1 ||| marker1\npayload2|||marker2\n")
            triple_file.write_text("a|||b|||c\nx ||| y ||| z\n")

            self.assertEqual(load_string_payloads(str(string_file)), ["one", "two"])
            self.assertEqual(
                load_tuple_payloads(str(tuple_file)),
                [("payload1", "marker1"), ("payload2", "marker2")],
            )
            self.assertEqual(
                load_triple_payloads(str(triple_file)),
                [("a", "b", "c"), ("x", "y", "z")],
            )


if __name__ == "__main__":
    unittest.main()
