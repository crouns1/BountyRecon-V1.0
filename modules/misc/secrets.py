"""
Secrets — gitleaks, trufflehog, SecretFinder, noseyparker
"""

from typing import Dict, List
from modules.base import BaseModule


class Secrets(BaseModule):
    name = "secrets"
    description = "Secret & credential scanning in JS files and responses"
    category = "misc"
    tools_required = ["gitleaks"]
    tools_optional = ["trufflehog", "noseyparker", "SecretFinder"]

    def run(self) -> Dict:
        urls = self.ctx.get("alive_urls", [])
        domain = self.ctx.get("domain", "")
        cfg = self.config

        # --- SecretFinder on JS files ---
        if cfg.get("use_secretfinder", True) and self.tool_exists("SecretFinder"):
            js_urls = [u for u in self.ctx.get("crawled_urls", [])
                       if u.endswith(".js") and self.in_scope(u)]

            for js_url in js_urls[:cfg.get("max_js_files", 50)]:
                safe = str(hash(js_url) % 100000)
                out = self.phase_dir / f"secretfinder_{safe}.html"
                self.exec([
                    "SecretFinder", "-i", js_url,
                    "-o", str(out), "-e",
                ], timeout=60, label="SecretFinder")

        # --- noseyparker ---
        if cfg.get("use_noseyparker", False) and self.tool_exists("noseyparker"):
            datastore = self.phase_dir / "noseyparker_ds"
            self.exec([
                "noseyparker", "scan", "--datastore", str(datastore),
                "--url", f"https://{domain}",
            ], timeout=600, label="noseyparker")

            result = self.exec([
                "noseyparker", "report", "--datastore", str(datastore),
                "--format", "json",
            ], timeout=60, label="noseyparker-report")

            if result and result.stdout:
                import json
                try:
                    findings = json.loads(result.stdout)
                    for f in findings:
                        self.findings.append({
                            "type": "secret",
                            "rule": f.get("rule_name", ""),
                            "match": f.get("match_content", "")[:200],
                        })
                except json.JSONDecodeError:
                    pass

        self.write_json(self.phase_dir / "secret_findings.json", self.findings)
        self.log(f"Secret findings: {len(self.findings)}")
        return self.get_results()
