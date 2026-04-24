"""
Secrets — gitleaks, trufflehog, SecretFinder, noseyparker
"""

import json
import re
import ssl
import urllib.request
from typing import Dict, List

from modules.base import BaseModule


class Secrets(BaseModule):
    name = "secrets"
    description = "Secret & credential scanning in JS files and responses"
    category = "misc"
    tools_required = []
    tools_optional = ["trufflehog", "noseyparker", "SecretFinder"]

    def run(self) -> Dict:
        domain = self.ctx.get("domain", "")
        cfg = self.config
        regex_patterns = [
            re.compile(pattern)
            for pattern in cfg.get("regex_patterns", [])
        ]

        js_urls = self._collect_js_urls()
        if js_urls:
            self._scan_js_content(js_urls, regex_patterns)

        # --- SecretFinder on JS files ---
        if cfg.get("use_secretfinder", True) and self.tool_exists("SecretFinder"):
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

        critical = [f for f in self.findings if f.get("severity") in ("critical", "high")]
        if critical:
            self.ctx.setdefault("vuln_findings", []).extend(critical)

        self.write_lines(self.phase_dir / "js_targets.txt", js_urls)
        self.write_json(self.phase_dir / "secret_findings.json", self.findings)
        self.log(f"Secret findings: {len(self.findings)}")
        return self.get_results()

    def _collect_js_urls(self) -> List[str]:
        candidates = set()
        for key in ("crawled_urls", "gathered_urls", "alive_urls"):
            for url in self.ctx.get(key, []):
                if isinstance(url, str) and ".js" in url.lower() and self.in_scope(url):
                    candidates.add(url)
        return sorted(candidates)

    def _scan_js_content(self, js_urls: List[str], regex_patterns: List[re.Pattern]) -> None:
        """Fetch JavaScript files and apply lightweight regex-based secret detection."""
        ctx = ssl.create_default_context()
        max_files = self.config_get("max_js_files", 50)

        for js_url in js_urls[:max_files]:
            try:
                req = urllib.request.Request(js_url, headers={"User-Agent": "BountyRecon/2.0"})
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    if resp.status >= 400:
                        continue
                    body = resp.read(250000).decode("utf-8", errors="ignore")
            except Exception:
                continue

            for pattern in regex_patterns:
                for match in pattern.finditer(body):
                    snippet = match.group(0)[:200]
                    self.findings.append({
                        "type": "secret",
                        "source": "regex",
                        "url": js_url,
                        "rule": pattern.pattern,
                        "match": snippet,
                        "severity": "high",
                    })
