"""
Forbidden Bypass — 401/403 authorization bypass techniques

Tools: nomore403, bypass-403
Tests various bypass techniques against forbidden endpoints.
"""

import json
from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class ForbiddenBypass(BaseModule):
    name = "forbidden_bypass"
    description = "401/403 authorization bypass testing"
    category = "misc"
    tools_required = []
    tools_optional = ["nomore403"]

    def run(self) -> Dict:
        # Find 401/403 endpoints from content discovery & alive hosts
        forbidden_urls = []

        for host in self.ctx.get("alive_hosts", []):
            status = host.get("status_code", 0)
            if status in (401, 403):
                url = host.get("url", "")
                if url and self.in_scope(url):
                    forbidden_urls.append(url)

        for finding in self.ctx.get("dir_findings", []):
            status = finding.get("status", 0)
            if status in (401, 403):
                url = finding.get("url", "")
                if url and self.in_scope(url):
                    forbidden_urls.append(url)

        forbidden_urls = list(set(forbidden_urls))

        if not forbidden_urls:
            self.log("No 401/403 endpoints found to test.", level="warn")
            return self.get_results()

        self.log(f"Testing {len(forbidden_urls)} forbidden endpoint(s)...")

        # --- nomore403 ---
        tools_dir = Path.home() / "tools" / "nomore403"
        if self.config.get("use_nomore403", True) and (
            self.tool_exists("nomore403") or (tools_dir / "nomore403").exists()
        ):
            tool_bin = "nomore403"
            if not self.tool_exists("nomore403") and (tools_dir / "nomore403").exists():
                tool_bin = str(tools_dir / "nomore403")

            for url in forbidden_urls[:30]:  # cap to prevent abuse
                out = self.phase_dir / f"nomore403_{hash(url) % 10000}.txt"
                result = self.exec([
                    tool_bin, "-u", url,
                ], timeout=120, label=f"nomore403 ({url[:40]})")

                if result and result.stdout:
                    with open(out, "w") as f:
                        f.write(result.stdout)
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if "200" in line or "bypass" in line.lower():
                            self.findings.append({
                                "url": url,
                                "result": line[:200],
                                "type": "forbidden_bypass",
                                "severity": "high",
                            })

        # --- Header-based bypass attempts (passive catalog) ---
        bypass_headers = [
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For: 127.0.0.1",
            "X-Custom-IP-Authorization: 127.0.0.1",
            "X-Forwarded-Host: 127.0.0.1", "X-Host: 127.0.0.1",
        ]
        for url in forbidden_urls:
            self.findings.append({
                "url": url,
                "type": "forbidden_endpoint",
                "severity": "info",
                "note": f"Test with bypass headers: {', '.join(bypass_headers[:3])}",
                "bypass_headers": bypass_headers,
            })

        # Propagate high findings
        critical = [f for f in self.findings if f.get("severity") in ("critical", "high")]
        self.ctx.setdefault("vuln_findings", []).extend(critical)

        self.write_json(self.phase_dir / "bypass_findings.json", self.findings)
        self.log(f"Forbidden bypass findings: {len(self.findings)}")
        return self.get_results()
