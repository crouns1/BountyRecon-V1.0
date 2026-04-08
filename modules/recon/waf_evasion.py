"""
WAF Evasion — wafw00f detection, nomore403, forbidden-buster
"""

from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class WafEvasion(BaseModule):
    name = "waf_evasion"
    description = "WAF detection and 403/401 bypass testing"
    category = "recon"
    tools_required = ["wafw00f"]
    tools_optional = ["nomore403", "forbidden-buster"]

    def run(self) -> Dict:
        urls = self.ctx.get("alive_urls", [])
        if not urls:
            self.log("No URLs for WAF testing.", level="warn")
            return self.get_results()

        urls = [u for u in urls if self.in_scope(u)]
        cfg = self.config
        forbidden_urls = self._get_403_urls()

        # --- nomore403 bypass ---
        if cfg.get("use_nomore403", True) and self.tool_exists("nomore403") and forbidden_urls:
            for url in forbidden_urls[:cfg.get("max_targets", 20)]:
                safe = str(hash(url) % 100000)
                out = self.phase_dir / f"nomore403_{safe}.txt"
                result = self.exec([
                    "nomore403", "-u", url,
                ], timeout=120, label="nomore403")

                if result and result.stdout:
                    with open(out, "w") as f:
                        f.write(result.stdout)
                    # Check for bypasses
                    if "bypass" in result.stdout.lower() or "200" in result.stdout:
                        self.findings.append({
                            "type": "403_bypass",
                            "url": url,
                            "output": result.stdout[:500],
                        })

        # --- forbidden-buster ---
        if cfg.get("use_forbidden_buster", False) and self.tool_exists("forbidden-buster"):
            for url in forbidden_urls[:10]:
                self.exec([
                    "forbidden-buster", "-u", url,
                ], timeout=120, label="forbidden-buster")

        self.log(f"WAF/403 bypass tested on {len(forbidden_urls)} URL(s)")
        self.write_json(self.phase_dir / "bypass_findings.json", self.findings)
        return self.get_results()

    def _get_403_urls(self) -> List[str]:
        """Extract URLs that returned 403 from content discovery."""
        dir_findings = self.ctx.get("dir_findings", [])
        alive = self.ctx.get("alive_hosts", [])
        blocked = []
        for f in dir_findings:
            if f.get("status") in (401, 403):
                blocked.append(f["url"])
        for h in alive:
            if h.get("status_code") in (401, 403):
                blocked.append(h["url"])
        return blocked
