"""
Origin IP — hakoriginfinder, CloudRip
"""

from typing import Dict
from modules.base import BaseModule


class OriginIP(BaseModule):
    name = "origin_ip"
    description = "Discover origin IPs behind CDN/WAF"
    category = "misc"
    tools_required = ["hakoriginfinder"]
    tools_optional = []

    def run(self) -> Dict:
        alive = self.ctx.get("alive_hosts", [])
        if not alive:
            self.log("No alive hosts for origin IP discovery.", level="warn")
            return self.get_results()

        cfg = self.config

        # Filter for CDN-protected hosts
        cdn_hosts = [h for h in alive if h.get("cdn")]
        if not cdn_hosts:
            self.log("No CDN-fronted hosts detected.")
            return self.get_results()

        hosts = [h["host"] for h in cdn_hosts if h.get("host") and self.in_scope(h["host"])]
        host_file = self.write_targets(hosts, "cdn_hosts.txt")

        # --- hakoriginfinder ---
        if cfg.get("use_hakoriginfinder", True) and self.tool_exists("hakoriginfinder"):
            out = self.phase_dir / "origin_ips.txt"
            result = self.exec([
                "hakoriginfinder", "-h", str(host_file),
            ], timeout=600, label="hakoriginfinder")

            if result and result.stdout:
                with open(out, "w") as f:
                    f.write(result.stdout)
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        self.findings.append({
                            "type": "origin_ip",
                            "detail": line.strip(),
                        })

        self.write_json(self.phase_dir / "origin_findings.json", self.findings)
        self.log(f"Origin IP findings: {len(self.findings)}")
        return self.get_results()
