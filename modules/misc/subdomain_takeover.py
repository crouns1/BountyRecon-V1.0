"""
Subdomain Takeover — subzy, subjack, dnsReaper
"""

from typing import Dict
from modules.base import BaseModule


class SubdomainTakeover(BaseModule):
    name = "subdomain_takeover"
    description = "Subdomain takeover vulnerability scanning"
    category = "misc"
    tools_required = ["subzy"]
    tools_optional = ["subjack", "dnsReaper"]

    def run(self) -> Dict:
        subs = self.ctx.get("subdomains", [])
        if not subs:
            self.log("No subdomains for takeover testing.", level="warn")
            return self.get_results()

        cfg = self.config
        sub_file = self.write_targets(subs, "subdomains.txt")

        # --- subzy ---
        if cfg.get("use_subzy", True) and self.tool_exists("subzy"):
            out = self.phase_dir / "subzy_results.txt"
            result = self.exec([
                "subzy", "run", "--targets", str(sub_file),
                "--concurrency", str(cfg.get("concurrency", 20)),
                "--timeout", str(cfg.get("timeout", 10)),
            ], timeout=600, label="subzy")

            if result and result.stdout:
                with open(out, "w") as f:
                    f.write(result.stdout)
                for line in result.stdout.strip().split("\n"):
                    if "vulnerable" in line.lower() or "takeover" in line.lower():
                        self.findings.append({
                            "type": "subdomain_takeover",
                            "detail": line.strip(),
                            "severity": "high",
                        })

        # --- subjack ---
        if cfg.get("use_subjack", False) and self.tool_exists("subjack"):
            out = self.phase_dir / "subjack_results.txt"
            self.exec([
                "subjack", "-w", str(sub_file),
                "-t", str(cfg.get("threads", 20)),
                "-timeout", str(cfg.get("timeout", 10)),
                "-ssl", "-o", str(out), "-v",
            ], timeout=600, label="subjack")

            if out.exists():
                for line in open(out):
                    line = line.strip()
                    if line:
                        self.findings.append({
                            "type": "subdomain_takeover",
                            "detail": line,
                            "source": "subjack",
                        })

        # --- dnsReaper ---
        if cfg.get("use_dnsreaper", False) and self.tool_exists("dnsReaper"):
            out = self.phase_dir / "dnsreaper.json"
            self.exec([
                "dnsReaper", "file", "--filename", str(sub_file),
                "--out", str(out), "--out-format", "json",
            ], timeout=600, label="dnsReaper")

        self.write_json(self.phase_dir / "takeover_findings.json", self.findings)
        self.log(f"Takeover findings: {len(self.findings)}")
        return self.get_results()
