"""
Vulnerability Scanners — nuclei, nikto
"""

import json
from typing import Dict, List
from modules.base import BaseModule


class VulnScanners(BaseModule):
    name = "vuln_scanners"
    description = "Template-based and general vulnerability scanning"
    category = "misc"
    tools_required = ["nuclei"]
    tools_optional = ["nikto"]

    def run(self) -> Dict:
        urls = self.ctx.get("alive_urls", [])
        if not urls:
            self.log("No URLs for vulnerability scanning.", level="warn")
            return self.get_results()

        urls = [u for u in urls if self.in_scope(u)]
        cfg = self.config

        # --- nuclei ---
        if cfg.get("use_nuclei", True) and self.tool_exists("nuclei"):
            url_file = self.write_targets(urls, "nuclei_targets.txt")
            json_out = self.phase_dir / "nuclei_results.jsonl"

            cmd = [
                "nuclei", "-l", str(url_file),
                "-severity", cfg.get("severity", "critical,high,medium"),
                "-rate-limit", str(cfg.get("rate_limit", 100)),
                "-bulk-size", str(cfg.get("bulk_size", 25)),
                "-silent", "-jsonl", "-o", str(json_out),
                "-no-interactsh",
            ]

            templates = cfg.get("templates", [])
            for t in templates:
                cmd.extend(["-t", t])

            exclude = cfg.get("exclude_templates", ["dos/", "fuzzing/"])
            for et in exclude:
                cmd.extend(["-exclude-templates", et])

            self.exec(cmd, timeout=3600, label="nuclei")

            if json_out.exists():
                for line in open(json_out):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        self.findings.append({
                            "template_id": e.get("template-id", ""),
                            "name": e.get("info", {}).get("name", ""),
                            "severity": e.get("info", {}).get("severity", ""),
                            "type": e.get("type", ""),
                            "host": e.get("host", ""),
                            "matched_at": e.get("matched-at", ""),
                            "description": e.get("info", {}).get("description", ""),
                            "reference": e.get("info", {}).get("reference", []),
                            "tags": e.get("info", {}).get("tags", []),
                        })
                    except json.JSONDecodeError:
                        continue

        # --- nikto ---
        if cfg.get("use_nikto", False) and self.tool_exists("nikto"):
            for url in urls[:cfg.get("max_nikto_targets", 10)]:
                safe = str(hash(url) % 100000)
                out = self.phase_dir / f"nikto_{safe}.json"
                self.exec([
                    "nikto", "-h", url,
                    "-Format", "json", "-output", str(out),
                    "-Tuning", "1234567890abc",
                    "-maxtime", str(cfg.get("nikto_timeout", 300)) + "s",
                ], timeout=600, label="nikto")

        self.write_json(self.phase_dir / "vuln_findings.json", self.findings)

        # Severity breakdown
        sev_map = {}
        for f in self.findings:
            s = f.get("severity", "unknown")
            sev_map[s] = sev_map.get(s, 0) + 1

        self.log(f"Vulnerabilities: {len(self.findings)}")
        for sev, count in sorted(sev_map.items()):
            self.log(f"  {sev.upper()}: {count}")

        self.ctx["vuln_findings"] = self.findings
        return self.get_results()
