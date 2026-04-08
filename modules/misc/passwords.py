"""
Passwords — Default credentials & weak password detection

Tools: nuclei (default-login templates), custom checks
Identifies login panels with default or weak credentials.
"""

import json
from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class Passwords(BaseModule):
    name = "passwords"
    description = "Default credentials & weak password detection"
    category = "misc"
    tools_required = []
    tools_optional = ["nuclei", "hydra"]

    def run(self) -> Dict:
        urls = self.ctx.get("alive_urls", [])
        if not urls:
            self.log("No alive URLs for password checks.", level="warn")
            return self.get_results()

        targets = self.filter_scope(urls)
        target_file = self.write_targets(targets)

        # --- Nuclei default-login templates ---
        if self.config.get("use_nuclei_defaults", True) and self.tool_exists("nuclei"):
            out = self.phase_dir / "nuclei_defaults.json"
            self.exec([
                "nuclei",
                "-l", str(target_file),
                "-t", "default-logins/",
                "-severity", "critical,high,medium",
                "-rate-limit", str(self.config.get("rate_limit", 30)),
                "-silent", "-jsonl",
                "-o", str(out),
                "-no-interactsh",
            ], timeout=1800, label="nuclei-default-logins")

            if out.exists():
                for line in open(out):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        self.findings.append({
                            "template_id": entry.get("template-id", ""),
                            "name": entry.get("info", {}).get("name", ""),
                            "severity": entry.get("info", {}).get("severity", ""),
                            "matched_at": entry.get("matched-at", ""),
                            "type": "default_credentials",
                        })
                    except json.JSONDecodeError:
                        continue

        # --- Passive: identify login panels from dir findings ---
        dir_findings = self.ctx.get("dir_findings", [])
        login_patterns = [
            "/login", "/admin", "/wp-login", "/signin", "/auth",
            "/panel", "/dashboard", "/console", "/manager",
            "/phpmyadmin", "/adminer", "/webmail",
        ]

        for finding in dir_findings:
            url = finding.get("url", "").lower()
            for pattern in login_patterns:
                if pattern in url:
                    self.findings.append({
                        "url": finding.get("url", ""),
                        "pattern": pattern,
                        "status": finding.get("status", ""),
                        "type": "login_panel",
                        "severity": "info",
                        "note": "Login panel discovered — test default credentials",
                    })
                    break

        # Propagate critical findings
        critical = [f for f in self.findings if f.get("severity") in ("critical", "high")]
        self.ctx.setdefault("vuln_findings", []).extend(critical)

        self.write_json(self.phase_dir / "password_findings.json", self.findings)
        self.log(f"Password findings: {len(self.findings)}")
        return self.get_results()
