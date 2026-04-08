"""
CMS Scanning — wpscan, CMSmap, joomscan
"""

import json
from typing import Dict, List
from modules.base import BaseModule


class CMS(BaseModule):
    name = "cms"
    description = "CMS-specific vulnerability scanning"
    category = "misc"
    tools_required = ["wpscan"]
    tools_optional = ["CMSmap", "joomscan"]

    def run(self) -> Dict:
        alive_hosts = self.ctx.get("alive_hosts", [])
        if not alive_hosts:
            self.log("No alive hosts for CMS scanning.", level="warn")
            return self.get_results()

        cfg = self.config

        # Detect WordPress, Joomla, Drupal from tech detection
        wp_targets = []
        joomla_targets = []
        other_cms = []

        for h in alive_hosts:
            techs = [t.lower() for t in h.get("tech", [])]
            url = h.get("url", "")
            if not url or not self.in_scope(url):
                continue

            if any("wordpress" in t for t in techs):
                wp_targets.append(url)
            elif any("joomla" in t for t in techs):
                joomla_targets.append(url)
            elif any(t in str(techs) for t in ["drupal", "magento", "shopify"]):
                other_cms.append(url)

        # --- wpscan ---
        if wp_targets and cfg.get("use_wpscan", True) and self.tool_exists("wpscan"):
            for url in wp_targets[:cfg.get("max_targets", 10)]:
                safe = str(hash(url) % 100000)
                out = self.phase_dir / f"wpscan_{safe}.json"
                cmd = [
                    "wpscan", "--url", url,
                    "-f", "json", "-o", str(out),
                    "--random-user-agent",
                    "-e", "vp,vt,u",
                    "--detection-mode", "mixed",
                ]
                api_token = cfg.get("wpscan_api_token", "")
                if api_token:
                    cmd.extend(["--api-token", api_token])

                self.exec(cmd, timeout=600, label="wpscan")

                if out.exists():
                    try:
                        data = json.loads(out.read_text())
                        vulns = data.get("vulnerabilities", [])
                        for v in vulns:
                            self.findings.append({
                                "type": "cms_vuln",
                                "cms": "wordpress",
                                "url": url,
                                "title": v.get("title", ""),
                                "severity": v.get("severity", ""),
                            })
                    except json.JSONDecodeError:
                        pass

        # --- joomscan ---
        if joomla_targets and cfg.get("use_joomscan", True) and self.tool_exists("joomscan"):
            for url in joomla_targets[:5]:
                self.exec([
                    "joomscan", "-u", url,
                ], timeout=600, label="joomscan")

        # --- CMSmap (general) ---
        if cfg.get("use_cmsmap", False) and self.tool_exists("CMSmap"):
            all_cms = wp_targets + joomla_targets + other_cms
            for url in all_cms[:10]:
                self.exec([
                    "CMSmap", "-t", url, "-f", "M",
                ], timeout=600, label="CMSmap")

        self.write_json(self.phase_dir / "cms_findings.json", self.findings)
        self.log(f"CMS findings: {len(self.findings)}")
        return self.get_results()
