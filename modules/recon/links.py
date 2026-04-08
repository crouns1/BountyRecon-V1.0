"""
Links — waybackurls, gau, waymore, LinkFinder, GoLinkFinder, xnLinkFinder, urlfinder
"""

from pathlib import Path
from typing import Dict, List, Set

from modules.base import BaseModule


class Links(BaseModule):
    name = "links"
    description = "URL & endpoint extraction from archives, JS files, crawling"
    category = "recon"
    tools_required = ["gau"]
    tools_optional = ["waybackurls", "waymore", "hakrawler", "urlfinder"]

    def run(self) -> Dict:
        domain = self.ctx["domain"]
        cfg = self.config
        all_urls: Set[str] = set()

        # --- gau (AlienVault, Wayback, Common Crawl) ---
        if cfg.get("use_gau", True) and self.tool_exists("gau"):
            out = self.phase_dir / "gau.txt"
            self.exec([
                "gau", domain, "--threads", str(cfg.get("threads", 10)),
                "--o", str(out),
            ], timeout=600, label="gau")
            all_urls |= self.read_lines(out)

        # --- waybackurls ---
        if cfg.get("use_waybackurls", True) and self.tool_exists("waybackurls"):
            out = self.phase_dir / "waybackurls.txt"
            result = self.exec(["waybackurls", domain], timeout=300, label="waybackurls")
            if result and result.stdout:
                with open(out, "w") as f:
                    f.write(result.stdout)
                all_urls |= self.read_lines(out)

        # --- waymore ---
        if cfg.get("use_waymore", False) and self.tool_exists("waymore"):
            out_dir = self.phase_dir / "waymore"
            out_dir.mkdir(exist_ok=True)
            self.exec([
                "waymore", "-i", domain, "-mode", "U",
                "-oU", str(out_dir / "urls.txt"),
            ], timeout=600, label="waymore")
            all_urls |= self.read_lines(out_dir / "urls.txt")

        # --- urlfinder (ProjectDiscovery) ---
        if cfg.get("use_urlfinder", False) and self.tool_exists("urlfinder"):
            out = self.phase_dir / "urlfinder.txt"
            self.exec([
                "urlfinder", "-d", domain, "-o", str(out), "-silent",
            ], timeout=300, label="urlfinder")
            all_urls |= self.read_lines(out)

        # Scope filter all discovered URLs
        filtered = [u for u in all_urls if self.in_scope(u)]
        self.write_lines(self.phase_dir / "all_urls.txt", filtered)

        self.log(f"URLs collected: {len(all_urls)} -> {len(filtered)} in-scope")
        self.ctx["gathered_urls"] = filtered
        self.findings = [{"url": u} for u in list(filtered)[:5000]]
        return self.get_results()
