"""
Content Discovery — ffuf, gobuster, feroxbuster, dirsearch, katana, gospider, hakrawler
"""

import json
from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class ContentDiscovery(BaseModule):
    name = "content_discovery"
    description = "Directory/file fuzzing and web crawling"
    category = "recon"
    tools_required = ["ffuf"]
    tools_optional = ["gobuster", "feroxbuster", "dirsearch", "katana",
                      "gospider", "hakrawler", "crawley"]

    def run(self) -> Dict:
        urls = self._get_urls()
        if not urls:
            self.log("No URLs for content discovery.", level="warn")
            return self.get_results()

        urls = [u for u in urls if self.in_scope(u)]
        cfg = self.config
        all_findings: List[Dict] = []

        # --- ffuf directory fuzzing ---
        wordlist = cfg.get("wordlist", "wordlists/common.txt")
        # Try local wordlist first, then system wordlist
        if not Path(wordlist).exists():
            system_wordlist = "/usr/share/wordlists/dirb/common.txt"
            if Path(system_wordlist).exists():
                wordlist = system_wordlist
            else:
                self.log(f"No wordlist found, skipping directory fuzzing", level="warn")
                wordlist = None

        if wordlist and cfg.get("use_ffuf", True) and self.tool_exists("ffuf"):
            for i, url in enumerate(urls[:cfg.get("max_targets", 30)], 1):
                safe = url.replace("://", "_").replace("/", "_").replace(":", "_")[:80]
                out = self.phase_dir / f"ffuf_{safe}.json"
                self.log(f"[{i}/{min(len(urls), cfg.get('max_targets', 30))}] Fuzzing {url}")
                self.exec([
                    "ffuf", "-u", f"{url.rstrip('/')}/FUZZ",
                    "-w", wordlist,
                    "-e", cfg.get("extensions", ".php,.html,.js,.json,.txt,.bak,.env"),
                    "-t", str(cfg.get("threads", 40)),
                    "-rate", str(cfg.get("rate_limit", 100)),
                    "-mc", cfg.get("match_status", "200,204,301,302,307,401,403,405,500"),
                    "-fc", cfg.get("filter_status", "404"),
                    "-sf", "-se", "-noninteractive",
                    "-json", "-o", str(out),
                ], timeout=600, label="ffuf")

                if out.exists():
                    try:
                        data = json.loads(out.read_text())
                        for r in data.get("results", []):
                            all_findings.append({
                                "target": url,
                                "path": r.get("input", {}).get("FUZZ", ""),
                                "url": r.get("url", ""),
                                "status": r.get("status", 0),
                                "length": r.get("length", 0),
                            })
                    except (json.JSONDecodeError, KeyError):
                        pass

        # --- katana crawling ---
        if cfg.get("use_katana", True) and self.tool_exists("katana"):
            url_file = self.write_targets(urls, "crawl_targets.txt")
            out = self.phase_dir / "katana.txt"
            self.exec([
                "katana", "-list", str(url_file),
                "-d", str(cfg.get("crawl_depth", 3)),
                "-jc", "-kf", "all",
                "-rate-limit", str(cfg.get("rate_limit", 100)),
                "-silent", "-o", str(out),
            ], timeout=1200, label="katana")
            crawled = self.read_lines(out)
            self.ctx.setdefault("crawled_urls", []).extend(crawled)

        # --- gospider ---
        if cfg.get("use_gospider", False) and self.tool_exists("gospider"):
            url_file = self.write_targets(urls, "spider_targets.txt")
            out_dir = self.phase_dir / "gospider"
            out_dir.mkdir(exist_ok=True)
            self.exec([
                "gospider", "-S", str(url_file),
                "-o", str(out_dir), "-t", "5",
                "-d", str(cfg.get("crawl_depth", 3)),
                "--sitemap", "--robots", "-q",
            ], timeout=1200, label="gospider")

        self.write_json(self.phase_dir / "all_findings.json", all_findings)
        found_urls = [f["url"] for f in all_findings if f.get("url")]
        self.write_lines(self.phase_dir / "discovered_endpoints.txt", found_urls)

        self.log(f"Endpoints discovered: {len(all_findings)}")
        self.ctx["dir_findings"] = all_findings
        self.findings = all_findings
        return self.get_results()

    def _get_urls(self) -> List[str]:
        return self.ctx.get("alive_urls", [])
