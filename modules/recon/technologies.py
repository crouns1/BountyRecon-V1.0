"""
Technologies — httpx probing, whatweb, wafw00f, webanalyze
"""

import json
from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class Technologies(BaseModule):
    name = "technologies"
    description = "HTTP probing, tech fingerprinting, WAF detection"
    category = "recon"
    tools_required = ["httpx"]
    tools_optional = ["whatweb", "wafw00f", "webanalyze"]

    def run(self) -> Dict:
        subs = self.ctx.get("subdomains", [])
        if not subs:
            self.log("No subdomains to probe.", level="warn")
            return self.get_results()

        input_file = self.write_targets(subs, "subdomains.txt")
        cfg = self.config
        alive_hosts: List[Dict] = []

        # --- httpx (primary prober + tech detect) ---
        if self.tool_exists("httpx"):
            json_out = self.phase_dir / "httpx_results.json"
            cmd = [
                "httpx", "-l", str(input_file),
                "-ports", cfg.get("ports", "80,443,8080,8443,8000,3000,5000,9090"),
                "-rate-limit", str(cfg.get("rate_limit", 100)),
                "-silent", "-json", "-o", str(json_out),
                "-title", "-status-code", "-tech-detect",
                "-content-length", "-web-server", "-cdn",
                "-follow-redirects",
            ]
            self.exec(cmd, timeout=900, label="httpx")

            if json_out.exists():
                for line in open(json_out):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        host = e.get("host", "")
                        if host and not self.in_scope(host):
                            continue
                        alive_hosts.append({
                            "url": e.get("url", ""),
                            "host": host,
                            "status_code": e.get("status_code", 0),
                            "title": e.get("title", ""),
                            "tech": e.get("tech", []),
                            "webserver": e.get("webserver", ""),
                            "content_length": e.get("content_length", 0),
                            "cdn": e.get("cdn", False),
                        })
                    except json.JSONDecodeError:
                        continue

        alive_urls = [h["url"] for h in alive_hosts if h.get("url")]
        self.write_lines(self.phase_dir / "alive_urls.txt", alive_urls)
        self.write_json(self.phase_dir / "alive_hosts.json", alive_hosts)

        # --- wafw00f ---
        if cfg.get("use_wafw00f", True) and self.tool_exists("wafw00f"):
            waf_out = self.phase_dir / "wafw00f.json"
            url_file = self.phase_dir / "alive_urls.txt"
            self.exec([
                "wafw00f", "-i", str(url_file), "-o", str(waf_out), "-f", "json",
            ], timeout=600, label="wafw00f")

        # --- whatweb ---
        if cfg.get("use_whatweb", False) and self.tool_exists("whatweb"):
            for url in alive_urls[:50]:  # cap for speed
                safe = url.replace("://", "_").replace("/", "_")[:60]
                out = self.phase_dir / f"whatweb_{safe}.json"
                self.exec([
                    "whatweb", url, "--log-json", str(out), "-q",
                ], timeout=60, label=f"whatweb")

        self.log(f"Alive hosts: {len(alive_hosts)}")
        self.ctx["alive_hosts"] = alive_hosts
        self.ctx["alive_urls"] = alive_urls
        self.findings = alive_hosts
        return self.get_results()
