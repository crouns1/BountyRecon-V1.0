"""
Technologies — httpx probing, whatweb, wafw00f, webanalyze
"""

import json
import ipaddress
import ssl
import urllib.request
from typing import Dict, List

from modules.base import BaseModule


class Technologies(BaseModule):
    name = "technologies"
    description = "HTTP probing, tech fingerprinting, WAF detection"
    category = "recon"
    tools_required = []
    tools_optional = ["httpx", "whatweb", "wafw00f", "webanalyze"]

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
            ]
            if any(self._is_private_host(host) for host in subs):
                cmd.append("-allow")
            if self.config_get("follow_redirects", True):
                cmd.append("-follow-redirects")
            if self.config_get("status_codes", ""):
                cmd.extend(["-mc", self.config_get("status_codes", "")])
            self.exec(cmd, timeout=900, label="httpx")

            if json_out.exists():
                with open(json_out) as handle:
                    for line in handle:
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

        if not alive_hosts:
            self.log("httpx produced no alive hosts; using built-in probe fallback.", level="warn")
            alive_hosts = self._builtin_probe(subs, cfg)

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

    def _builtin_probe(self, subs: List[str], cfg: dict) -> List[Dict]:
        ports = [p.strip() for p in str(cfg.get("ports", "80,443")).split(",") if p.strip()]
        timeout = int(self.config_get("timeout", 5))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        results: List[Dict] = []

        for host in subs:
            if not self.in_scope(host):
                continue
            for port in ports:
                for scheme in ("https", "http"):
                    default_port = (scheme == "https" and port == "443") or (scheme == "http" and port == "80")
                    netloc = host if default_port else f"{host}:{port}"
                    url = f"{scheme}://{netloc}/"
                    try:
                        req = urllib.request.Request(url, headers={"User-Agent": "BountyRecon/2.0"})
                        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                            body = resp.read(4096).decode("utf-8", errors="ignore")
                            title = ""
                            if "<title>" in body.lower():
                                lower = body.lower()
                                start = lower.find("<title>") + 7
                                end = lower.find("</title>", start)
                                if end > start:
                                    title = body[start:end].strip()
                            results.append({
                                "url": url,
                                "host": host,
                                "status_code": getattr(resp, "status", 0),
                                "title": title,
                                "tech": [],
                                "webserver": resp.headers.get("Server", ""),
                                "content_length": int(resp.headers.get("Content-Length", "0") or 0),
                                "cdn": False,
                            })
                            break
                    except Exception:
                        continue
        return results

    def _is_private_host(self, host: str) -> bool:
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
        except ValueError:
            return host.endswith(".local") or host.endswith(".localhost")
