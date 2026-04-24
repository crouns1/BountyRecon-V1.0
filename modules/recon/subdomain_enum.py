"""
Subdomain Enumeration — subfinder, amass, assetfinder, findomain, crt.sh,
github-subdomains, shuffledns, puredns
"""

import json
import ssl
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, Set

from modules.base import BaseModule


class SubdomainEnum(BaseModule):
    name = "subdomain_enum"
    description = "Passive & active subdomain enumeration"
    category = "recon"
    tools_required = ["subfinder"]
    tools_optional = ["amass", "assetfinder", "findomain", "shuffledns",
                      "puredns", "github-subdomains", "dnsx"]

    def run(self) -> Dict:
        domain = self.ctx["domain"]
        all_subs: Set[str] = set()
        cfg = self.config

        # --- subfinder ---
        if cfg.get("use_subfinder", True):
            out = self.phase_dir / "subfinder.txt"
            self.exec([
                "subfinder", "-d", domain, "-silent", "-all",
                "-t", str(self.config_get("threads", 50, "subfinder_threads")),
                "-o", str(out),
            ], timeout=600, label="subfinder")
            all_subs |= self.read_lines(out)

        # --- amass passive ---
        if cfg.get("use_amass", True) and self.tool_exists("amass"):
            out = self.phase_dir / "amass.txt"
            self.exec([
                "amass", "enum", "-passive", "-d", domain,
                "-o", str(out), "-timeout", str(cfg.get("amass_timeout", 15)),
            ], timeout=1200, label="amass")
            all_subs |= self.read_lines(out)

        # --- assetfinder ---
        if cfg.get("use_assetfinder", True) and self.tool_exists("assetfinder"):
            out = self.phase_dir / "assetfinder.txt"
            result = self.exec(["assetfinder", "--subs-only", domain],
                               timeout=300, label="assetfinder")
            if result and result.stdout:
                with open(out, "w") as f:
                    f.write(result.stdout)
                all_subs |= self.read_lines(out)

        # --- findomain ---
        if cfg.get("use_findomain", True) and self.tool_exists("findomain"):
            out = self.phase_dir / "findomain.txt"
            self.exec([
                "findomain", "-t", domain, "-u", str(out), "-q",
            ], timeout=600, label="findomain")
            all_subs |= self.read_lines(out)

        # --- crt.sh (no tool needed) ---
        if cfg.get("use_crtsh", True):
            all_subs |= self._query_crtsh(domain)

        # --- github-subdomains ---
        if cfg.get("use_github_subdomains", False) and self.tool_exists("github-subdomains"):
            token = cfg.get("github_token", "")
            if token:
                out = self.phase_dir / "github_subs.txt"
                self.exec([
                    "github-subdomains", "-d", domain, "-t", token,
                    "-o", str(out),
                ], timeout=300, label="github-subdomains")
                all_subs |= self.read_lines(out)

        # --- shuffledns brute (active) ---
        wordlist = cfg.get("wordlist", "")
        if cfg.get("use_shuffledns", False) and self.tool_exists("shuffledns") and wordlist:
            out = self.phase_dir / "shuffledns.txt"
            self.exec([
                "shuffledns", "-d", domain, "-w", wordlist,
                "-r", self.config_get("resolvers", "/usr/share/wordlists/resolvers.txt"),
                "-o", str(out), "-silent",
            ], timeout=1800, label="shuffledns")
            all_subs |= self.read_lines(out)

        # Always include root domain
        all_subs.add(domain)

        self.log(f"Raw subdomains collected: {len(all_subs)}")

        # Scope filter
        filtered = self.filter_scope(list(all_subs))
        filtered.sort()

        self.write_lines(self.phase_dir / "all_subdomains.txt", filtered)

        self.log(f"In-scope subdomains: {len(filtered)}")
        self.ctx["subdomains"] = filtered
        self.findings = [{"subdomain": s} for s in filtered]
        return self.get_results()

    def _query_crtsh(self, domain: str) -> Set[str]:
        self.log("Querying crt.sh...")
        subs = set()
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "BountyRecon/2.0"})
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                data = json.loads(resp.read().decode())
            for entry in data:
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub:
                        subs.add(sub)
            self.write_lines(self.phase_dir / "crtsh.txt", subs)
        except Exception as e:
            self.log(f"crt.sh failed: {e}", level="warn")
        return subs
