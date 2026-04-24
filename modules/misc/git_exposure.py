"""
Git Exposure — git-dumper, gitjacker, GitHunter
"""

from typing import Dict, List
from modules.base import BaseModule


class GitExposure(BaseModule):
    name = "git_exposure"
    description = "Exposed .git repository scanning"
    category = "misc"
    tools_required = []
    tools_optional = ["git-dumper", "gitjacker"]

    def run(self) -> Dict:
        urls = self.ctx.get("alive_urls", [])
        if not urls:
            self.log("No URLs for .git exposure testing.", level="warn")
            return self.get_results()

        urls = [u for u in urls if self.in_scope(u)]
        cfg = self.config

        # Test for exposed .git directories via HTTP
        import urllib.request
        import ssl

        git_paths = ["/.git/HEAD", "/.git/config", "/.git/index"]
        ctx = ssl.create_default_context()

        for url in urls[:cfg.get("max_targets", 30)]:
            base = url.rstrip("/")
            for path in git_paths:
                test_url = f"{base}{path}"
                try:
                    req = urllib.request.Request(test_url, headers={
                        "User-Agent": "Mozilla/5.0 BountyRecon/2.0"
                    })
                    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                        if resp.status == 200:
                            body = resp.read(500).decode("utf-8", errors="ignore")
                            if path == "/.git/HEAD" and "ref:" in body:
                                self.findings.append({
                                    "type": "git_exposure",
                                    "url": test_url,
                                    "severity": "high",
                                    "evidence": body[:100],
                                })
                                self.log(f"EXPOSED .git found: {test_url}")
                                break  # Found for this host
                            elif path == "/.git/config" and "[core]" in body:
                                self.findings.append({
                                    "type": "git_exposure",
                                    "url": test_url,
                                    "severity": "high",
                                    "evidence": body[:100],
                                })
                                break
                except Exception:
                    continue

        # --- git-dumper on confirmed exposures ---
        if cfg.get("use_git_dumper", False) and self.tool_exists("git-dumper"):
            for f in self.findings:
                if f["type"] == "git_exposure":
                    base_url = f["url"].rsplit("/.git", 1)[0]
                    dump_dir = self.phase_dir / f"dump_{hash(base_url) % 10000}"
                    dump_dir.mkdir(exist_ok=True)
                    self.exec([
                        "git-dumper", f"{base_url}/.git/", str(dump_dir),
                    ], timeout=300, label="git-dumper")

        critical = [f for f in self.findings if f.get("severity") in ("critical", "high")]
        if critical:
            self.ctx.setdefault("vuln_findings", []).extend(critical)

        self.write_json(self.phase_dir / "git_findings.json", self.findings)
        self.log(f"Git exposure findings: {len(self.findings)}")
        return self.get_results()
