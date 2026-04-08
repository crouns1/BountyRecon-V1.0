"""
Screenshots — gowitness, eyewitness, aquatone
"""

from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class Screenshots(BaseModule):
    name = "screenshots"
    description = "Visual screenshot capture of alive web hosts"
    category = "recon"
    tools_required = ["gowitness"]
    tools_optional = ["eyewitness", "aquatone"]

    def run(self) -> Dict:
        urls = self._get_urls()
        if not urls:
            self.log("No URLs for screenshots.", level="warn")
            return self.get_results()

        urls = [u for u in urls if self.in_scope(u)]
        input_file = self.write_targets(urls, "urls.txt")
        cfg = self.config

        # --- gowitness ---
        if cfg.get("use_gowitness", True) and self.tool_exists("gowitness"):
            ss_dir = self.phase_dir / "gowitness"
            ss_dir.mkdir(exist_ok=True)
            self.exec([
                "gowitness", "file",
                "-f", str(input_file),
                "--screenshot-path", str(ss_dir),
                "--threads", str(cfg.get("threads", 10)),
                "--timeout", str(cfg.get("timeout", 15)),
            ], timeout=1800, label="gowitness")

        # --- eyewitness ---
        if cfg.get("use_eyewitness", False) and self.tool_exists("eyewitness"):
            ew_dir = self.phase_dir / "eyewitness"
            ew_dir.mkdir(exist_ok=True)
            self.exec([
                "eyewitness", "-f", str(input_file),
                "-d", str(ew_dir),
                "--timeout", str(cfg.get("timeout", 15)),
                "--no-prompt",
            ], timeout=1800, label="eyewitness")

        self.log(f"Screenshots captured for {len(urls)} URL(s)")
        self.findings = [{"url": u, "status": "captured"} for u in urls]
        return self.get_results()

    def _get_urls(self) -> List[str]:
        alive = self.ctx.get("alive_hosts", [])
        if alive:
            return [h["url"] for h in alive if h.get("url")]
        subs = self.ctx.get("subdomains", [])
        return [f"https://{s}" for s in subs]
