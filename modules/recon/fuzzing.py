"""
Fuzzing — ffuf (targeted), wfuzz, qsfuzz
"""

from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class Fuzzing(BaseModule):
    name = "fuzzing"
    description = "Targeted query string and input fuzzing"
    category = "recon"
    tools_required = ["ffuf"]
    tools_optional = ["wfuzz", "qsfuzz"]

    def run(self) -> Dict:
        param_urls = self._get_param_urls()
        if not param_urls:
            self.log("No parameterized URLs to fuzz.", level="warn")
            return self.get_results()

        param_urls = [u for u in param_urls if self.in_scope(u)]
        cfg = self.config
        import json

        # --- ffuf targeted fuzzing ---
        if cfg.get("use_ffuf", True) and self.tool_exists("ffuf"):
            fuzz_wordlist = cfg.get("wordlist", "/usr/share/wordlists/seclists/Fuzzing/special-chars.txt")
            if not Path(fuzz_wordlist).exists():
                fuzz_wordlist = "/usr/share/wordlists/dirb/common.txt"

            for i, url in enumerate(param_urls[:cfg.get("max_targets", 20)], 1):
                # Replace param value with FUZZ keyword
                if "=" in url:
                    fuzz_url = url.rsplit("=", 1)[0] + "=FUZZ"
                else:
                    continue

                safe = str(hash(url) % 100000)
                out = self.phase_dir / f"ffuf_fuzz_{safe}.json"
                self.log(f"[{i}] Fuzzing: {fuzz_url[:80]}")
                self.exec([
                    "ffuf", "-u", fuzz_url,
                    "-w", fuzz_wordlist,
                    "-t", str(cfg.get("threads", 20)),
                    "-rate", str(cfg.get("rate_limit", 50)),
                    "-mc", "all", "-fc", "404",
                    "-sf", "-se", "-noninteractive",
                    "-json", "-o", str(out),
                ], timeout=300, label="ffuf-fuzz")

        self.log(f"Fuzzing done on {len(param_urls)} URL(s)")
        return self.get_results()

    def _get_param_urls(self) -> List[str]:
        """Get URLs with parameters from gathered URLs or parameter discovery."""
        urls = self.ctx.get("gathered_urls", [])
        return [u for u in urls if "?" in u and "=" in u]
