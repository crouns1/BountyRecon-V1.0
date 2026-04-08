"""
Parameters — arjun, paramspider, x8
"""

from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class Parameters(BaseModule):
    name = "parameters"
    description = "Hidden HTTP parameter discovery"
    category = "recon"
    tools_required = ["arjun"]
    tools_optional = ["paramspider", "x8"]

    def run(self) -> Dict:
        urls = self.ctx.get("alive_urls", [])
        if not urls:
            self.log("No URLs for parameter discovery.", level="warn")
            return self.get_results()

        urls = [u for u in urls if self.in_scope(u)]
        cfg = self.config
        all_params: List[Dict] = []

        # --- Arjun ---
        if cfg.get("use_arjun", True) and self.tool_exists("arjun"):
            url_file = self.write_targets(urls[:cfg.get("max_targets", 20)], "arjun_targets.txt")
            out = self.phase_dir / "arjun_results.json"
            self.exec([
                "arjun", "-i", str(url_file),
                "-oJ", str(out),
                "-t", str(cfg.get("threads", 10)),
                "--rate-limit", str(cfg.get("rate_limit", 30)),
                "-q",
            ], timeout=1200, label="arjun")

            if out.exists():
                try:
                    import json
                    data = json.loads(out.read_text())
                    for target_url, params in data.items():
                        for p in params:
                            all_params.append({"url": target_url, "param": p})
                except (json.JSONDecodeError, KeyError):
                    pass

        # --- ParamSpider ---
        if cfg.get("use_paramspider", True) and self.tool_exists("paramspider"):
            domain = self.ctx["domain"]
            out_dir = self.phase_dir / "paramspider"
            out_dir.mkdir(exist_ok=True)
            self.exec([
                "paramspider", "-d", domain,
                "--output", str(out_dir / "params.txt"),
                "-l", "high",
            ], timeout=600, label="paramspider")

            param_urls = self.read_lines(out_dir / "params.txt")
            for u in param_urls:
                all_params.append({"url": u, "source": "paramspider"})

        # --- x8 ---
        if cfg.get("use_x8", False) and self.tool_exists("x8"):
            for url in urls[:10]:
                out = self.phase_dir / f"x8_{hash(url) % 10000}.json"
                self.exec([
                    "x8", "-u", url, "--output", str(out), "-O", "json",
                ], timeout=300, label="x8")

        self.write_json(self.phase_dir / "all_parameters.json", all_params)
        self.log(f"Parameters found: {len(all_params)}")
        self.ctx["parameters"] = all_params
        self.findings = all_params
        return self.get_results()
