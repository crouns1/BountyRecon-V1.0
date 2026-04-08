"""
Content Filtering — Response deduplication & noise reduction

Tools: uro, anew
Filters duplicate and noise URLs from gathered results to
produce a clean, unique target list for downstream modules.
"""

from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class ContentFiltering(BaseModule):
    name = "content_filtering"
    description = "URL deduplication & content noise filtering"
    category = "recon"
    tools_required = []
    tools_optional = ["uro", "anew"]

    def run(self) -> Dict:
        gathered = self.ctx.get("gathered_urls", [])
        if not gathered:
            self.log("No gathered URLs to filter.", level="warn")
            return self.get_results()

        self.log(f"Input URLs: {len(gathered)}")

        # Write raw input
        raw_file = self.write_targets(gathered, "raw_urls.txt")
        filtered_urls = list(set(gathered))  # basic dedup

        # --- uro (URL deduplication) ---
        if self.config.get("use_uro", True) and self.tool_exists("uro"):
            out = self.phase_dir / "uro_output.txt"
            result = self.exec(
                ["bash", "-c", f"cat {raw_file} | uro"],
                timeout=300, label="uro"
            )
            if result and result.stdout:
                with open(out, "w") as f:
                    f.write(result.stdout)
                filtered_urls = [
                    line.strip() for line in result.stdout.splitlines()
                    if line.strip()
                ]

        # --- Scope filter ---
        filtered_urls = self.filter_scope(filtered_urls)

        # --- Remove common noise patterns ---
        noise_patterns = self.config.get("noise_patterns", [
            ".css", ".woff", ".woff2", ".ttf", ".eot", ".svg",
            ".ico", ".png", ".jpg", ".jpeg", ".gif", ".webp",
            "fonts.googleapis.com", "google-analytics.com",
            "facebook.com/tr", "doubleclick.net",
        ])

        if self.config.get("filter_noise", True):
            before = len(filtered_urls)
            filtered_urls = [
                url for url in filtered_urls
                if not any(noise in url.lower() for noise in noise_patterns)
            ]
            removed = before - len(filtered_urls)
            if removed:
                self.log(f"Noise filtered: {removed} URLs removed")

        # Write filtered output
        self.write_lines(self.phase_dir / "filtered_urls.txt", filtered_urls)

        # Update context
        self.ctx["gathered_urls"] = filtered_urls

        self.findings = [{"filtered_count": len(filtered_urls), "original_count": len(gathered)}]
        self.log(f"Filtered URLs: {len(gathered)} → {len(filtered_urls)}")
        return self.get_results()
