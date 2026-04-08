"""
Monitoring — Continuous recon change detection

Compares current scan results with previous runs to detect
new subdomains, new open ports, and new endpoints (diff-based).
"""

import json
from pathlib import Path
from typing import Dict, List, Set

from modules.base import BaseModule


class Monitoring(BaseModule):
    name = "monitoring"
    description = "Change detection vs. previous scan results"
    category = "recon"
    tools_required = []
    tools_optional = []

    def run(self) -> Dict:
        domain = self.ctx["domain"]
        base_dir = self.output_dir.parent  # results/<domain>/

        # Find previous run directories (excluding current)
        current = self.output_dir.name
        prev_runs = sorted([
            d for d in base_dir.iterdir()
            if d.is_dir() and d.name != current
        ], reverse=True)

        if not prev_runs:
            self.log("No previous runs found. Skipping diff.", level="warn")
            return self.get_results()

        prev_dir = prev_runs[0]
        self.log(f"Comparing against: {prev_dir.name}")

        # --- Subdomain diff ---
        prev_subs = self._load_previous(prev_dir, "recon_subdomain_enum/all_subdomains.txt")
        curr_subs = set(self.ctx.get("subdomains", []))

        new_subs = curr_subs - prev_subs
        removed_subs = prev_subs - curr_subs

        if new_subs:
            self.log(f"NEW subdomains: {len(new_subs)}")
            for s in sorted(new_subs):
                self.findings.append({
                    "type": "new_subdomain",
                    "value": s,
                    "severity": "info",
                })

        if removed_subs:
            self.log(f"Removed subdomains: {len(removed_subs)}")

        # --- Alive hosts diff ---
        prev_alive = self._load_previous(prev_dir, "recon_technologies/alive_urls.txt")
        curr_alive = set(self.ctx.get("alive_urls", []))

        new_alive = curr_alive - prev_alive
        if new_alive:
            self.log(f"NEW alive hosts: {len(new_alive)}")
            for h in sorted(new_alive):
                self.findings.append({
                    "type": "new_alive_host",
                    "value": h,
                    "severity": "info",
                })

        # --- Open ports diff ---
        prev_ports = self._load_previous(prev_dir, "recon_port_scan/open_ports.txt")
        curr_port_entries = self.ctx.get("port_results", [])
        curr_ports = {f"{e.get('host', '')}:{e.get('port', '')}" for e in curr_port_entries}

        new_ports = curr_ports - prev_ports
        if new_ports:
            self.log(f"NEW open ports: {len(new_ports)}")
            for p in sorted(new_ports):
                self.findings.append({
                    "type": "new_open_port",
                    "value": p,
                    "severity": "medium",
                })

        # Write diff report
        diff_report = {
            "previous_run": str(prev_dir),
            "new_subdomains": sorted(new_subs),
            "removed_subdomains": sorted(removed_subs),
            "new_alive_hosts": sorted(new_alive),
            "new_open_ports": sorted(new_ports),
        }
        self.write_json(self.phase_dir / "diff_report.json", diff_report)

        summary = self.phase_dir / "changes.txt"
        lines = []
        if new_subs:
            lines.append(f"=== NEW SUBDOMAINS ({len(new_subs)}) ===")
            lines.extend(sorted(new_subs))
            lines.append("")
        if new_alive:
            lines.append(f"=== NEW ALIVE HOSTS ({len(new_alive)}) ===")
            lines.extend(sorted(new_alive))
            lines.append("")
        if new_ports:
            lines.append(f"=== NEW OPEN PORTS ({len(new_ports)}) ===")
            lines.extend(sorted(new_ports))
        self.write_lines(summary, lines)

        self.log(f"Change detection findings: {len(self.findings)}")
        return self.get_results()

    def _load_previous(self, prev_dir: Path, relative_path: str) -> Set[str]:
        """Load a text file from the previous run into a set."""
        filepath = prev_dir / relative_path
        if filepath.exists():
            return self.read_lines(filepath)
        return set()
