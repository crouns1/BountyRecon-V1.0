"""
Permutation — alterx, gotator, dnsgen, altdns
"""

from typing import Dict, Set
from modules.base import BaseModule


class Permutation(BaseModule):
    name = "permutation"
    description = "Subdomain permutation and mutation generation"
    category = "misc"
    tools_required = ["alterx"]
    tools_optional = ["gotator", "dnsgen", "puredns", "dnsx"]

    def run(self) -> Dict:
        subs = self.ctx.get("subdomains", [])
        if not subs:
            self.log("No subdomains for permutation.", level="warn")
            return self.get_results()

        cfg = self.config
        sub_file = self.write_targets(subs, "input_subdomains.txt")
        all_permutations: Set[str] = set()

        # --- alterx ---
        if cfg.get("use_alterx", True) and self.tool_exists("alterx"):
            out = self.phase_dir / "alterx.txt"
            self.exec([
                "alterx", "-l", str(sub_file),
                "-o", str(out), "-silent",
                "-en",
            ], timeout=300, label="alterx")
            all_permutations |= self.read_lines(out)

        # --- gotator ---
        if cfg.get("use_gotator", False) and self.tool_exists("gotator"):
            out = self.phase_dir / "gotator.txt"
            result = self.exec([
                "gotator", "-sub", str(sub_file),
                "-depth", str(cfg.get("depth", 1)),
                "-numbers", "3", "-mindup",
            ], timeout=300, label="gotator")
            if result and result.stdout:
                with open(out, "w") as f:
                    f.write(result.stdout)
                all_permutations |= self.read_lines(out)

        # --- dnsgen ---
        if cfg.get("use_dnsgen", False) and self.tool_exists("dnsgen"):
            out = self.phase_dir / "dnsgen.txt"
            result = self.exec([
                "dnsgen", str(sub_file),
            ], timeout=300, label="dnsgen")
            if result and result.stdout:
                with open(out, "w") as f:
                    f.write(result.stdout)
                all_permutations |= self.read_lines(out)

        self.log(f"Permutations generated: {len(all_permutations)}")
        perm_file = self.write_lines(self.phase_dir / "all_permutations.txt", all_permutations)

        # --- Resolve permutations with puredns or dnsx ---
        resolved: Set[str] = set()
        if cfg.get("resolve", True):
            if self.tool_exists("puredns"):
                out = self.phase_dir / "resolved.txt"
                self.exec([
                    "puredns", "resolve", str(perm_file),
                    "-r", cfg.get("resolvers", "/usr/share/wordlists/resolvers.txt"),
                    "-w", str(out), "-q",
                ], timeout=1800, label="puredns")
                resolved = self.read_lines(out)

            elif self.tool_exists("dnsx"):
                out = self.phase_dir / "resolved.txt"
                self.exec([
                    "dnsx", "-l", str(perm_file),
                    "-silent", "-o", str(out),
                    "-rate-limit", str(cfg.get("rate_limit", 500)),
                ], timeout=1200, label="dnsx")
                resolved = self.read_lines(out)

        if resolved:
            # Scope filter and merge into pipeline
            new_subs = self.filter_scope(list(resolved))
            existing = set(self.ctx.get("subdomains", []))
            new_only = [s for s in new_subs if s not in existing]
            self.ctx["subdomains"] = sorted(existing | set(new_subs))
            self.log(f"New subdomains from permutation: {len(new_only)}")

        self.findings = [{"subdomain": s} for s in resolved]
        self.write_json(self.phase_dir / "permutation_results.json",
                        {"generated": len(all_permutations), "resolved": len(resolved)})
        return self.get_results()
