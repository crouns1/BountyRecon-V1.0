"""
scope.py — Scope enforcement module for BountyRecon.

Parses in-scope and out-of-scope definitions, then provides filtering
functions to ensure no out-of-scope assets enter the pipeline.
"""

import re
import ipaddress
from pathlib import Path
from typing import List, Set
from urllib.parse import urlparse


class ScopeEnforcer:
    """Loads scope rules and filters assets to stay within program bounds."""

    def __init__(self, inscope_file: str = "", outscope_file: str = ""):
        self.in_scope_domains: Set[str] = set()
        self.out_scope_domains: Set[str] = set()
        self.out_scope_ips: Set[str] = set()
        self.out_scope_cidrs: list = []
        self.out_scope_patterns: List[re.Pattern] = []

        if inscope_file and Path(inscope_file).exists():
            self._load_inscope(inscope_file)
        if outscope_file and Path(outscope_file).exists():
            self._load_outscope(outscope_file)

    def _load_inscope(self, filepath: str):
        """Load in-scope domains (one per line, supports wildcard *.example.com)."""
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    cleaned = self._normalize_domain_rule(line)
                    self.in_scope_domains.add(cleaned.lower())

    def _load_outscope(self, filepath: str):
        """
        Load out-of-scope rules. Supports:
          - Domains: example.com, *.staging.example.com
          - IPs: 192.168.1.1
          - CIDRs: 10.0.0.0/8
          - Regex patterns: regex:.*\\.internal\\..*
        """
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Regex pattern
                if line.startswith("regex:"):
                    pattern = line[6:].strip()
                    self.out_scope_patterns.append(
                        re.compile(pattern, re.IGNORECASE)
                    )
                    continue

                # CIDR notation
                if "/" in line:
                    try:
                        self.out_scope_cidrs.append(ipaddress.ip_network(line, strict=False))
                        continue
                    except ValueError:
                        pass

                # Plain IP
                try:
                    ipaddress.ip_address(line)
                    self.out_scope_ips.add(line)
                    continue
                except ValueError:
                    pass

                # Domain (possibly with wildcard)
                cleaned = self._normalize_domain_rule(line)
                self.out_scope_domains.add(cleaned)

    def _normalize_domain_rule(self, value: str) -> str:
        value = value.strip()
        wildcard = value.startswith("*.")
        parsed = urlparse(value if "://" in value else f"//{value.lstrip('*.')}")
        host = parsed.netloc or parsed.path
        host = host.split("/", 1)[0].split("@")[-1].split(":", 1)[0].strip(".").lower()
        return host if not wildcard else host

    def is_in_scope(self, asset: str) -> bool:
        """
        Returns True if the asset is in scope and NOT out of scope.
        An asset is considered in-scope if it matches any in-scope domain
        (or if no in-scope list is defined) AND does not match any out-of-scope rule.
        """
        asset_lower = asset.lower().strip()

        # Strip protocol if present
        if "://" in asset_lower:
            asset_lower = asset_lower.split("://", 1)[1]
        # Strip port if present
        asset_lower = asset_lower.split(":")[0]
        # Strip trailing path
        asset_lower = asset_lower.split("/")[0]

        # Check out-of-scope first (deny takes priority)
        if self._matches_outscope(asset_lower):
            return False

        # If we have in-scope domains defined, the asset must match one
        if self.in_scope_domains:
            return self._matches_inscope(asset_lower)

        return True

    def _matches_inscope(self, domain: str) -> bool:
        """Check if domain matches any in-scope definition."""
        for scope_domain in self.in_scope_domains:
            if domain == scope_domain or domain.endswith("." + scope_domain):
                return True
        return False

    def _matches_outscope(self, asset: str) -> bool:
        """Check if asset matches any out-of-scope rule."""
        # Check domain rules
        for oos_domain in self.out_scope_domains:
            if asset == oos_domain or asset.endswith("." + oos_domain):
                return True

        # Check IP rules
        if asset in self.out_scope_ips:
            return True

        # Check CIDR rules
        try:
            ip = ipaddress.ip_address(asset)
            for cidr in self.out_scope_cidrs:
                if ip in cidr:
                    return True
        except ValueError:
            pass

        # Check regex patterns
        for pattern in self.out_scope_patterns:
            if pattern.search(asset):
                return True

        return False

    def filter_assets(self, assets: List[str]) -> List[str]:
        """Filter a list of assets, returning only those that are in scope."""
        filtered = [a for a in assets if self.is_in_scope(a)]
        removed = len(assets) - len(filtered)
        if removed > 0:
            print(f"  [SCOPE] Filtered out {removed} out-of-scope asset(s).")
        return filtered

    def get_stats(self) -> dict:
        return {
            "in_scope_domains": len(self.in_scope_domains),
            "out_scope_domains": len(self.out_scope_domains),
            "out_scope_ips": len(self.out_scope_ips),
            "out_scope_cidrs": len(self.out_scope_cidrs),
            "out_scope_patterns": len(self.out_scope_patterns),
        }
