"""
base.py — Base module class for BountyRecon pipeline.

All modules inherit from BaseModule, providing:
  - Consistent interface (setup, run, cleanup)
  - Output directory management
  - Tool availability checking
  - Subprocess execution with rate limiting and timeouts
  - Scope enforcement at the module level
"""

import subprocess
import shutil
import json
from pathlib import Path
from typing import Any, List, Dict, Optional, Set


class BaseModule:
    """Base class for all recon/exploit/misc modules."""

    name: str = "base"
    description: str = ""
    category: str = "uncategorized"       # recon | exploit | misc
    tools_required: List[str] = []        # CLI tools this module needs
    tools_optional: List[str] = []        # Nice-to-have tools

    def __init__(self, output_dir: Path, config: dict, scope, context: dict):
        """
        Args:
            output_dir:  Root output directory for this scan run
            config:      Parsed config.yaml section for this module
            scope:       ScopeEnforcer instance
            context:     Shared pipeline context dict (results from prior phases)
        """
        self.output_dir = output_dir
        self.config = config
        self.scope = scope
        self.ctx = context
        self.phase_dir = output_dir / f"{self.category}_{self.name}"
        self.phase_dir.mkdir(parents=True, exist_ok=True)
        self.findings: List[Dict] = []

    # ------------------------------------------------------------------
    # Tool management
    # ------------------------------------------------------------------

    @classmethod
    def check_tools(cls) -> Dict[str, bool]:
        """Return availability status of all required + optional tools."""
        status = {}
        for tool in cls.tools_required + cls.tools_optional:
            status[tool] = shutil.which(tool) is not None
        return status

    @classmethod
    def is_available(cls) -> bool:
        """Returns True if at least one required tool is installed."""
        if not cls.tools_required:
            return True
        return any(shutil.which(t) is not None for t in cls.tools_required)

    def tool_exists(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def config_get(self, key: str, default: Any = None, *aliases: str) -> Any:
        """Read a config value with backward-compatible aliases."""
        for candidate in (key, *aliases):
            if candidate in self.config:
                return self.config[candidate]
        return default

    # ------------------------------------------------------------------
    # Subprocess helpers
    # ------------------------------------------------------------------

    def exec(
        self,
        cmd: List[str],
        timeout: int = 600,
        label: str = "",
    ) -> Optional[subprocess.CompletedProcess]:
        """Run a subprocess with timeout handling."""
        tool = cmd[0] if cmd else "unknown"
        label = label or tool

        if not self.tool_exists(tool):
            self.log(f"{label} not found — skipping", level="warn")
            return None

        self.log(f"Running {label}...")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired:
            self.log(f"{label} timed out after {timeout}s", level="warn")
            return None
        except Exception as e:
            self.log(f"{label} error: {e}", level="error")
            return None

    # ------------------------------------------------------------------
    # Scope helpers
    # ------------------------------------------------------------------

    def filter_scope(self, assets: List[str]) -> List[str]:
        """Filter assets through scope enforcer."""
        return self.scope.filter_assets(assets)

    def in_scope(self, asset: str) -> bool:
        return self.scope.is_in_scope(asset)

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    def read_lines(self, filepath: Path) -> Set[str]:
        if not filepath.exists():
            return set()
        with open(filepath) as f:
            return {line.strip() for line in f if line.strip()}

    def write_lines(self, filepath: Path, lines) -> Path:
        with open(filepath, "w") as f:
            f.write("\n".join(sorted(set(lines))))
        return filepath

    def write_json(self, filepath: Path, data) -> Path:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath

    def write_targets(self, hosts: List[str], filename: str = "targets.txt") -> Path:
        """Write a target list file and return its path."""
        p = self.phase_dir / filename
        self.write_lines(p, hosts)
        return p

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log(self, msg: str, level: str = "info"):
        icons = {"info": "+", "warn": "!", "error": "-", "step": "*"}
        icon = icons.get(level, "+")
        print(f"  [{icon}] [{self.name}] {msg}")

    # ------------------------------------------------------------------
    # Pipeline interface
    # ------------------------------------------------------------------

    def run(self) -> Dict:
        """Execute the module. Override in subclasses. Returns results dict."""
        raise NotImplementedError

    def get_results(self) -> Dict:
        """Return structured results for the reporter."""
        return {
            "module": self.name,
            "category": self.category,
            "description": self.description,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "output_dir": str(self.phase_dir),
        }
