"""
Port Scanning — naabu, masscan, nmap, rustscan
"""

import json
from pathlib import Path
from typing import Dict, List

from modules.base import BaseModule


class PortScan(BaseModule):
    name = "port_scan"
    description = "Fast port scanning on alive hosts"
    category = "recon"
    tools_required = ["naabu"]
    tools_optional = ["masscan", "nmap", "rustscan"]

    def run(self) -> Dict:
        hosts = self._get_hosts()
        if not hosts:
            self.log("No hosts to scan.", level="warn")
            return self.get_results()

        hosts = self.filter_scope(hosts)
        input_file = self.write_targets(hosts)
        cfg = self.config
        all_ports: List[Dict] = []

        # --- naabu ---
        if cfg.get("use_naabu", True) and self.tool_exists("naabu"):
            out = self.phase_dir / "naabu.json"
            self.exec([
                "naabu", "-list", str(input_file),
                "-top-ports", str(self.config_get("top_ports", "1000")),
                "-rate", str(self.config_get("rate", 1000, "rate_limit")),
                "-silent", "-json", "-o", str(out),
            ], timeout=1200, label="naabu")
            all_ports.extend(self._parse_naabu(out))

        # --- masscan ---
        if self.config_get("use_masscan", False) and self.tool_exists("masscan"):
            out = self.phase_dir / "masscan.json"
            ports = self.config_get("masscan_ports", "1-65535")
            self.exec([
                "masscan", "-iL", str(input_file),
                "-p", str(ports),
                "--rate", str(self.config_get("masscan_rate", 10000)),
                "-oJ", str(out),
            ], timeout=1800, label="masscan")
            all_ports.extend(self._parse_masscan(out))

        # --- nmap service detection on found ports ---
        if self.config_get("use_nmap_service", False, "use_nmap_sV") and self.tool_exists("nmap") and all_ports:
            self._nmap_service_scan(all_ports)

        # Deduplicate
        seen = set()
        unique = []
        for p in all_ports:
            key = f"{p['host']}:{p['port']}"
            if key not in seen:
                seen.add(key)
                unique.append(p)

        self.write_json(self.phase_dir / "open_ports.json", unique)

        lines = [f"{p['host']}:{p['port']}" for p in unique]
        self.write_lines(self.phase_dir / "open_ports.txt", lines)

        # Build host -> ports mapping
        host_ports: Dict[str, List[int]] = {}
        for p in unique:
            host_ports.setdefault(p["host"], []).append(p["port"])
        self.write_json(self.phase_dir / "port_summary.json", host_ports)

        self.log(f"Open ports: {len(unique)} across {len(host_ports)} host(s)")
        self.ctx["port_results"] = unique
        self.ctx["host_ports"] = host_ports
        self.findings = unique
        return self.get_results()

    def _get_hosts(self) -> List[str]:
        alive = self.ctx.get("alive_hosts", [])
        if alive:
            return list({h.get("host", "") for h in alive if h.get("host")})
        return self.ctx.get("subdomains", [])

    def _parse_naabu(self, path: Path) -> List[Dict]:
        results = []
        if not path.exists():
            return results
        for line in open(path):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                host = e.get("host", e.get("ip", ""))
                port = e.get("port", 0)
                if host and port:
                    results.append({"host": host, "port": port, "source": "naabu"})
            except json.JSONDecodeError:
                continue
        return results

    def _parse_masscan(self, path: Path) -> List[Dict]:
        results = []
        if not path.exists():
            return results
        try:
            data = json.loads(path.read_text())
            for entry in data:
                ip = entry.get("ip", "")
                for p in entry.get("ports", []):
                    results.append({
                        "host": ip,
                        "port": p.get("port", 0),
                        "proto": p.get("proto", "tcp"),
                        "source": "masscan",
                    })
        except (json.JSONDecodeError, KeyError):
            pass
        return results

    def _nmap_service_scan(self, ports: List[Dict]):
        """Run nmap -sV on discovered ports for service fingerprinting."""
        host_ports: Dict[str, List[int]] = {}
        for p in ports:
            host_ports.setdefault(p["host"], []).append(p["port"])

        for host, port_list in list(host_ports.items())[:50]:  # cap at 50 hosts
            port_str = ",".join(str(p) for p in sorted(set(port_list)))
            out = self.phase_dir / f"nmap_{host.replace('.', '_')}.xml"
            self.exec([
                "nmap", "-sV", "--open", "-T4",
                "-p", port_str, host,
                "-oX", str(out),
            ], timeout=300, label=f"nmap-sV:{host}")
