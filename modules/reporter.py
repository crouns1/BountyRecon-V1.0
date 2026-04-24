"""
reporter.py — Report Generator for BountyRecon v2.0

Produces structured Markdown and JSON reports summarizing
all findings across 30+ modules in three categories.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any


def generate_report(
    domain: str,
    output_dir: Path,
    context: dict,
    results: List[Dict],
    scope_stats: dict,
    elapsed: float,
):
    """Generate both JSON and Markdown summary reports."""
    report_data = _build_report_data(
        domain, context, results, scope_stats, elapsed
    )

    # JSON report
    json_path = output_dir / "report.json"
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    # Markdown report
    md_path = output_dir / "report.md"
    md_content = _render_markdown(report_data)
    with open(md_path, "w") as f:
        f.write(md_content)

    print(f"\n  [+] Reports saved:")
    print(f"      JSON:     {json_path}")
    print(f"      Markdown: {md_path}")

    return report_data, json_path, md_path


def _build_report_data(
    domain: str,
    context: dict,
    results: List[Dict],
    scope_stats: dict,
    elapsed: float,
) -> Dict[str, Any]:

    # Categorize module results
    recon_results = [r for r in results if r.get("category") == "recon"]
    exploit_results = [r for r in results if r.get("category") == "exploit"]
    misc_results = [r for r in results if r.get("category") == "misc"]

    # Vulnerability severity breakdown
    sev_map: Dict[str, int] = {}
    for v in context.get("vuln_findings", []):
        s = v.get("severity", "unknown").lower()
        sev_map[s] = sev_map.get(s, 0) + 1

    # Technology summary from alive_hosts
    tech_map: Dict[str, int] = {}
    for host in context.get("alive_hosts", []):
        for t in host.get("tech", []):
            tech_map[t] = tech_map.get(t, 0) + 1

    # Port summary
    port_map: Dict[int, int] = {}
    for entry in context.get("port_results", []):
        p = entry.get("port", 0)
        port_map[p] = port_map.get(p, 0) + 1

    return {
        "meta": {
            "target": domain,
            "generated_at": datetime.now().isoformat(),
            "elapsed_seconds": round(elapsed, 1),
            "modules_executed": [r.get("module") for r in results],
            "scope_enforcement": scope_stats,
        },
        "summary": {
            "total_subdomains": len(context.get("subdomains", [])),
            "alive_hosts": len(context.get("alive_hosts", [])),
            "open_ports": len(context.get("port_results", [])),
            "discovered_endpoints": len(context.get("dir_findings", [])),
            "gathered_urls": len(context.get("gathered_urls", [])),
            "parameters_found": len(context.get("parameters", [])),
            "vulnerabilities": len(context.get("vuln_findings", [])),
            "vulnerability_breakdown": sev_map,
            "total_module_findings": sum(
                r.get("findings_count", 0) for r in results
            ),
        },
        "technologies": dict(sorted(
            tech_map.items(), key=lambda x: x[1], reverse=True
        )),
        "top_ports": dict(sorted(
            port_map.items(), key=lambda x: x[1], reverse=True
        )[:20]),
        "recon_results": recon_results,
        "exploit_results": exploit_results,
        "misc_results": misc_results,
        "alive_hosts": context.get("alive_hosts", []),
        "vulnerability_findings": context.get("vuln_findings", []),
    }


def _render_markdown(data: Dict) -> str:
    meta = data["meta"]
    summary = data["summary"]

    lines = [
        f"# BountyRecon v2.0 Report: {meta['target']}",
        "",
        f"**Generated:** {meta['generated_at']}  ",
        f"**Elapsed:** {meta['elapsed_seconds']}s  ",
        f"**Modules Executed:** {', '.join(meta['modules_executed'])}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Subdomains Discovered | {summary['total_subdomains']} |",
        f"| Alive Hosts | {summary['alive_hosts']} |",
        f"| Open Ports | {summary['open_ports']} |",
        f"| Discovered Endpoints | {summary['discovered_endpoints']} |",
        f"| Gathered URLs | {summary['gathered_urls']} |",
        f"| Parameters Found | {summary['parameters_found']} |",
        f"| Vulnerabilities | {summary['vulnerabilities']} |",
        f"| Total Module Findings | {summary['total_module_findings']} |",
        "",
    ]

    # Vulnerability breakdown
    if summary.get("vulnerability_breakdown"):
        lines.append("### Vulnerability Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
            count = summary["vulnerability_breakdown"].get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")
        lines.append("")

    # Scope enforcement
    scope = meta.get("scope_enforcement", {})
    if scope:
        lines.append("### Scope Enforcement")
        lines.append("")
        for k, v in scope.items():
            lines.append(f"- {k}: {v}")
        lines.append("")

    # Technologies
    if data.get("technologies"):
        lines.append("## Technologies Detected")
        lines.append("")
        lines.append("| Technology | Hosts |")
        lines.append("|------------|-------|")
        for tech, count in list(data["technologies"].items())[:30]:
            lines.append(f"| {tech} | {count} |")
        lines.append("")

    # Top Ports
    if data.get("top_ports"):
        lines.append("## Top Open Ports")
        lines.append("")
        lines.append("| Port | Occurrences |")
        lines.append("|------|-------------|")
        for port, count in data["top_ports"].items():
            lines.append(f"| {port} | {count} |")
        lines.append("")

    # Alive Hosts
    hosts = data.get("alive_hosts", [])
    if hosts:
        lines.append("## Alive Hosts")
        lines.append("")
        lines.append("| URL | Status | Title | Web Server |")
        lines.append("|-----|--------|-------|------------|")
        for h in hosts[:100]:
            url = h.get("url", "")
            sc = h.get("status_code", "")
            title = str(h.get("title", ""))[:50]
            ws = h.get("webserver", "")
            lines.append(f"| {url} | {sc} | {title} | {ws} |")
        lines.append("")

    # Module results by category
    for cat_label, cat_key in [
        ("Recon Modules", "recon_results"),
        ("Exploit Modules", "exploit_results"),
        ("Misc Modules", "misc_results"),
    ]:
        cat_results = data.get(cat_key, [])
        if not cat_results:
            continue
        lines.append(f"## {cat_label}")
        lines.append("")
        for r in cat_results:
            mod = r.get("module", "unknown")
            desc = r.get("description", "")
            count = r.get("findings_count", 0)
            lines.append(f"### {mod}")
            lines.append(f"*{desc}* — **{count} findings**")
            lines.append("")
            for f_item in r.get("findings", [])[:20]:
                if isinstance(f_item, dict):
                    sev = f_item.get("severity", "").upper()
                    name = f_item.get("name", str(f_item))
                    matched = f_item.get("matched_at", "")
                    prefix = f"[{sev}] " if sev else ""
                    suffix = f" — `{matched}`" if matched else ""
                    lines.append(f"- {prefix}{name}{suffix}")
                else:
                    lines.append(f"- {f_item}")
            if count > 20:
                lines.append(f"- *...and {count - 20} more*")
            lines.append("")

    # Critical vulnerabilities
    vulns = data.get("vulnerability_findings", [])
    if vulns:
        lines.append("## Vulnerabilities (Detail)")
        lines.append("")
        for v in vulns[:50]:
            sev = v.get("severity", "unknown").upper()
            name = v.get("name", "Unknown")
            tid = v.get("template_id", "")
            matched = v.get("matched_at", "")
            desc = str(v.get("description", ""))[:200]

            lines.append(f"### [{sev}] {name}")
            lines.append("")
            if tid:
                lines.append(f"- **Template:** `{tid}`")
            if matched:
                lines.append(f"- **Matched At:** `{matched}`")
            if desc:
                lines.append(f"- **Description:** {desc}")
            refs = v.get("reference", [])
            if refs:
                lines.append(f"- **References:** {', '.join(refs[:5])}")
            lines.append("")

    lines.append("---")
    lines.append("*Report generated by BountyRecon v2.0 Framework*")

    return "\n".join(lines)
