#!/usr/bin/env python3
"""
bountyrecon.py — Professional Automated Reconnaissance Framework
for HackerOne Bug Bounty Programs (v2.0)

Chains 40+ industry-standard tools across Recon, Exploitation, and
Miscellaneous categories into a fully automated pipeline with strict
scope enforcement.

Usage:
    python3 bountyrecon.py -d target.com --full
    python3 bountyrecon.py -d target.com --recon
    python3 bountyrecon.py -d target.com --modules subdomain_enum,technologies,vuln_scanners
    python3 bountyrecon.py -d target.com --exploit --inscope scope/inscope.txt
"""

import argparse
import shutil
import sys
import time
from urllib.parse import urlparse
import yaml
from datetime import datetime
from pathlib import Path

from modules.scope import ScopeEnforcer

# ---------------------------------------------------------------------------
# Module Registry — all modules in pipeline execution order
# ---------------------------------------------------------------------------
from modules.recon.subdomain_enum import SubdomainEnum
from modules.recon.technologies import Technologies
from modules.recon.port_scan import PortScan
from modules.recon.screenshots import Screenshots
from modules.recon.content_discovery import ContentDiscovery
from modules.recon.content_filtering import ContentFiltering
from modules.recon.links import Links
from modules.recon.parameters import Parameters
from modules.recon.fuzzing import Fuzzing
from modules.recon.monitoring import Monitoring
from modules.recon.waf_evasion import WafEvasion

from modules.exploit.cors import CORSMisconfig
from modules.exploit.crlf import CRLFInjection
from modules.exploit.csrf import CSRF
from modules.exploit.sqli import SQLInjection
from modules.exploit.xss import XSSInjection
from modules.exploit.xxe import XXEInjection
from modules.exploit.ssrf import SSRF
from modules.exploit.open_redirect import OpenRedirect
from modules.exploit.smuggling import RequestSmuggling
from modules.exploit.command_injection import CommandInjection
from modules.exploit.lfi import LFI
from modules.exploit.directory_traversal import DirectoryTraversal
from modules.exploit.graphql import GraphQL
from modules.exploit.header_injection import HeaderInjection
from modules.exploit.ssti import SSTI
from modules.exploit.cache_poisoning import CachePoisoning
from modules.exploit.idor import IDOR
from modules.exploit.race_condition import RaceCondition
from modules.exploit.deserialization import InsecureDeserialization
from modules.exploit.postmessage import PostMessage
from modules.exploit.clickjacking import Clickjacking

from modules.misc.passwords import Passwords
from modules.misc.secrets import Secrets
from modules.misc.git_exposure import GitExposure
from modules.misc.buckets import Buckets
from modules.misc.cms import CMS
from modules.misc.jwt import JWT
from modules.misc.subdomain_takeover import SubdomainTakeover
from modules.misc.vuln_scanners import VulnScanners
from modules.misc.forbidden_bypass import ForbiddenBypass
from modules.misc.permutation import Permutation
from modules.misc.origin_ip import OriginIP
from modules.misc.session_security import SessionSecurity
from modules.misc.api_exposure import APIExposure
from modules.misc.rate_limiting import RateLimiting

from modules.reporter import generate_report
from modules.ollama_analyzer import OllamaAnalyzer

# Pipeline execution order
RECON_MODULES = [
    SubdomainEnum, Technologies, PortScan, Screenshots,
    ContentDiscovery, ContentFiltering, Links, Parameters,
    Fuzzing, Monitoring, WafEvasion,
]

EXPLOIT_MODULES = [
    CORSMisconfig, CRLFInjection, CSRF, SQLInjection, XSSInjection,
    XXEInjection, SSRF, OpenRedirect, RequestSmuggling, CommandInjection,
    LFI, DirectoryTraversal, GraphQL, HeaderInjection, SSTI,
    CachePoisoning, IDOR, RaceCondition, InsecureDeserialization, PostMessage,
    Clickjacking,
]

MISC_MODULES = [
    Passwords, Secrets, GitExposure, Buckets, CMS, JWT,
    SubdomainTakeover, VulnScanners, ForbiddenBypass, Permutation, OriginIP,
    SessionSecurity, APIExposure, RateLimiting,
]

ALL_MODULES = RECON_MODULES + EXPLOIT_MODULES + MISC_MODULES
MODULE_MAP = {m.name: m for m in ALL_MODULES}


BANNER = r"""
 ____                    _         ____
| __ )  ___  _   _ _ __ | |_ _   _|  _ \ ___  ___ ___  _ __
|  _ \ / _ \| | | | '_ \| __| | | | |_) / _ \/ __/ _ \| '_ \
| |_) | (_) | |_| | | | | |_| |_| |  _ <  __/ (_| (_) | | | |
|____/ \___/ \__,_|_| |_|\__|\__, |_| \_\___|\___\___/|_| |_|
                              |___/
    Professional Bug Bounty Reconnaissance Framework  v2.0
    ─────────────────────────────────────────────────────
    Modules: {mod_count} | Tools: 40+ | Categories: Recon · Exploit · Misc
"""


def normalize_target(target: str) -> str:
    """Normalize a user-supplied target into a bare hostname/domain."""
    value = (target or "").strip().lower()
    if not value:
        return ""

    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.netloc or parsed.path
    host = host.split("/", 1)[0].split("@")[-1].split(":", 1)[0].strip(".")
    return host


def parse_args():
    p = argparse.ArgumentParser(
        description="BountyRecon v2.0 — Automated Bug Bounty Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target — not required for utility commands
    p.add_argument("-d", "--domain", default="", help="Target root domain")

    # Scope
    p.add_argument("--inscope", default="", help="In-scope domains file")
    p.add_argument("--outscope", default="", help="Out-of-scope rules file")

    # Module selection (mutually exclusive)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true",
                      help="Run ALL modules (recon + exploit + misc)")
    mode.add_argument("--recon", action="store_true",
                      help="Run recon modules only")
    mode.add_argument("--exploit", action="store_true",
                      help="Run exploit modules only")
    mode.add_argument("--misc", action="store_true",
                      help="Run miscellaneous modules only")
    mode.add_argument("--modules", type=str, default="",
                      help="Comma-separated list of specific module names")

    # Config & output
    p.add_argument("--config", default="config.yaml", help="YAML config file")
    p.add_argument("--output", default="results", help="Base output directory")
    p.add_argument("--delay", type=float, default=0,
                   help="Delay between modules (seconds)")
    p.add_argument("--ollama-analyze", action="store_true",
                   help="Generate an AI assessment with a local Ollama instance")
    p.add_argument("--ollama-model", default="",
                   help="Override the Ollama model for AI assessment")

    # Utility
    p.add_argument("--list-modules", action="store_true",
                   help="List all available modules and exit")
    p.add_argument("--check-tools", action="store_true",
                   help="Check tool availability and exit")

    return p.parse_args()


def load_config(path: str) -> dict:
    if Path(path).exists():
        with open(path) as f:
            return yaml.safe_load(f) or {}
    print(f"[!] Config not found: {path}. Using defaults.")
    return {}


def list_modules():
    """Print all available modules with tool status."""
    print("\n  Available Modules:\n")
    categories = [
        ("RECON", RECON_MODULES),
        ("EXPLOITATION", EXPLOIT_MODULES),
        ("MISCELLANEOUS", MISC_MODULES),
    ]
    for cat_name, modules in categories:
        print(f"  ╔══ {cat_name} {'═' * (50 - len(cat_name))}")
        for mod in modules:
            tools = mod.check_tools()
            avail = "✓" if mod.is_available() else "✗"
            tool_str = ", ".join(
                f"{'✓' if v else '✗'}{k}" for k, v in tools.items()
            )
            print(f"  ║  [{avail}] {mod.name:<25} {mod.description}")
            if tool_str:
                print(f"  ║      Tools: {tool_str}")
        print(f"  ╚{'═' * 55}")
        print()


def check_all_tools():
    """Print availability of all tools."""
    print("\n  Tool Availability Check:\n")
    all_tools = set()
    for mod in ALL_MODULES:
        all_tools.update(mod.tools_required + mod.tools_optional)

    installed = 0
    for tool in sorted(all_tools):
        available = shutil.which(tool) is not None
        icon = "✓" if available else "✗"
        status = "installed" if available else "MISSING"
        print(f"  [{icon}] {tool:<25} {status}")
        if available:
            installed += 1

    print(f"\n  Total: {installed}/{len(all_tools)} tools installed\n")


def resolve_modules(args) -> list:
    """Determine which module classes to run based on CLI args."""
    if args.full:
        return list(ALL_MODULES)
    elif args.recon:
        return list(RECON_MODULES)
    elif args.exploit:
        return list(EXPLOIT_MODULES)
    elif args.misc:
        return list(MISC_MODULES)
    elif args.modules:
        names = [n.strip() for n in args.modules.split(",")]
        selected = []
        for name in names:
            if name in MODULE_MAP:
                selected.append(MODULE_MAP[name])
            else:
                print(f"[!] Unknown module: {name}")
                print(f"    Available: {', '.join(sorted(MODULE_MAP.keys()))}")
                sys.exit(1)
        return selected
    else:
        return list(RECON_MODULES)


def main():
    args = parse_args()
    print(BANNER.format(mod_count=len(ALL_MODULES)))

    if args.list_modules:
        list_modules()
        return

    if args.check_tools:
        check_all_tools()
        return

    normalized_domain = normalize_target(args.domain)
    if not normalized_domain:
        print("[-] Error: -d/--domain is required for scanning.")
        print("    Usage: python3 bountyrecon.py -d target.com --full")
        sys.exit(1)
    if normalized_domain != args.domain:
        print(f"  [*] Normalized target: {args.domain} -> {normalized_domain}")
    args.domain = normalized_domain

    module_classes = resolve_modules(args)
    config = load_config(args.config)

    # Initialize scope
    scope = ScopeEnforcer(inscope_file=args.inscope, outscope_file=args.outscope)
    if not args.inscope:
        scope.in_scope_domains.add(args.domain.lower())

    # Setup output directory
    date_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    output_dir = Path(args.output) / args.domain / date_str
    output_dir.mkdir(parents=True, exist_ok=True)

    # Shared pipeline context
    context = {
        "domain": args.domain,
        "subdomains": [],
        "alive_hosts": [],
        "alive_urls": [],
        "port_results": [],
        "host_ports": {},
        "dir_findings": [],
        "gathered_urls": [],
        "crawled_urls": [],
        "parameters": [],
        "vuln_findings": [],
    }

    print(f"  Target     : {args.domain}")
    print(f"  Output     : {output_dir}")
    print(f"  Modules    : {len(module_classes)}")
    print(f"  Scope      : {scope.get_stats()}")
    print()

    # Execute pipeline
    all_results = []
    start_time = time.time()
    total = len(module_classes)

    for idx, ModClass in enumerate(module_classes, 1):
        header = f"[{idx}/{total}] {ModClass.category.upper()} :: {ModClass.name}"
        print(f"\n{'━' * 60}")
        print(f"  {header}")
        print(f"  {ModClass.description}")
        print(f"{'━' * 60}")

        if not ModClass.is_available():
            missing = [t for t in ModClass.tools_required
                       if not shutil.which(t)]
            print(f"  [!] Skipping — missing required tools: {', '.join(missing)}")
            continue

        mod_config = config.get(ModClass.name, {})

        try:
            mod = ModClass(
                output_dir=output_dir,
                config=mod_config,
                scope=scope,
                context=context,
            )
            result = mod.run()
            all_results.append(result)
        except Exception as e:
            print(f"  [-] Module {ModClass.name} failed: {e}")
            import traceback
            traceback.print_exc()

        if args.delay and idx < total:
            time.sleep(args.delay)

    # Generate report
    elapsed = time.time() - start_time
    print(f"\n{'━' * 60}")
    print(f"  GENERATING REPORT")
    print(f"  Elapsed: {elapsed:.1f}s")
    print(f"{'━' * 60}")

    report_data, _, _ = generate_report(
        domain=args.domain,
        output_dir=output_dir,
        context=context,
        results=all_results,
        scope_stats=scope.get_stats(),
        elapsed=elapsed,
    )

    _maybe_run_ollama_analysis(args, config, output_dir, report_data)

    # Generate HackerOne reports for vulnerabilities
    vulns = context.get("vuln_findings", [])
    if vulns:
        from modules.h1_reporter import generate_h1_reports
        print(f"\n{'━' * 60}")
        print(f"  GENERATING HACKERONE REPORTS")
        print(f"  Vulnerabilities: {len(vulns)}")
        print(f"{'━' * 60}")

        h1_reports = generate_h1_reports(args.domain, output_dir, vulns)
        print(f"  [+] Generated {len(h1_reports)} HackerOne report(s)")
        for rp in h1_reports:
            print(f"      → {rp}")

    _update_findings_log(args.domain, output_dir, context, all_results)
    print(f"\n  [+] Complete. Results: {output_dir}")
    print(f"  [+] Report:  {output_dir / 'report.md'}")
    if vulns:
        print(f"  [+] H1 Reports: {output_dir / 'h1_reports/'}")


def _maybe_run_ollama_analysis(args, config: dict, output_dir: Path, report_data: dict):
    ollama_cfg = config.get("ollama", {})
    enabled = args.ollama_analyze or ollama_cfg.get("enabled", False)
    if not enabled:
        return

    model = args.ollama_model or ollama_cfg.get("model", "llama3:8b")
    endpoint = ollama_cfg.get("endpoint", "http://127.0.0.1:11434/api/generate")
    timeout = int(ollama_cfg.get("timeout", 120))
    prompt = ollama_cfg.get("prompt", "")

    print(f"\n{'━' * 60}")
    print("  GENERATING OLLAMA AI ASSESSMENT")
    print(f"  Model:   {model}")
    print(f"  API:     {endpoint}")
    print(f"{'━' * 60}")

    try:
        analyzer = OllamaAnalyzer(
            model=model,
            endpoint=endpoint,
            timeout=timeout,
            prompt=prompt,
        )
        md_path, raw_path = analyzer.analyze(report_data, output_dir)
        print("  [+] Ollama assessment saved:")
        print(f"      Markdown: {md_path}")
        print(f"      JSON:     {raw_path}")
    except Exception as exc:
        print(f"  [!] Ollama analysis failed: {exc}")


def _update_findings_log(domain, output_dir, context, results):
    """Append key findings to ./recon/findings.md"""
    findings_dir = Path("recon")
    findings_dir.mkdir(exist_ok=True)
    f_path = findings_dir / "findings.md"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_findings = sum(r.get("findings_count", 0) for r in results)
    vulns = context.get("vuln_findings", [])

    lines = [
        f"\n## {domain} — {ts}\n",
        f"- **Output:** `{output_dir}`\n",
        f"- **Subdomains:** {len(context.get('subdomains', []))}\n",
        f"- **Alive Hosts:** {len(context.get('alive_hosts', []))}\n",
        f"- **Total Findings:** {total_findings}\n",
        f"- **Modules Run:** {len(results)}\n",
    ]

    if vulns:
        lines.append("\n### Critical Vulnerabilities\n")
        for v in vulns[:15]:
            sev = v.get("severity", "?").upper()
            name = v.get("name", "Unknown")
            matched = v.get("matched_at", "")
            lines.append(f"- **[{sev}]** {name} — `{matched}`\n")

    with open(f_path, "a") as f:
        f.writelines(lines)


if __name__ == "__main__":
    main()
