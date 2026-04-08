<div align="center">

# BountyRecon v2.0

**Professional Automated Reconnaissance Framework for Bug Bounty Programs**

42 Modules · 88 Tools · 3 Categories · Full Scope Enforcement

---

</div>

## Overview

BountyRecon is a modular, automated reconnaissance and vulnerability discovery framework built for HackerOne (and other) bug bounty programs. It orchestrates 88 industry-standard open-source tools across **42 modules** organized into three categories — **Recon**, **Exploitation**, and **Miscellaneous** — providing end-to-end attack surface mapping with strict scope compliance.

Inspired by [awesome-bugbounty-tools](https://github.com/vavkamil/awesome-bugbounty-tools).

### Key Features

- **42 modular pipeline stages** covering recon through exploitation
- **88 integrated tools** (Go, Python, and system tools)
- **Strict scope enforcement** — in-scope/out-of-scope filtering at every stage (domains, IPs, CIDRs, regex)
- **Rate limiting** on every tool to prevent accidental DoS
- **Structured output** — organized directories + JSON + Markdown reports
- **Selective execution** — run all, by category, or pick individual modules
- **Shared pipeline context** — modules pass data downstream automatically
- **Auto-skip** — gracefully skips modules when required tools are missing

---

## Architecture

```
bountyrecon.py                  # Core orchestrator — CLI entry point
config.yaml                     # Tunable settings for all 42 modules
setup.sh                        # One-click dependency installer (88 tools)
requirements.txt                # Python dependencies

scope/
  inscope.txt                   # In-scope domains (wildcards supported)
  outscope.txt                  # Out-of-scope rules (domains, IPs, CIDRs, regex)

modules/
  base.py                       # BaseModule class — shared interface for all modules
  scope.py                      # Scope enforcement engine
  reporter.py                   # JSON + Markdown report generator

  recon/                        # 11 Recon modules
    subdomain_enum.py           #   subfinder, amass, assetfinder, findomain, shuffledns, puredns, dnsx
    technologies.py             #   httpx, whatweb, wafw00f, webanalyze
    port_scan.py                #   naabu, masscan, nmap, rustscan
    screenshots.py              #   gowitness, eyewitness, aquatone
    content_discovery.py        #   ffuf, gobuster, feroxbuster, dirsearch, katana, gospider, hakrawler
    content_filtering.py        #   uro, anew
    links.py                    #   gau, waybackurls, waymore, hakrawler, urlfinder
    parameters.py               #   arjun, paramspider, x8
    fuzzing.py                  #   ffuf, wfuzz, qsfuzz
    monitoring.py               #   Change detection (built-in)
    waf_evasion.py              #   wafw00f, nomore403, forbidden-buster

  exploit/                      # 20 Exploitation modules
    cors.py                     #   corsy, CORStest
    crlf.py                     #   crlfuzz, CRLFsuite
    csrf.py                     #   bolt
    sqli.py                     #   sqlmap, ghauri, nosqli
    xss.py                      #   dalfox, kxss
    xxe.py                      #   nuclei
    ssrf.py                     #   SSRFmap, gf, qsreplace
    open_redirect.py            #   Oralyzer, OpenRedireX
    smuggling.py                #   smuggler, h2csmuggler
    command_injection.py        #   commix
    lfi.py                      #   dotdotpwn, gf
    directory_traversal.py      #   nuclei, gf, dotdotpwn
    graphql.py                  #   graphw00f, clairvoyance
    header_injection.py         #   headi
    ssti.py                     #   SSTImap, tplmap
    cache_poisoning.py          #   toxicache
    idor.py                     #   gf
    race_condition.py           #   nuclei
    deserialization.py          #   nuclei
    postmessage.py              #   nuclei

  misc/                         # 11 Miscellaneous modules
    passwords.py                #   nuclei, hydra
    secrets.py                  #   gitleaks, trufflehog, noseyparker, SecretFinder
    git_exposure.py             #   git-dumper, gitjacker
    buckets.py                  #   S3Scanner, CloudBrute
    cms.py                      #   wpscan, CMSmap, joomscan
    jwt.py                      #   jwt_tool, jwt-hack
    subdomain_takeover.py       #   subzy, subjack, dnsReaper
    vuln_scanners.py            #   nuclei, nikto
    forbidden_bypass.py         #   nomore403
    permutation.py              #   alterx, gotator, dnsgen, puredns, dnsx
    origin_ip.py                #   hakoriginfinder

results/                        # Auto-created: results/<domain>/<timestamp>/
recon/
  findings.md                   # Persistent findings log across runs
```

---

## Module Reference

### Recon (11 modules)

| Module | Description | Tools |
|--------|-------------|-------|
| `subdomain_enum` | Passive & active subdomain enumeration | subfinder, amass, assetfinder, findomain, shuffledns, puredns, github-subdomains, dnsx |
| `technologies` | HTTP probing, tech fingerprinting, WAF detection | httpx, whatweb, wafw00f, webanalyze |
| `port_scan` | Fast port scanning on alive hosts | naabu, masscan, nmap, rustscan |
| `screenshots` | Visual screenshot capture of alive web hosts | gowitness, eyewitness, aquatone |
| `content_discovery` | Directory/file fuzzing and web crawling | ffuf, gobuster, feroxbuster, dirsearch, katana, gospider, hakrawler, crawley |
| `content_filtering` | URL deduplication & content noise filtering | uro, anew |
| `links` | URL & endpoint extraction from archives, JS, crawling | gau, waybackurls, waymore, hakrawler, urlfinder |
| `parameters` | Hidden HTTP parameter discovery | arjun, paramspider, x8 |
| `fuzzing` | Targeted query string and input fuzzing | ffuf, wfuzz, qsfuzz |
| `monitoring` | Change detection vs. previous scan results | Built-in (no external tools) |
| `waf_evasion` | WAF detection and 403/401 bypass testing | wafw00f, nomore403, forbidden-buster |

### Exploitation (20 modules)

| Module | Description | Tools |
|--------|-------------|-------|
| `cors` | CORS misconfiguration scanning | corsy, CORStest |
| `crlf` | CRLF injection scanning | crlfuzz, CRLFsuite |
| `csrf` | CSRF token validation & bypass detection | bolt |
| `sqli` | SQL & NoSQL injection scanning | sqlmap, ghauri, nosqli |
| `xss` | Cross-site scripting (XSS) scanning | dalfox, kxss |
| `xxe` | XML External Entity injection detection | nuclei |
| `ssrf` | Server-Side Request Forgery scanning | SSRFmap, gf, qsreplace |
| `open_redirect` | Open redirect vulnerability scanning | Oralyzer, OpenRedireX |
| `smuggling` | HTTP request smuggling detection | smuggler, h2csmuggler |
| `command_injection` | OS command injection scanning | commix |
| `lfi` | Local file inclusion & directory traversal scanning | dotdotpwn, gf |
| `directory_traversal` | Path/directory traversal vulnerability detection | nuclei, gf, dotdotpwn |
| `graphql` | GraphQL endpoint discovery and testing | graphw00f, clairvoyance |
| `header_injection` | HTTP header injection scanning | headi |
| `ssti` | Server-Side Template Injection scanning | SSTImap, tplmap |
| `cache_poisoning` | Web cache poisoning detection | toxicache |
| `idor` | Insecure Direct Object Reference detection | gf |
| `race_condition` | Race condition / TOCTOU detection | nuclei |
| `deserialization` | Insecure deserialization vulnerability detection | nuclei |
| `postmessage` | DOM postMessage vulnerability detection | nuclei |

### Miscellaneous (11 modules)

| Module | Description | Tools |
|--------|-------------|-------|
| `passwords` | Default credentials & weak password detection | nuclei, hydra |
| `secrets` | Secret & credential scanning in JS files and responses | gitleaks, trufflehog, noseyparker, SecretFinder |
| `git_exposure` | Exposed .git repository scanning | git-dumper, gitjacker |
| `buckets` | Cloud storage bucket misconfiguration scanning | S3Scanner, CloudBrute |
| `cms` | CMS-specific vulnerability scanning | wpscan, CMSmap, joomscan |
| `jwt` | JSON Web Token testing | jwt_tool, jwt-hack |
| `subdomain_takeover` | Subdomain takeover vulnerability scanning | subzy, subjack, dnsReaper |
| `vuln_scanners` | Template-based and general vulnerability scanning | nuclei, nikto |
| `forbidden_bypass` | 401/403 authorization bypass testing | nomore403 |
| `permutation` | Subdomain permutation and mutation generation | alterx, gotator, dnsgen, puredns, dnsx |
| `origin_ip` | Discover origin IPs behind CDN/WAF | hakoriginfinder |

---

## Quick Start

### 1. Install Dependencies

```bash
chmod +x setup.sh
sudo bash setup.sh
```

Installs Go 1.22+, all 88 tools (Go-based, Python-based, system packages), Python dependencies, and updates Nuclei templates.

### 2. Configure Scope

Edit scope files to match your HackerOne program rules:

**scope/inscope.txt** — one domain per line, wildcards supported:
```
*.target.com
target.com
api.target.com
```

**scope/outscope.txt** — domains, IPs, CIDRs, or regex patterns:
```
# Third-party services
*.zendesk.com
*.statuspage.io

# Staging
staging.target.com
*.staging.target.com

# Internal ranges
10.0.0.0/8
192.168.0.0/16

# Regex pattern
regex:.*\.internal\..*
```

### 3. Run

```bash
# Full pipeline (all 42 modules)
python3 bountyrecon.py -d target.com --full \
  --inscope scope/inscope.txt \
  --outscope scope/outscope.txt

# Recon only (subdomain enum → tech → ports → screenshots → content → links → params → fuzzing)
python3 bountyrecon.py -d target.com --recon

# Exploitation only (CORS, CRLF, SQLi, XSS, SSRF, etc.)
python3 bountyrecon.py -d target.com --exploit

# Miscellaneous only (secrets, git, buckets, CMS, JWT, takeover, etc.)
python3 bountyrecon.py -d target.com --misc

# Cherry-pick specific modules
python3 bountyrecon.py -d target.com --modules subdomain_enum,technologies,sqli,xss,secrets
```

---

## CLI Reference

```
usage: bountyrecon.py [-h] [-d DOMAIN] [--inscope INSCOPE] [--outscope OUTSCOPE]
                      [--config CONFIG] [--output OUTPUT] [--delay DELAY]
                      [--full | --recon | --exploit | --misc | --modules MODULES]
                      [--list-modules] [--check-tools]

Target:
  -d, --domain          Target root domain (required for scanning)

Scope:
  --inscope             Path to in-scope domains file
  --outscope            Path to out-of-scope rules file

Module Selection (mutually exclusive):
  --full                Run ALL 42 modules (recon + exploit + misc)
  --recon               Run 11 recon modules only (default)
  --exploit             Run 20 exploitation modules only
  --misc                Run 11 miscellaneous modules only
  --modules             Comma-separated list of specific module names

Configuration:
  --config              Path to YAML config file (default: config.yaml)
  --output              Base output directory (default: results/)
  --delay               Delay in seconds between modules (default: 0)

Utility:
  --list-modules        List all modules with tool availability and exit
  --check-tools         Check all 88 tools and print install status
```

---

## Output Structure

All results are organized under `results/<domain>/<timestamp>/`:

```
results/target.com/2026-04-07_143022/
├── recon_subdomain_enum/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── crtsh.json
│   ├── assetfinder.txt
│   └── all_subdomains.txt
├── recon_technologies/
│   ├── httpx_results.json
│   ├── alive_urls.txt
│   └── tech_fingerprints.json
├── recon_port_scan/
│   ├── naabu_results.json
│   └── port_summary.json
├── recon_screenshots/
│   └── screenshots/
├── recon_content_discovery/
│   ├── ffuf_*.json
│   └── discovered_endpoints.txt
├── recon_content_filtering/
│   └── filtered_urls.txt
├── recon_links/
│   ├── gau.txt
│   ├── waybackurls.txt
│   └── all_urls.txt
├── recon_parameters/
│   └── discovered_params.json
├── recon_fuzzing/
│   └── fuzz_results.json
├── recon_monitoring/
│   └── changes_detected.json
├── recon_waf_evasion/
│   └── waf_results.json
├── exploit_cors/
│   └── cors_findings.json
├── exploit_sqli/
│   └── sqli_findings.json
├── exploit_xss/
│   └── xss_findings.json
├── ...                              # (one dir per executed module)
├── misc_secrets/
│   └── secrets_found.json
├── misc_vuln_scanners/
│   └── nuclei_results.json
├── report.json                      # Machine-readable full report
└── report.md                        # Human-readable summary with all findings
```

---

## Pipeline Flow

The framework executes modules in dependency order. Each module reads from and writes to a shared **pipeline context**, so downstream modules automatically receive upstream results:

```
┌─────────────────────────────────────────────────────────────────┐
│                          RECON                                  │
│                                                                 │
│  subdomain_enum ──→ technologies ──→ port_scan ──→ screenshots  │
│        │                 │               │                      │
│        ▼                 ▼               ▼                      │
│  permutation      content_discovery   links ──→ parameters      │
│        │                 │               │          │            │
│        ▼                 ▼               ▼          ▼            │
│  content_filtering   monitoring      fuzzing    waf_evasion     │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                       EXPLOITATION                              │
│                                                                 │
│  cors    crlf     csrf     sqli     xss     xxe     ssrf       │
│  open_redirect   smuggling   command_injection   lfi            │
│  directory_traversal   graphql   header_injection   ssti        │
│  cache_poisoning   idor   race_condition   deserialization      │
│  postmessage                                                    │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                      MISCELLANEOUS                              │
│                                                                 │
│  passwords   secrets   git_exposure   buckets   cms   jwt       │
│  subdomain_takeover   vuln_scanners   forbidden_bypass          │
│  origin_ip                                                      │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                     REPORT GENERATION                           │
│                                                                 │
│  report.json + report.md + recon/findings.md                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Configuration

All module behavior is tunable via `config.yaml`. Each module has its own section:

```yaml
# Example: subdomain_enum configuration
subdomain_enum:
  use_subfinder: true
  use_amass: true
  use_crtsh: true
  use_assetfinder: true
  use_findomain: true
  subfinder_threads: 30
  amass_timeout: 15          # minutes

# Example: rate limiting for SQLi scanning
sqli:
  rate_limit: 10             # requests per second
  level: 1                   # sqlmap level (1-5)
  risk: 1                    # sqlmap risk (1-3)
  threads: 5
  batch: true                # non-interactive mode

# Example: Nuclei vulnerability scanning
vuln_scanners:
  severity: "critical,high,medium"
  rate_limit: 50
  templates:
    - "cves/"
    - "vulnerabilities/"
    - "misconfiguration/"
    - "exposed-panels/"
  exclude_templates:
    - "dos/"
    - "fuzzing/"
```

See the full [config.yaml](config.yaml) for all 42 module configurations.

---

## Scope Enforcement

The scope engine (`modules/scope.py`) is enforced at **every module boundary** — no tool ever receives an out-of-scope target.

### Supported Rule Types

| Type | Example | Behavior |
|------|---------|----------|
| Exact domain | `staging.target.com` | Blocks exact match |
| Wildcard domain | `*.staging.target.com` | Blocks domain and all subdomains |
| IP address | `192.168.1.100` | Blocks specific IP |
| CIDR range | `10.0.0.0/8` | Blocks entire subnet |
| Regex pattern | `regex:.*\.internal\..*` | Blocks any matching hostname |

**Deny always wins** — if an asset matches both in-scope and out-of-scope, it is excluded.

---

## Safety Features

| Feature | Implementation |
|---------|----------------|
| **Scope enforcement** | Every module filters through `ScopeEnforcer` before processing |
| **Rate limiting** | Configurable per-tool rate limits in `config.yaml` |
| **Non-destructive scanning** | Nuclei excludes DoS/fuzzing templates; sqlmap uses safe defaults |
| **No OOB callbacks** | Nuclei runs with `--no-interactsh` |
| **Timeout protection** | All subprocess calls have configurable timeouts via `BaseModule.exec()` |
| **Graceful degradation** | Missing tools cause module skip, not pipeline failure |
| **HackerOne compliance** | Out-of-scope parsing designed for program policy files |

---

## Adding Custom Modules

Create a new file under the appropriate category directory, inheriting from `BaseModule`:

```python
# modules/exploit/my_scanner.py

from modules.base import BaseModule

class MyScanner(BaseModule):
    name = "my_scanner"
    description = "Custom vulnerability scanner"
    category = "exploit"
    tools_required = ["my-tool"]
    tools_optional = ["helper-tool"]

    def run(self):
        # Access shared pipeline context
        alive_urls = self.ctx.get("alive_urls", [])

        # Filter through scope
        targets = self.scope.filter_assets(alive_urls)

        # Execute tools
        result = self.exec(["my-tool", "-l", str(self.save_list(targets))])

        # Store findings
        self.findings = [{"url": t, "vuln": "example"} for t in targets]

        # Update shared context for downstream modules
        self.ctx.setdefault("vuln_findings", []).extend(self.findings)

        return self.get_results()
```

Then register it in `bountyrecon.py`:

```python
from modules.exploit.my_scanner import MyScanner

EXPLOIT_MODULES = [
    ...,
    MyScanner,   # Add to execution order
]
```

---

## Tool Inventory (88 tools)

<details>
<summary>Click to expand full tool list</summary>

**Recon Tools:**
amass, assetfinder, crawley, dirsearch, dnsx, feroxbuster, ffuf, findomain,
gau, github-subdomains, gobuster, gospider, gowitness, hakrawler, httpx,
katana, masscan, naabu, nmap, puredns, rustscan, shuffledns, subfinder,
urlfinder, uro, anew, wafw00f, waybackurls, waymore, webanalyze

**Exploitation Tools:**
bolt, clairvoyance, commix, corsy, CORStest, crlfuzz, CRLFsuite, dalfox,
dotdotpwn, gf, ghauri, graphw00f, h2csmuggler, headi, kxss, nosqli, nuclei,
OpenRedireX, Oralyzer, qsfuzz, qsreplace, smuggler, sqlmap, SSRFmap, SSTImap,
tplmap, toxicache, wfuzz

**Miscellaneous Tools:**
alterx, CloudBrute, CMSmap, dnsgen, dnsReaper, forbidden-buster, git-dumper,
gitjacker, gitleaks, gotator, hydra, joomscan, jwt_tool, jwt-hack, nikto,
nomore403, noseyparker, S3Scanner, SecretFinder, subjack, subzy, trufflehog,
wpscan, hakoriginfinder, paramspider, x8, aquatone, eyewitness

</details>

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.8+ |
| Go | 1.21+ (for tool installation) |
| OS | Linux (Kali / Debian recommended) |
| Privileges | Root/sudo for SYN scanning (naabu, masscan) |
| Disk | ~2GB for tools + templates |
| RAM | 4GB minimum, 8GB+ recommended for large scans |

---

## Examples

```bash
# Quick recon on a target
python3 bountyrecon.py -d example.com --recon \
  --inscope scope/inscope.txt --outscope scope/outscope.txt

# Full audit with 2-second delay between modules
python3 bountyrecon.py -d example.com --full --delay 2

# Just check for low-hanging fruit (XSS + SQLi + CORS + secrets)
python3 bountyrecon.py -d example.com \
  --modules subdomain_enum,technologies,xss,sqli,cors,secrets

# List all modules and check which tools you have installed
python3 bountyrecon.py --list-modules
python3 bountyrecon.py --check-tools

# Run only subdomain enumeration with permutations
python3 bountyrecon.py -d example.com --modules subdomain_enum,permutation

# CMS-specific assessment
python3 bountyrecon.py -d example.com \
  --modules subdomain_enum,technologies,cms,passwords,vuln_scanners
```

---

## Legal Disclaimer

This tool is designed for **authorized security testing only**. Always ensure you have explicit written permission before scanning any target. Respect HackerOne program scope, rules of engagement, and safe harbor policies. The authors are not responsible for misuse of this tool.

**Do not use this tool against targets you do not have permission to test.**
