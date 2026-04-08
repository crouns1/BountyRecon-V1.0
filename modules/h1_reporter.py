"""
HackerOne Report Generator — Creates submission-ready vulnerability reports

Generates professional HackerOne reports from findings including:
- CVSS scoring
- Steps to reproduce
- PoC evidence
- Impact statement
- Remediation suggestions
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


# CVSS v3.1 base scores by vulnerability type
CVSS_SCORES = {
    # Critical (9.0-10.0)
    "rce": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "ssti": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "sql_injection": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "command_injection": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "xxe": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "deserialization": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},

    # High (7.0-8.9)
    "ssrf": {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "lfi": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "idor": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "subdomain_takeover": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"},
    "jwt_bypass": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "authentication_bypass": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "directory_traversal": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "git_exposure": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "secrets_exposure": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},

    # Medium (4.0-6.9)
    "xss": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "csrf": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"},
    "cors_misconfig": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"},
    "open_redirect": {"score": 4.7, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"},
    "crlf": {"score": 5.4, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "header_injection": {"score": 5.4, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "clickjacking": {"score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "cache_poisoning": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"},

    # Low (0.1-3.9)
    "information_disclosure": {"score": 3.7, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "rate_limiting": {"score": 2.7, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"},
}

# Remediation templates
REMEDIATION = {
    "ssti": """
**Remediation:**
1. Never pass user input directly to template engines
2. Use sandboxed template environments (e.g., Jinja2 SandboxedEnvironment)
3. Implement strict input validation and sanitization
4. Use a template engine that auto-escapes output
5. Apply the principle of least privilege to template contexts
""",
    "ssrf": """
**Remediation:**
1. Implement allowlist validation for URLs/hostnames
2. Block requests to internal IP ranges (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x)
3. Disable unnecessary URL schemes (file://, gopher://, dict://)
4. Use a dedicated service for external URL fetching with network isolation
5. Implement response validation to prevent data exfiltration
""",
    "lfi": """
**Remediation:**
1. Avoid passing user input to file system functions
2. Implement strict allowlist validation for file paths
3. Use realpath() to resolve and validate the final path
4. Disable directory traversal sequences (../, ..\\)
5. Run the application with minimal file system permissions
""",
    "sql_injection": r"""
**Remediation:**
1. Use parameterized queries / prepared statements
2. Implement input validation with strict allowlists
3. Apply least privilege to database accounts
4. Use stored procedures where appropriate
5. Enable WAF rules for SQL injection detection
""",
    "xss": """
**Remediation:**
1. Encode output based on context (HTML, JavaScript, URL, CSS)
2. Implement Content-Security-Policy headers
3. Use modern frameworks with automatic output encoding
4. Validate and sanitize all user input
5. Set HttpOnly and Secure flags on session cookies
""",
    "open_redirect": """
**Remediation:**
1. Implement allowlist validation for redirect URLs
2. Use relative URLs instead of absolute URLs
3. Require explicit user confirmation for external redirects
4. Validate URL scheme (only allow http/https)
5. Log and monitor redirect attempts
""",
    "cors_misconfig": """
**Remediation:**
1. Never reflect the Origin header in Access-Control-Allow-Origin
2. Implement strict allowlist for allowed origins
3. Avoid using Access-Control-Allow-Origin: *
4. Set Access-Control-Allow-Credentials only when necessary
5. Validate the Origin header server-side
""",
    "subdomain_takeover": """
**Remediation:**
1. Remove dangling DNS records pointing to unclaimed resources
2. Implement monitoring for unused subdomains
3. Claim or deprovision unused cloud resources
4. Use DNS record monitoring services
5. Maintain an inventory of all subdomains and their purposes
""",
}

# Impact statements
IMPACT_STATEMENTS = {
    "ssti": """
## Impact

Server-Side Template Injection allows an attacker to inject malicious template code that executes on the server. This can lead to:

- **Remote Code Execution (RCE)**: Full control over the server
- **Data Theft**: Access to sensitive files, databases, and credentials
- **Lateral Movement**: Pivot to other internal systems
- **Complete Application Compromise**: Modify application behavior and data

This is a **critical** vulnerability that requires immediate attention.
""",
    "ssrf": """
## Impact

Server-Side Request Forgery allows an attacker to make the server perform requests on their behalf. This can lead to:

- **Internal Service Access**: Access to internal APIs, databases, and services
- **Cloud Metadata Theft**: Steal AWS/GCP/Azure credentials from metadata services
- **Port Scanning**: Map internal network infrastructure
- **Data Exfiltration**: Read sensitive internal data through the server

In cloud environments, this often leads to complete infrastructure compromise via stolen credentials.
""",
    "lfi": """
## Impact

Local File Inclusion allows an attacker to read arbitrary files from the server. This can lead to:

- **Source Code Disclosure**: Access to application source code and logic
- **Credential Theft**: Read configuration files with database passwords, API keys
- **System Information**: Access /etc/passwd, /proc/self/environ for reconnaissance
- **Log Poisoning to RCE**: In some cases, can be escalated to remote code execution

This vulnerability exposes sensitive server-side data and can lead to further compromise.
""",
    "sql_injection": """
## Impact

SQL Injection allows an attacker to manipulate database queries. This can lead to:

- **Data Breach**: Extract entire database contents including user data
- **Authentication Bypass**: Log in as any user including administrators
- **Data Manipulation**: Modify or delete database records
- **Remote Code Execution**: In some configurations, execute system commands

This is a critical vulnerability with potential for massive data breach.
""",
    "xss": """
## Impact

Cross-Site Scripting allows an attacker to execute JavaScript in victims' browsers. This can lead to:

- **Session Hijacking**: Steal session cookies and impersonate users
- **Credential Theft**: Capture login credentials via fake forms
- **Keylogging**: Record user keystrokes
- **Malware Distribution**: Redirect users to malicious sites

The impact depends on the privileges of affected users (higher impact for admin accounts).
""",
    "open_redirect": """
## Impact

Open Redirect allows an attacker to redirect users to malicious websites. This can enable:

- **Phishing Attacks**: Redirect to convincing fake login pages
- **OAuth Token Theft**: Intercept authorization codes in OAuth flows
- **Malware Distribution**: Redirect to drive-by download sites
- **Reputation Damage**: Association with malicious content

This vulnerability enables social engineering attacks that leverage user trust in the domain.
""",
}


class HackerOneReporter:
    """Generate HackerOne-ready vulnerability reports."""

    def __init__(self, output_dir: Path, domain: str):
        self.output_dir = output_dir
        self.domain = domain
        self.reports_dir = output_dir / "h1_reports"
        self.reports_dir.mkdir(exist_ok=True)

    def generate_reports(self, findings: List[Dict]) -> List[Path]:
        """Generate individual HackerOne reports for each finding."""
        report_paths = []

        # Group findings by type for consolidated reports
        by_type: Dict[str, List[Dict]] = {}
        for f in findings:
            vuln_type = self._normalize_type(f.get("type", "unknown"))
            by_type.setdefault(vuln_type, []).append(f)

        # Generate report for each vulnerability type
        for vuln_type, type_findings in by_type.items():
            if vuln_type == "unknown":
                continue

            report_path = self._generate_report(vuln_type, type_findings)
            if report_path:
                report_paths.append(report_path)

        # Generate summary report
        summary_path = self._generate_summary(findings)
        report_paths.append(summary_path)

        return report_paths

    def _generate_report(self, vuln_type: str, findings: List[Dict]) -> Optional[Path]:
        """Generate a single HackerOne report for a vulnerability type."""
        if not findings:
            return None

        cvss = CVSS_SCORES.get(vuln_type, {"score": 5.0, "vector": "N/A"})
        severity = self._score_to_severity(cvss["score"])

        # Build report
        report_lines = [
            f"# {self._format_title(vuln_type)} - {self.domain}",
            "",
            f"**Severity:** {severity}",
            f"**CVSS Score:** {cvss['score']} ({cvss['vector']})",
            f"**Affected Asset:** {self.domain}",
            f"**Date Found:** {datetime.now().strftime('%Y-%m-%d')}",
            "",
            "---",
            "",
        ]

        # Add summary
        report_lines.append("## Summary")
        report_lines.append("")
        report_lines.append(self._get_summary(vuln_type, findings))
        report_lines.append("")

        # Add impact statement
        if vuln_type in IMPACT_STATEMENTS:
            report_lines.append(IMPACT_STATEMENTS[vuln_type])
            report_lines.append("")

        # Add steps to reproduce
        report_lines.append("## Steps to Reproduce")
        report_lines.append("")
        for i, f in enumerate(findings[:5], 1):
            report_lines.extend(self._format_steps(i, f))
        if len(findings) > 5:
            report_lines.append(f"*...and {len(findings) - 5} more affected endpoints*")
        report_lines.append("")

        # Add PoC
        report_lines.append("## Proof of Concept")
        report_lines.append("")
        report_lines.extend(self._format_poc(findings[0]))
        report_lines.append("")

        # Add remediation
        if vuln_type in REMEDIATION:
            report_lines.append(REMEDIATION[vuln_type])
            report_lines.append("")

        # Add references
        report_lines.append("## References")
        report_lines.append("")
        report_lines.extend(self._get_references(vuln_type))
        report_lines.append("")

        # Write report
        filename = f"h1_report_{vuln_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = self.reports_dir / filename
        report_path.write_text("\n".join(report_lines))

        return report_path

    def _generate_summary(self, findings: List[Dict]) -> Path:
        """Generate a summary report of all findings."""
        lines = [
            f"# Vulnerability Assessment Summary - {self.domain}",
            "",
            f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Total Findings:** {len(findings)}",
            "",
            "---",
            "",
            "## Findings by Severity",
            "",
        ]

        # Count by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "medium").lower()
            if sev == "critical":
                severity_counts["Critical"] += 1
            elif sev == "high":
                severity_counts["High"] += 1
            elif sev == "medium":
                severity_counts["Medium"] += 1
            elif sev == "low":
                severity_counts["Low"] += 1
            else:
                severity_counts["Info"] += 1

        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev, count in severity_counts.items():
            if count > 0:
                lines.append(f"| {sev} | {count} |")
        lines.append("")

        # List by type
        lines.append("## Findings by Type")
        lines.append("")
        lines.append("| Type | Count | Severity | CVSS |")
        lines.append("|------|-------|----------|------|")

        by_type: Dict[str, List[Dict]] = {}
        for f in findings:
            t = self._normalize_type(f.get("type", "unknown"))
            by_type.setdefault(t, []).append(f)

        for vuln_type, type_findings in sorted(by_type.items(), key=lambda x: -len(x[1])):
            cvss = CVSS_SCORES.get(vuln_type, {"score": 5.0})
            severity = self._score_to_severity(cvss["score"])
            lines.append(f"| {self._format_title(vuln_type)} | {len(type_findings)} | {severity} | {cvss['score']} |")
        lines.append("")

        # Detailed findings
        lines.append("## Detailed Findings")
        lines.append("")

        for i, f in enumerate(findings[:50], 1):
            lines.append(f"### {i}. {f.get('name', f.get('type', 'Unknown'))}")
            lines.append("")
            lines.append(f"- **URL:** `{f.get('matched_at', f.get('url', 'N/A'))}`")
            if f.get("payload"):
                lines.append(f"- **Payload:** `{f.get('payload')}`")
            if f.get("evidence"):
                lines.append(f"- **Evidence:** `{str(f.get('evidence'))[:100]}...`")
            if f.get("poc"):
                lines.append(f"- **PoC:** `{f.get('poc')}`")
            lines.append("")

        if len(findings) > 50:
            lines.append(f"*...and {len(findings) - 50} more findings (see individual reports)*")

        # Write summary
        filename = f"h1_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        summary_path = self.reports_dir / filename
        summary_path.write_text("\n".join(lines))

        return summary_path

    def _normalize_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type name."""
        mappings = {
            "ssti_confirmed": "ssti",
            "ssrf_confirmed": "ssrf",
            "lfi_confirmed": "lfi",
            "xss_confirmed": "xss",
            "open_redirect_confirmed": "open_redirect",
            "sql_injection_confirmed": "sql_injection",
            "blind_ssrf_candidate": "ssrf",
            "reflected_param": "xss",
            "cors_misconfig": "cors_misconfig",
            "subdomain_takeover": "subdomain_takeover",
        }
        return mappings.get(vuln_type, vuln_type)

    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity string."""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "Info"

    def _format_title(self, vuln_type: str) -> str:
        """Format vulnerability type as title."""
        titles = {
            "ssti": "Server-Side Template Injection",
            "ssrf": "Server-Side Request Forgery",
            "lfi": "Local File Inclusion",
            "sql_injection": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "xxe": "XML External Entity Injection",
            "open_redirect": "Open Redirect",
            "cors_misconfig": "CORS Misconfiguration",
            "csrf": "Cross-Site Request Forgery",
            "crlf": "CRLF Injection",
            "subdomain_takeover": "Subdomain Takeover",
            "command_injection": "OS Command Injection",
            "idor": "Insecure Direct Object Reference",
            "directory_traversal": "Directory Traversal",
            "header_injection": "HTTP Header Injection",
            "cache_poisoning": "Web Cache Poisoning",
            "jwt_bypass": "JWT Authentication Bypass",
            "git_exposure": "Git Repository Exposure",
            "secrets_exposure": "Secrets/Credentials Exposure",
        }
        return titles.get(vuln_type, vuln_type.replace("_", " ").title())

    def _get_summary(self, vuln_type: str, findings: List[Dict]) -> str:
        """Generate summary text for vulnerability type."""
        count = len(findings)
        title = self._format_title(vuln_type)

        first = findings[0]
        url = first.get("matched_at", first.get("url", self.domain))

        summaries = {
            "ssti": f"I discovered a {title} vulnerability affecting {count} endpoint(s) on {self.domain}. This vulnerability allows an attacker to inject and execute arbitrary template code on the server, potentially leading to Remote Code Execution (RCE).",
            "ssrf": f"I discovered a {title} vulnerability affecting {count} endpoint(s) on {self.domain}. This allows an attacker to make the server perform unauthorized requests to internal services, potentially accessing cloud metadata, internal APIs, or sensitive resources.",
            "lfi": f"I discovered a {title} vulnerability affecting {count} endpoint(s) on {self.domain}. This allows an attacker to read arbitrary files from the server, including configuration files, source code, and potentially sensitive credentials.",
            "xss": f"I discovered a {title} vulnerability affecting {count} endpoint(s) on {self.domain}. This allows an attacker to execute arbitrary JavaScript in the context of the victim's browser, enabling session hijacking, credential theft, and other attacks.",
            "open_redirect": f"I discovered an {title} vulnerability affecting {count} endpoint(s) on {self.domain}. This can be abused for phishing attacks by redirecting users to malicious sites while appearing to originate from a trusted domain.",
        }

        return summaries.get(vuln_type, f"I discovered a {title} vulnerability affecting {count} endpoint(s) on {self.domain}.")

    def _format_steps(self, num: int, finding: Dict) -> List[str]:
        """Format steps to reproduce for a finding."""
        url = finding.get("poc_url", finding.get("matched_at", finding.get("url", "")))
        payload = finding.get("payload", "")
        param = finding.get("param", "")

        lines = [f"**Finding {num}:**", ""]

        if url:
            lines.append(f"1. Navigate to the following URL:")
            lines.append(f"   ```")
            lines.append(f"   {url}")
            lines.append(f"   ```")

        if param and payload:
            lines.append(f"2. The parameter `{param}` is vulnerable to injection")
            lines.append(f"3. Payload used: `{payload}`")

        if finding.get("evidence"):
            lines.append(f"4. Observe the response containing: `{str(finding['evidence'])[:100]}...`")

        lines.append("")
        return lines

    def _format_poc(self, finding: Dict) -> List[str]:
        """Format proof of concept section."""
        lines = []

        poc_url = finding.get("poc_url", finding.get("url", ""))
        if poc_url:
            lines.append("### HTTP Request")
            lines.append("")
            lines.append("```http")
            lines.append(f"GET {poc_url}")
            lines.append("Host: " + self.domain)
            lines.append("User-Agent: Mozilla/5.0")
            lines.append("```")
            lines.append("")

        if finding.get("evidence"):
            lines.append("### Response Evidence")
            lines.append("")
            lines.append("```")
            lines.append(str(finding["evidence"])[:500])
            lines.append("```")

        return lines

    def _get_references(self, vuln_type: str) -> List[str]:
        """Get reference links for vulnerability type."""
        refs = {
            "ssti": [
                "- [PortSwigger - Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)",
                "- [OWASP - Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)",
                "- [HackTricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)",
            ],
            "ssrf": [
                "- [PortSwigger - Server-side request forgery](https://portswigger.net/web-security/ssrf)",
                "- [OWASP - Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)",
                "- [HackTricks - SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)",
            ],
            "lfi": [
                "- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)",
                "- [PortSwigger - Directory traversal](https://portswigger.net/web-security/file-path-traversal)",
                "- [HackTricks - File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)",
            ],
            "xss": [
                "- [PortSwigger - Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)",
                "- [OWASP - XSS](https://owasp.org/www-community/attacks/xss/)",
                "- [HackTricks - XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)",
            ],
            "open_redirect": [
                "- [PortSwigger - Open redirection](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)",
                "- [OWASP - Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)",
                "- [HackTricks - Open Redirect](https://book.hacktricks.xyz/pentesting-web/open-redirect)",
            ],
        }
        return refs.get(vuln_type, ["- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)"])


def generate_h1_reports(domain: str, output_dir: Path, findings: List[Dict]) -> List[Path]:
    """
    Main entry point to generate HackerOne reports.

    Args:
        domain: Target domain
        output_dir: Base output directory
        findings: List of vulnerability findings from modules

    Returns:
        List of generated report file paths
    """
    reporter = HackerOneReporter(output_dir, domain)
    return reporter.generate_reports(findings)
