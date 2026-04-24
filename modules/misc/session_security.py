"""
Session Security — Cookie flag checks and session handling weaknesses.
"""

import re
import ssl
import urllib.request
from typing import Dict, List

from modules.base import BaseModule


class SessionSecurity(BaseModule):
    name = "session_security"
    description = "Session, cookie, and auth surface checks"
    category = "misc"
    tools_required = []
    tools_optional = []

    AUTH_HINTS = (
        "/login", "/signin", "/auth", "/account", "/session", "/admin",
        "/reset", "/forgot", "/password", "/verify", "/otp", "/mfa",
    )
    SESSION_COOKIE_HINTS = ("sess", "session", "sid", "token", "auth", "jwt")
    SESSION_IN_URL = re.compile(r"(jsessionid|phpsessid|sessionid|aspsessionid|token)=", re.I)

    def run(self) -> Dict:
        urls = set(self.ctx.get("alive_urls", []))
        urls.update(self.ctx.get("gathered_urls", []))
        targets = [u for u in sorted(urls) if self.in_scope(u)]
        if not targets:
            self.log("No URLs for session security checks.", level="warn")
            return self.get_results()

        for url in targets[: self.config_get("max_targets", 60)]:
            if self.SESSION_IN_URL.search(url):
                self.findings.append({
                    "name": "Session Identifier in URL",
                    "type": "session_fixation_candidate",
                    "matched_at": url,
                    "severity": "medium",
                    "description": "Potential session token or identifier found in URL.",
                })

            if any(h in url.lower() for h in self.AUTH_HINTS):
                self.findings.append({
                    "type": "auth_surface",
                    "matched_at": url,
                    "severity": "info",
                    "description": "Authentication-related endpoint discovered.",
                })

            cookie_findings = self._check_cookies(url)
            self.findings.extend(cookie_findings)

        medium = [f for f in self.findings if f.get("severity") in ("critical", "high", "medium")]
        if medium:
            self.ctx.setdefault("vuln_findings", []).extend(medium)

        self.write_json(self.phase_dir / "session_security_findings.json", self.findings)
        self.log(f"Session security findings: {len(self.findings)}")
        return self.get_results()

    def _check_cookies(self, url: str) -> List[Dict]:
        findings = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "BountyRecon/2.0"})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                cookies = resp.headers.get_all("Set-Cookie", [])
        except Exception:
            return findings

        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=", 1)[0].strip()
            is_sensitive = any(h in cookie_name.lower() for h in self.SESSION_COOKIE_HINTS) or any(
                h in url.lower() for h in self.AUTH_HINTS
            )
            severity = "medium" if is_sensitive else "low"

            if "httponly" not in cookie_lower:
                findings.append({
                    "name": "Cookie Missing HttpOnly",
                    "type": "insecure_session_cookie",
                    "matched_at": url,
                    "severity": severity,
                    "description": f"Cookie `{cookie_name}` is missing the HttpOnly flag.",
                })
            if url.lower().startswith("https://") and "secure" not in cookie_lower:
                findings.append({
                    "name": "Cookie Missing Secure",
                    "type": "insecure_session_cookie",
                    "matched_at": url,
                    "severity": severity,
                    "description": f"Cookie `{cookie_name}` is missing the Secure flag.",
                })
            if "samesite" not in cookie_lower:
                findings.append({
                    "name": "Cookie Missing SameSite",
                    "type": "insecure_session_cookie",
                    "matched_at": url,
                    "severity": "low",
                    "description": f"Cookie `{cookie_name}` is missing a SameSite attribute.",
                })
        return findings
