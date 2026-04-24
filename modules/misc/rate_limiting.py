"""
Rate Limiting — Lightweight candidate checks for auth and verification flows.
"""

import ssl
import urllib.request
from typing import Dict, List

from modules.base import BaseModule


class RateLimiting(BaseModule):
    name = "rate_limiting"
    description = "Rate limiting and brute-force protection checks"
    category = "misc"
    tools_required = []
    tools_optional = []

    CANDIDATE_HINTS = (
        "/login", "/signin", "/auth", "/reset", "/forgot", "/otp",
        "/verify", "/mfa", "/token", "/invite", "/password",
    )

    def run(self) -> Dict:
        urls = [u for u in self.ctx.get("gathered_urls", []) if self.in_scope(u)]
        candidates = [u for u in urls if any(h in u.lower() for h in self.CANDIDATE_HINTS)]
        if not candidates:
            self.log("No candidate endpoints for rate limit checks.", level="warn")
            return self.get_results()

        for url in candidates[: self.config_get("max_targets", 25)]:
            finding = self._probe(url)
            if finding:
                self.findings.append(finding)

        low_plus = [f for f in self.findings if f.get("severity") in ("critical", "high", "medium", "low")]
        if low_plus:
            self.ctx.setdefault("vuln_findings", []).extend(low_plus)

        self.write_json(self.phase_dir / "rate_limiting_findings.json", self.findings)
        self.log(f"Rate limiting findings: {len(self.findings)}")
        return self.get_results()

    def _probe(self, url: str):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        statuses = []
        retry_after_seen = False
        rate_headers_seen = False

        for _ in range(3):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "BountyRecon/2.0"})
                with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                    statuses.append(resp.status)
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    if "retry-after" in headers:
                        retry_after_seen = True
                    if any(h in headers for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit")):
                        rate_headers_seen = True
            except Exception:
                return None

        if len(statuses) == 3 and len(set(statuses)) == 1 and not retry_after_seen and not rate_headers_seen:
            return {
                "name": "Weak or Missing Rate Limiting",
                "type": "rate_limiting",
                "matched_at": url,
                "severity": "low",
                "description": "Repeated requests returned the same response with no visible rate-limit headers or Retry-After indicator.",
            }
        return None
