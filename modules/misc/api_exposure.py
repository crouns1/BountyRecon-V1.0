"""
API Exposure — Swagger, OpenAPI, GraphQL consoles, and API docs discovery.
"""

import ssl
import urllib.request
from urllib.parse import urljoin
from typing import Dict, List

from modules.base import BaseModule


class APIExposure(BaseModule):
    name = "api_exposure"
    description = "Exposed API docs and console discovery"
    category = "misc"
    tools_required = []
    tools_optional = []

    DOC_PATHS = [
        "/swagger",
        "/swagger-ui",
        "/swagger-ui.html",
        "/api-docs",
        "/openapi.json",
        "/openapi.yaml",
        "/v3/api-docs",
        "/.well-known/openapi.json",
        "/graphiql",
        "/playground",
    ]

    def run(self) -> Dict:
        bases = [u.rstrip("/") + "/" for u in self.ctx.get("alive_urls", []) if self.in_scope(u)]
        if not bases:
            self.log("No alive URLs for API exposure checks.", level="warn")
            return self.get_results()

        for base in bases[: self.config_get("max_targets", 40)]:
            for path in self.DOC_PATHS:
                finding = self._probe(urljoin(base, path.lstrip("/")))
                if finding:
                    self.findings.append(finding)

        low_plus = [f for f in self.findings if f.get("severity") in ("critical", "high", "medium", "low")]
        if low_plus:
            self.ctx.setdefault("vuln_findings", []).extend(low_plus)

        self.write_json(self.phase_dir / "api_exposure_findings.json", self.findings)
        self.log(f"API exposure findings: {len(self.findings)}")
        return self.get_results()

    def _probe(self, url: str):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "BountyRecon/2.0"})
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                if resp.status not in (200, 401, 403):
                    return None
                body = resp.read(2000).decode("utf-8", errors="ignore").lower()
        except Exception:
            return None

        if any(marker in body for marker in ("swagger", "openapi", "graphiql", "graphql-playground", "__schema")):
            return {
                "name": "Exposed API Documentation or Console",
                "type": "api_exposure",
                "matched_at": url,
                "severity": "low",
                "description": "Publicly reachable API documentation, interactive console, or schema endpoint detected.",
            }
        return None
