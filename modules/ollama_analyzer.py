"""
ollama_analyzer.py — Optional local AI assessment using Ollama.

Consumes structured report data and produces an analyst-style markdown
assessment plus raw response metadata.
"""

import json
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple


DEFAULT_PROMPT = """You are a Senior Penetration Tester and Security Analyst.

You are reviewing structured results from an automated reconnaissance and exploitation framework.

Important rules:
- Only claim a vulnerability when the evidence supports it.
- Distinguish clearly between confirmed findings and likely/suspected findings.
- Prefer the strongest attack path or path of least resistance.
- Keep the report professional, concise, and technically precise.
- If the data is weak or inconclusive, say that explicitly.

Produce the report using exactly this structure:

1. Executive Summary
Provide a high-level overview of the security posture.
Highlight the most critical path of least resistance discovered.

2. Technical Vulnerability Analysis
For every significant finding, include:
- Vulnerability Name
- Severity
- Evidence
- Impact

3. Strategic Remediation
Provide actionable mitigation steps for both developers and sysadmins.
Suggest long-term architectural improvements where appropriate.
"""


def _compact_report(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce prompt size while preserving the most valuable evidence."""
    compact = {
        "meta": report_data.get("meta", {}),
        "summary": report_data.get("summary", {}),
        "technologies": report_data.get("technologies", {}),
        "top_ports": report_data.get("top_ports", {}),
        "alive_hosts": report_data.get("alive_hosts", [])[:25],
        "vulnerability_findings": report_data.get("vulnerability_findings", [])[:50],
        "recon_results": _trim_module_results(report_data.get("recon_results", [])),
        "exploit_results": _trim_module_results(report_data.get("exploit_results", [])),
        "misc_results": _trim_module_results(report_data.get("misc_results", [])),
    }
    return compact


def _trim_module_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    trimmed = []
    for item in results[:20]:
        trimmed.append({
            "module": item.get("module"),
            "category": item.get("category"),
            "description": item.get("description"),
            "findings_count": item.get("findings_count"),
            "findings": item.get("findings", [])[:15],
        })
    return trimmed


def build_ollama_prompt(report_data: Dict[str, Any], custom_prompt: str = "") -> str:
    prompt = (custom_prompt or DEFAULT_PROMPT).strip()
    compact = _compact_report(report_data)
    return (
        f"{prompt}\n\n"
        "Structured input data follows as JSON. Base your assessment only on this data.\n\n"
        f"{json.dumps(compact, indent=2, default=str)}\n"
    )


class OllamaAnalyzer:
    def __init__(self, model: str, endpoint: str, timeout: int = 120, prompt: str = ""):
        self.model = model
        self.endpoint = endpoint
        self.timeout = timeout
        self.prompt = prompt

    def analyze(self, report_data: Dict[str, Any], output_dir: Path) -> Tuple[Path, Path]:
        prompt = build_ollama_prompt(report_data, self.prompt)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode())

        text = body.get("response", "").strip()
        md_path = output_dir / "ai_assessment.md"
        raw_path = output_dir / "ai_assessment.json"

        with open(md_path, "w") as handle:
            handle.write(text + "\n")

        with open(raw_path, "w") as handle:
            json.dump({
                "model": self.model,
                "endpoint": self.endpoint,
                "prompt_preview": prompt[:3000],
                "response": body,
            }, handle, indent=2, default=str)

        return md_path, raw_path
