"""
S3 / Cloud Bucket Scanning — S3Scanner, CloudBrute
"""

from typing import Dict
from modules.base import BaseModule


class Buckets(BaseModule):
    name = "buckets"
    description = "Cloud storage bucket misconfiguration scanning"
    category = "misc"
    tools_required = ["S3Scanner"]
    tools_optional = ["CloudBrute"]

    def run(self) -> Dict:
        domain = self.ctx.get("domain", "")
        subdomains = self.ctx.get("subdomains", [])
        cfg = self.config

        # Build bucket name candidates from domain/subdomains
        bucket_names = set()
        parts = domain.split(".")
        bucket_names.add(parts[0])
        bucket_names.add(domain.replace(".", "-"))
        bucket_names.add(domain.replace(".", ""))
        for sub in subdomains[:50]:
            bucket_names.add(sub.split(".")[0])
            bucket_names.add(sub.replace(".", "-"))

        wordlist = self.phase_dir / "bucket_names.txt"
        self.write_lines(wordlist, bucket_names)

        # --- S3Scanner ---
        if cfg.get("use_s3scanner", True) and self.tool_exists("S3Scanner"):
            out = self.phase_dir / "s3scanner_results.txt"
            self.exec([
                "S3Scanner", "scan", "--buckets-file", str(wordlist),
                "--out", str(out),
            ], timeout=600, label="S3Scanner")

            if out.exists():
                for line in open(out):
                    line = line.strip()
                    if line and ("exists" in line.lower() or "public" in line.lower()):
                        self.findings.append({
                            "type": "bucket_found",
                            "detail": line,
                        })

        # --- CloudBrute ---
        if cfg.get("use_cloudbrute", False) and self.tool_exists("CloudBrute"):
            out = self.phase_dir / "cloudbrute_results.txt"
            self.exec([
                "CloudBrute", "-d", domain,
                "-k", str(wordlist),
                "-o", str(out),
            ], timeout=600, label="CloudBrute")

        self.write_json(self.phase_dir / "bucket_findings.json", self.findings)
        self.log(f"Bucket findings: {len(self.findings)}")
        return self.get_results()
