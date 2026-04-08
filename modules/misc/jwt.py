"""
JWT — jwt_tool, jwt-hack
"""

from typing import Dict
from modules.base import BaseModule


class JWT(BaseModule):
    name = "jwt"
    description = "JSON Web Token testing"
    category = "misc"
    tools_required = ["jwt_tool"]
    tools_optional = ["jwt-hack"]

    def run(self) -> Dict:
        cfg = self.config

        # Look for JWTs in gathered URLs and responses
        gathered = self.ctx.get("gathered_urls", [])
        import re
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

        tokens = set()
        for url in gathered:
            matches = jwt_pattern.findall(url)
            tokens.update(matches)

        if not tokens:
            self.log("No JWT tokens found in pipeline data.", level="warn")
            self.write_lines(self.phase_dir / "jwt_note.txt",
                             ["No JWTs found. Manually supply tokens for testing."])
            return self.get_results()

        self.log(f"Found {len(tokens)} unique JWT(s)")
        self.write_lines(self.phase_dir / "found_jwts.txt", tokens)

        # --- jwt_tool ---
        if cfg.get("use_jwt_tool", True) and self.tool_exists("jwt_tool"):
            for token in list(tokens)[:cfg.get("max_tokens", 10)]:
                safe = str(hash(token) % 100000)
                out = self.phase_dir / f"jwt_tool_{safe}.txt"
                result = self.exec([
                    "jwt_tool", token, "-M", "at",
                    "-t", self.ctx.get("alive_urls", [""])[0],
                ], timeout=300, label="jwt_tool")

                if result and result.stdout:
                    with open(out, "w") as f:
                        f.write(result.stdout)
                    if "vulnerable" in result.stdout.lower():
                        self.findings.append({
                            "type": "jwt_vulnerability",
                            "token": token[:50] + "...",
                            "detail": result.stdout[:500],
                        })

        self.write_json(self.phase_dir / "jwt_findings.json", self.findings)
        self.log(f"JWT findings: {len(self.findings)}")
        return self.get_results()
