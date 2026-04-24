import sqlite3
import tempfile
import threading
import time
import urllib.parse
import urllib.request as urllib_request
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from modules.exploit.open_redirect import OpenRedirect
from modules.exploit.ssrf import SSRF
from modules.exploit.clickjacking import Clickjacking
from modules.misc.api_exposure import APIExposure
from modules.misc.git_exposure import GitExposure
from modules.misc.rate_limiting import RateLimiting
from modules.misc.secrets import Secrets
from modules.misc.session_security import SessionSecurity
from modules.recon.content_discovery import ContentDiscovery
from modules.recon.technologies import Technologies
from modules.scope import ScopeEnforcer


class LabHandler(BaseHTTPRequestHandler):
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("create table items(id integer primary key, name text)")
    db.executemany("insert into items(name) values(?)", [("widget",), ("gadget",)])
    db.commit()

    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            body = f"""
            <html><head><title>Lab</title></head><body>
            <a href="/admin/login">admin</a>
            <a href="/redirect?next=/final">redirect</a>
            <a href="/fetch?url=http://127.0.0.1:{self.server.server_port}/internal">fetch</a>
            <a href="/static/app.js">js</a>
            </body></html>
            """.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/admin/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sessionid=abc123")
            self.end_headers()
            self.wfile.write(b"<form action='/login'><input name='user'></form>")
            return

        if path == "/swagger-ui":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>swagger ui</body></html>")
            return

        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", qs.get("next", ["/"])[0])
            self.end_headers()
            return

        if path == "/final":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"final")
            return

        if path == "/fetch":
            target = qs.get("url", [""])[0]
            try:
                data = urllib_request.urlopen(target, timeout=2).read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)
            except Exception as exc:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(exc).encode())
            return

        if path == "/internal":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ami-id\ninstance-id\nsecurity-credentials")
            return

        if path == "/static/app.js":
            body = b'const API_KEY = "AAAAAAAAAAAAAAAAAAAA111111111111";'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/.git/HEAD":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
            return

        self.send_response(404)
        self.end_headers()


class LocalLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.RequestHandlerClass.db.close()

    def setUp(self):
        self.scope = ScopeEnforcer()
        self.scope.in_scope_domains.add("127.0.0.1")
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.tmpdir.name)
        self.context = {
            "domain": "127.0.0.1",
            "subdomains": ["127.0.0.1"],
            "alive_hosts": [],
            "alive_urls": [],
            "port_results": [],
            "host_ports": {},
            "dir_findings": [],
            "gathered_urls": [
                f"http://127.0.0.1:{self.port}/redirect?next=/final",
                f"http://127.0.0.1:{self.port}/fetch?url=http://127.0.0.1:{self.port}/internal",
                f"http://127.0.0.1:{self.port}/static/app.js",
            ],
            "crawled_urls": [f"http://127.0.0.1:{self.port}/static/app.js"],
            "parameters": [],
            "vuln_findings": [],
        }

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_technologies_fallback_finds_local_target(self):
        mod = Technologies(
            self.output_dir,
            {"ports": str(self.port), "use_wafw00f": False, "use_whatweb": False},
            self.scope,
            self.context,
        )
        result = mod.run()
        self.assertGreaterEqual(result["findings_count"], 1)
        self.assertTrue(any(f":{self.port}" in url for url in self.context["alive_urls"]))

    def test_content_discovery_merges_findings_into_gathered_urls(self):
        self.context["alive_urls"] = [f"http://127.0.0.1:{self.port}/"]
        wordlist = self.output_dir / "words.txt"
        wordlist.write_text("admin/login\nstatic/app.js\n")

        mod = ContentDiscovery(
            self.output_dir,
            {
                "wordlist": str(wordlist),
                "extensions": "",
                "max_targets": 1,
                "use_katana": False,
                "use_gospider": False,
            },
            self.scope,
            self.context,
        )
        mod.run()
        self.assertTrue(any("/admin/login" in url for url in self.context["gathered_urls"]))

    def test_secrets_and_git_exposure_record_findings(self):
        self.context["alive_urls"] = [f"http://127.0.0.1:{self.port}/"]

        secrets = Secrets(
            self.output_dir,
            {
                "max_js_files": 5,
                "regex_patterns": [
                    r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|auth)[\s]*[=:][\s]*['\"]?[A-Za-z0-9/+=]{16,}"
                ],
            },
            self.scope,
            self.context,
        )
        git_exposure = GitExposure(self.output_dir, {"max_targets": 2}, self.scope, self.context)

        self.assertGreaterEqual(secrets.run()["findings_count"], 1)
        self.assertGreaterEqual(git_exposure.run()["findings_count"], 1)
        self.assertTrue(any(f.get("type") == "secret" for f in self.context["vuln_findings"]))
        self.assertTrue(any(f.get("type") == "git_exposure" for f in self.context["vuln_findings"]))

    def test_open_redirect_and_ssrf_confirm_findings(self):
        redirect = OpenRedirect(
            self.output_dir,
            {"max_targets": 2, "timeout": 2},
            self.scope,
            self.context,
        )
        ssrf = SSRF(
            self.output_dir,
            {"max_targets": 1, "timeout": 1},
            self.scope,
            self.context,
        )
        ssrf.SSRF_PAYLOADS = []

        self.assertGreaterEqual(redirect.run()["findings_count"], 1)
        self.assertGreaterEqual(ssrf.run()["findings_count"], 1)
        self.assertTrue(any(f.get("type") == "open_redirect" for f in self.context["vuln_findings"]))
        self.assertTrue(any(f.get("type") == "ssrf" for f in self.context["vuln_findings"]))

    def test_clickjacking_session_api_and_rate_limit_checks(self):
        self.context["alive_urls"] = [
            f"http://127.0.0.1:{self.port}/",
            f"http://127.0.0.1:{self.port}/admin/login",
        ]
        self.context["gathered_urls"].extend([
            f"http://127.0.0.1:{self.port}/admin/login",
            f"http://127.0.0.1:{self.port}/swagger-ui",
        ])

        clickjacking = Clickjacking(self.output_dir, {"max_targets": 10}, self.scope, self.context)
        session_security = SessionSecurity(self.output_dir, {"max_targets": 10}, self.scope, self.context)
        api_exposure = APIExposure(self.output_dir, {"max_targets": 5}, self.scope, self.context)
        rate_limiting = RateLimiting(self.output_dir, {"max_targets": 5}, self.scope, self.context)

        self.assertGreaterEqual(clickjacking.run()["findings_count"], 1)
        self.assertGreaterEqual(session_security.run()["findings_count"], 1)
        self.assertGreaterEqual(api_exposure.run()["findings_count"], 1)
        self.assertGreaterEqual(rate_limiting.run()["findings_count"], 1)


if __name__ == "__main__":
    unittest.main()
