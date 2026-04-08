"""
Callback Server — Out-of-Band (OOB) testing server for blind vulnerabilities

Provides a lightweight HTTP/DNS callback server for detecting:
- Blind SSRF
- Blind XXE
- Blind XSS
- Out-of-band SQL injection
- DNS exfiltration
"""

import json
import socket
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, List, Optional, Callable
from urllib.parse import urlparse, parse_qs


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs all incoming requests."""

    callbacks: List[Dict] = []
    callback_file: Optional[Path] = None
    on_callback: Optional[Callable] = None

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def _log_callback(self, method: str):
        """Log the callback with details."""
        callback = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "path": self.path,
            "client_ip": self.client_address[0],
            "client_port": self.client_address[1],
            "headers": dict(self.headers),
            "query_params": parse_qs(urlparse(self.path).query),
        }

        # Extract marker from path (e.g., /ssrf-12345)
        path_parts = self.path.strip("/").split("/")
        if path_parts:
            callback["marker"] = path_parts[0]

        CallbackHandler.callbacks.append(callback)

        # Write to file if configured
        if CallbackHandler.callback_file:
            with open(CallbackHandler.callback_file, "a") as f:
                f.write(json.dumps(callback) + "\n")

        # Trigger callback function if configured
        if CallbackHandler.on_callback:
            try:
                CallbackHandler.on_callback(callback)
            except Exception:
                pass

        print(f"  [CALLBACK] {method} {self.path} from {self.client_address[0]}")

    def do_GET(self):
        self._log_callback("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")

        callback = {
            "timestamp": datetime.now().isoformat(),
            "method": "POST",
            "path": self.path,
            "client_ip": self.client_address[0],
            "client_port": self.client_address[1],
            "headers": dict(self.headers),
            "body": body[:1000],  # Limit body size
        }

        path_parts = self.path.strip("/").split("/")
        if path_parts:
            callback["marker"] = path_parts[0]

        CallbackHandler.callbacks.append(callback)

        if CallbackHandler.callback_file:
            with open(CallbackHandler.callback_file, "a") as f:
                f.write(json.dumps(callback) + "\n")

        if CallbackHandler.on_callback:
            try:
                CallbackHandler.on_callback(callback)
            except Exception:
                pass

        print(f"  [CALLBACK] POST {self.path} from {self.client_address[0]} (body: {len(body)} bytes)")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_HEAD(self):
        self._log_callback("HEAD")
        self.send_response(200)
        self.end_headers()


class CallbackServer:
    """
    Manages the callback server for OOB testing.

    Usage:
        server = CallbackServer(port=8888, output_dir=Path("./results"))
        server.start()

        # Get callback URL for payloads
        url = server.get_callback_url("ssrf-test-123")
        # -> http://YOUR_IP:8888/ssrf-test-123

        # Check for callbacks
        callbacks = server.get_callbacks(marker="ssrf-test-123")

        server.stop()
    """

    def __init__(
        self,
        port: int = 8888,
        output_dir: Optional[Path] = None,
        on_callback: Optional[Callable] = None,
    ):
        self.port = port
        self.output_dir = output_dir
        self.on_callback = on_callback
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.public_ip: Optional[str] = None

        # Configure handler
        CallbackHandler.callbacks = []
        CallbackHandler.on_callback = on_callback
        if output_dir:
            CallbackHandler.callback_file = output_dir / "callbacks.jsonl"
        else:
            CallbackHandler.callback_file = None

    def start(self) -> bool:
        """Start the callback server in a background thread."""
        try:
            self.server = HTTPServer(("0.0.0.0", self.port), CallbackHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()

            # Try to determine public IP
            self.public_ip = self._get_public_ip()

            print(f"  [+] Callback server started on port {self.port}")
            if self.public_ip:
                print(f"  [+] Public URL: http://{self.public_ip}:{self.port}/")

            return True

        except OSError as e:
            print(f"  [-] Failed to start callback server: {e}")
            return False

    def stop(self):
        """Stop the callback server."""
        if self.server:
            self.server.shutdown()
            self.server = None
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        print("  [+] Callback server stopped")

    def get_callback_url(self, marker: str = "") -> str:
        """
        Get a callback URL with optional marker for tracking.

        Args:
            marker: Unique identifier to track which payload triggered the callback

        Returns:
            Full callback URL (e.g., http://1.2.3.4:8888/ssrf-12345)
        """
        host = self.public_ip or self._get_local_ip() or "localhost"
        if marker:
            return f"http://{host}:{self.port}/{marker}"
        return f"http://{host}:{self.port}/"

    def get_callbacks(self, marker: Optional[str] = None, since: Optional[datetime] = None) -> List[Dict]:
        """
        Get recorded callbacks, optionally filtered by marker or time.

        Args:
            marker: Filter by marker string
            since: Only return callbacks after this time

        Returns:
            List of callback records
        """
        callbacks = CallbackHandler.callbacks.copy()

        if marker:
            callbacks = [c for c in callbacks if c.get("marker") == marker]

        if since:
            since_str = since.isoformat()
            callbacks = [c for c in callbacks if c.get("timestamp", "") > since_str]

        return callbacks

    def has_callback(self, marker: str) -> bool:
        """Check if a callback with the given marker was received."""
        return any(c.get("marker") == marker for c in CallbackHandler.callbacks)

    def wait_for_callback(self, marker: str, timeout: int = 30) -> Optional[Dict]:
        """
        Wait for a callback with the given marker.

        Args:
            marker: Marker to wait for
            timeout: Maximum seconds to wait

        Returns:
            Callback record if received, None if timeout
        """
        start = time.time()
        while time.time() - start < timeout:
            for c in CallbackHandler.callbacks:
                if c.get("marker") == marker:
                    return c
            time.sleep(0.5)
        return None

    def clear_callbacks(self):
        """Clear all recorded callbacks."""
        CallbackHandler.callbacks.clear()

    def _get_public_ip(self) -> Optional[str]:
        """Try to determine public IP address."""
        try:
            import urllib.request
            return urllib.request.urlopen(
                "https://api.ipify.org", timeout=3
            ).read().decode("utf-8").strip()
        except Exception:
            pass

        try:
            import urllib.request
            return urllib.request.urlopen(
                "https://ifconfig.me/ip", timeout=3
            ).read().decode("utf-8").strip()
        except Exception:
            pass

        return None

    def _get_local_ip(self) -> Optional[str]:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None


# Convenience function for quick testing
def run_callback_server(port: int = 8888):
    """Run callback server in foreground (for testing)."""
    server = CallbackServer(port=port)
    if server.start():
        print(f"\nCallback URL: {server.get_callback_url('test')}")
        print("Press Ctrl+C to stop...\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.stop()


if __name__ == "__main__":
    run_callback_server()
