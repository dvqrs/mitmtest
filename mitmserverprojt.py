#!/usr/bin/env python3
import os
import sys
import signal
import base64
import logging
import asyncio
import re
import requests

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# ─────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────
MITM_PORT = int(os.getenv("MITMPROXY_PORT", "8443"))
VT_API_KEY = os.getenv("0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416", "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416")
BLOCK_MALICIOUS = True
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")

# ─────────────────────────────────────────────────────────
# Content Inspection Helpers
# ─────────────────────────────────────────────────────────
MALICIOUS_PATTERNS = [
    b"<script>alert(1)",  # example XSS
    b"UNION SELECT",     # SQL injection
    b"/etc/passwd",      # LFI
]
KEYWORD_REGEX = re.compile(rb"(malware|virus|trojan)", re.IGNORECASE)

def inspect_bytes(content: bytes) -> bool:
    for pat in MALICIOUS_PATTERNS:
        if pat in content:
            return True
    if KEYWORD_REGEX.search(content):
        return True
    return False

# ─────────────────────────────────────────────────────────
# VirusTotal Lookup
# ─────────────────────────────────────────────────────────
def is_malicious(url: str) -> bool:
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=5
        )
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats.get("malicious", 0) > 0
    except Exception as e:
        logger.warning(f"VT lookup failed for {url}: {e}")
    return False

# ─────────────────────────────────────────────────────────
# MITMproxy Add-on
# ─────────────────────────────────────────────────────────
class AllInOne:
    def request(self, flow: http.HTTPFlow) -> None:
        # Serve CA certificate
        if (
            flow.request.method.upper() == "GET"
            and flow.request.path == "/mitmproxy-ca-cert.pem"
            and flow.request.scheme == "http"
        ):
            if not os.path.isfile(CA_PATH):
                logger.warning(f"CA not found at {CA_PATH}")
                flow.response = http.Response.make(
                    404,
                    b"CA not yet generated. Visit any HTTPS site through this proxy first.",
                    {"Content-Type": "text/plain"}
                )
            else:
                body = open(CA_PATH, "rb").read()
                flow.response = http.Response.make(
                    200,
                    body,
                    {
                        "Content-Type": "application/x-pem-file",
                        "Content-Length": str(len(body)),
                        "Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"
                    }
                )
                logger.info("[CA] Served mitmproxy root certificate")
            return

        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Inspect request content
        content = flow.request.raw_content or b""
        if inspect_bytes(content):
            logger.warning(f"[ALERT] Malicious pattern in request to {url}")

        # VirusTotal blocking
        if BLOCK_MALICIOUS and is_malicious(url):
            logger.warning(f"[BLOCKED] {url}")
            flow.response = http.Response.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        status = flow.response.status_code
        length = len(flow.response.raw_content or b"")
        logger.info(f"[RESPONSE] {url} ← {status} ({length} bytes)")

        if inspect_bytes(flow.response.raw_content or b""):
            logger.warning(f"[ALERT] Malicious pattern in response from {url}")

# ─────────────────────────────────────────────────────────
# Async Runner
# ─────────────────────────────────────────────────────────
async def run_proxy() -> None:
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)
    m = DumpMaster(opts)
    m.addons.add(AllInOne())

    def shutdown() -> None:
        logger.info("[*] Shutting down mitmproxy…")
        m.shutdown()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    logger.info(f"[*] mitmproxy all-in-one running on port {MITM_PORT}…")
    await m.run()

# ─────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    asyncio.run(run_proxy())
