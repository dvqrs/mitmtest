#!/usr/bin/env python3
import os
import sys
import signal
import base64
import logging
import asyncio
from urllib.parse import urlparse

import requests
from mitmproxy import http
from mitmproxy import ctx
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# ─────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────
MITM_PORT = 8443
VT_API_KEY = os.getenv("VT_API_KEY", "<your-virustotal-api-key>")
BLOCK_MALICIOUS = True
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")

# ─────────────────────────────────────────────────────────
# VirusTotal check
# ─────────────────────────────────────────────────────────
def is_malicious(url: str) -> bool:
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            stats = resp.json().get("data", {}) \
                               .get("attributes", {}) \
                               .get("last_analysis_stats", {})
            return stats.get("malicious", 0) > 0
    except Exception as e:
        logger.warning(f"[!] VT check error: {e}")
    return False

# ─────────────────────────────────────────────────────────
# Addon with VT firewall + CA serving
# ─────────────────────────────────────────────────────────
class AllInOne:
    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Serve CA cert at /mitmproxy-ca-cert.pem
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                logger.warning(f"CA not found at {CA_PATH} (visit any HTTPS site to generate it)")
                flow.response = http.Response.make(
                    404, b"CA not found", {"Content-Type": "text/plain"}
                )
                return
            with open(CA_PATH, "rb") as f:
                body = f.read()
            flow.response = http.Response.make(
                200, body,
                {
                    "Content-Type": "application/x-pem-file",
                    "Content-Length": str(len(body)),
                    "Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"
                }
            )
            return

        # Block malicious URLs
        if BLOCK_MALICIOUS and is_malicious(url):
            logger.warning(f"[BLOCKED] {url}")
            flow.response = http.Response.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow):
        # (optional: log or scan responses here)
        pass

# ─────────────────────────────────────────────────────────
# Async runner
# ─────────────────────────────────────────────────────────
async def run_proxy():
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)
    m = DumpMaster(opts)
    m.addons.add(AllInOne())

    def shutdown():
        logger.info("[*] Shutting down mitmproxy…")
        asyncio.create_task(m.shutdown())

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    logger.info(f"[*] mitmproxy running on port {MITM_PORT}…")
    await m.run()

# ─────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    asyncio.run(run_proxy())
