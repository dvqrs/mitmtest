#!/usr/bin/env python3
import os
import signal
import base64
import logging
import asyncio

import requests
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# ─────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────
MITM_PORT = 8443
VT_API_KEY = os.getenv("0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416", "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416")
BLOCK_MALICIOUS = True
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")

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

class AllInOne:
    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Serve CA cert
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(
                    404, b"CA not found", {"Content-Type": "text/plain"}
                )
                return
            with open(CA_PATH, "rb") as f:
                cert = f.read()
            flow.response = http.Response.make(
                200, cert,
                {
                    "Content-Type": "application/x-pem-file",
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
        pass

async def run_proxy():
    # 1) We're already inside an async context, so get_running_loop() works
    loop = asyncio.get_running_loop()

    # 2) Configure your mitmproxy options
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)

    # 3) Instantiate DumpMaster *without* event_loop kwarg
    m = DumpMaster(opts)
    m.addons.add(AllInOne())

    # 4) Graceful shutdown on SIGINT/SIGTERM
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(m.shutdown()))

    logger.info(f"[*] mitmproxy running on port {MITM_PORT}…")
    # 5) Run until shutdown is called
    await m.run()

if __name__ == "__main__":
    asyncio.run(run_proxy())
