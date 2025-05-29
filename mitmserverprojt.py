#!/usr/bin/env python3
import os
import signal
import base64
import logging
import asyncio
import itertools

import requests
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# ─────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────
MITM_PORT = 8443

# Hardcoded VirusTotal API keys
VT_API_KEYS = [
    "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416",
    "b7b3510d6136926eb092d853ea0968ca0f0df2228fdb2e302e25ea113520aca0",
    "6e5281c4f459d5192fc42c9282ca94228c535e2329c2f3dda676cc61286cb91e",
    "16539b7c5e8140decd35a6110b00c5a794ee21f2bddb605e55e6c8c3e3ad6898",
    "0f53125a357dcffafb064976bfac2c47d3e20181720dc0d391ad7bf83608d319",
]

# Create a cycling iterator to rotate keys on each use
_key_cycle = itertools.cycle(VT_API_KEYS)

# Should we block malicious URLs?
BLOCK_MALICIOUS = True

# Path to mitmproxy CA cert
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")


def get_vt_api_key() -> str:
    """Return the next API key from the cycle."""
    return next(_key_cycle)


def is_malicious(url: str) -> bool:
    """Query VirusTotal for the URL; return True if flagged malicious."""
    try:
        api_key = get_vt_api_key()
        # Log which key and URL we're checking
        logger.info(f"[VT] using key ending with ...{api_key[-6:]} to check {url}")

        # VT expects a URL ID encoded in base64 without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if resp.status_code == 200:
            stats = resp.json().get("data", {}) \
                               .get("attributes", {}) \
                               .get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            logger.info(f"[VT] analysis result for {url}: malicious={malicious_count}")
            return malicious_count > 0

        # Log 404s explicitly
        if resp.status_code == 404:
            logger.info(f"[VT] no record for {url} (404); treating as clean")
            return False

        # Other errors
        logger.warning(f"[VT] unexpected status {resp.status_code} for {url}")
    except Exception as e:
        logger.warning(f"[VT] error checking {url}: {e}")
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
    loop = asyncio.get_running_loop()
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)
    m = DumpMaster(opts)
    m.addons.add(AllInOne())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(m.shutdown()))

    logger.info(f"[*] mitmproxy running on port {MITM_PORT}…")
    await m.run()


if __name__ == "__main__":
    asyncio.run(run_proxy())
