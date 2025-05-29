#!/usr/bin/env python3
import base64
import logging
import asyncio
import itertools
import os
import signal

import httpx
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
# Cycle through keys for each new scan
_key_cycle = itertools.cycle(VT_API_KEYS)
# Limit concurrent scans to number of keys
scan_semaphore = asyncio.Semaphore(len(VT_API_KEYS))
# Block or allow unknown
BLOCK_MALICIOUS = True
# Path to mitmproxy CA
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")

# Shared HTTPX client for async VT requests
vt_client = httpx.AsyncClient(timeout=15.0)

async def get_vt_api_key() -> str:
    return next(_key_cycle)

async def scan_url(url: str) -> bool:
    """
    Submit URL to VT and poll until analysis completes.
    Runs under a semaphore to allow parallel scans up to key count.
    """
    async with scan_semaphore:
        api_key = await get_vt_api_key()
        headers = {"x-apikey": api_key}
        logger.info(f"[VT] POST /urls for {url} with key ...{api_key[-6:]}")
        post = await vt_client.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        if post.status_code != 200:
            logger.warning(f"[!] VT POST failed {post.status_code} for {url}")
            return False
        analysis_id = post.json().get("data", {}).get("id")
        if not analysis_id:
            return False

        # Poll analysis endpoint
        for _ in range(10):
            get = await vt_client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
            if get.status_code == 200:
                attrs = get.json().get("data", {}).get("attributes", {})
                if attrs.get("status") == "completed":
                    stats = attrs.get("stats", {})
                    malicious = stats.get("malicious", 0) > 0
                    logger.info(f"[VT] completed {url}: malicious={malicious}")
                    return malicious
            await asyncio.sleep(5)
        logger.warning(f"[!] VT scan timeout for {url}")
        return False

class AllInOne:
    async def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # serve CA cert
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(404, b"CA not found")
                return
            cert = open(CA_PATH, "rb").read()
            flow.response = http.Response.make(200, cert, {"Content-Type": "application/x-pem-file"})
            return

        # only scan top-level HTML GETs
        if flow.request.method == "GET" and "text/html" in flow.request.headers.get("Accept", ""):
            if BLOCK_MALICIOUS:
                # schedule scan and await result concurrently
                malicious = await scan_url(url)
                if malicious:
                    flow.response = http.Response.make(403, b"Blocked by VT", {"Content-Type": "text/html"})

def start_proxy():
    asyncio.run(_run())

async def _run():
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)
    m = DumpMaster(opts)
    m.addons.add(AllInOne())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(m.shutdown()))
    logger.info(f"[*] Mitmproxy on port {MITM_PORT}")
    await m.run()

if __name__ == "__main__":
    start_proxy()
