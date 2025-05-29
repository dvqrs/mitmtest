#!/usr/bin/env python3
import base64
import logging
import asyncio
import itertools
import os
import signal
import time
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
# Round-robin iterator for keys\_key
_key_cycle = itertools.cycle(VT_API_KEYS)
# Limit concurrent scans to number of keys\_sem
scan_semaphore = asyncio.Semaphore(len(VT_API_KEYS))
BLOCK_MALICIOUS = True
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")


def get_vt_api_key() -> str:
    return next(_key_cycle)


def sync_scan_url(url: str) -> bool:
    """Sync VT submit-and-poll; to be run in executor."""
    api_key = get_vt_api_key()
    headers = {"x-apikey": api_key}
    logger.info(f"[VT] POST /urls for {url} with key ...{api_key[-6:]}")
    try:
        post = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )
    except Exception as e:
        logger.warning(f"[!] VT POST error for {url}: {e}")
        return False
    if post.status_code != 200:
        logger.warning(f"[!] VT POST failed {post.status_code} for {url}")
        return False
    analysis_id = post.json().get("data", {}).get("id")
    if not analysis_id:
        return False

    for _ in range(10):
        try:
            get = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=15
            )
        except Exception as e:
            logger.warning(f"[!] VT GET error for {url}: {e}")
            break
        if get.status_code == 200:
            attrs = get.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                malicious = stats.get("malicious", 0) > 0
                logger.info(f"[VT] completed {url}: malicious={malicious}")
                return malicious
        else:
            logger.warning(f"[!] VT GET failed {get.status_code} for {url}")
            break
        time.sleep(5)

    logger.warning(f"[!] VT scan timeout for {url}")
    return False

async def scan_url(url: str) -> bool:
    """
    Run sync_scan_url in thread pool under semaphore.
    """
    async with scan_semaphore:
        return await asyncio.get_event_loop().run_in_executor(None, sync_scan_url, url)

class AllInOne:
    async def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Serve CA cert
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(404, b"CA not found", {"Content-Type": "text/plain"})
                return
            with open(CA_PATH, "rb") as f:
                cert = f.read()
            flow.response = http.Response.make(
                200,
                cert,
                {"Content-Type": "application/x-pem-file", "Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"}
            )
            return

        # Only scan top-level HTML GETs
        if flow.request.method == "GET" and "text/html" in flow.request.headers.get("Accept", ""):
            if BLOCK_MALICIOUS:
                malicious = await scan_url(url)
                if malicious:
                    flow.response = http.Response.make(
                        403,
                        b"<h1>403 Forbidden</h1><p>Blocked by VT</p>",
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
