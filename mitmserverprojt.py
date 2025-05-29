#!/usr/bin/env python3
import base64
import logging
import asyncio
import itertools
import os
import signal
import time
import requests
from urllib.parse import urlparse
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# ─────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────
MITM_PORT = 8443

# VirusTotal API keys (hardcoded)
VT_API_KEYS = [
    "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416",
    "b7b3510d6136926eb092d853ea0968ca0f0df2228fdb2e302e25ea113520aca0",
    "6e5281c4f459d5192fc42c9282ca94228c535e2329c2f3dda676cc61286cb91e",
    "16539b7c5e8140decd35a6110b00c5a794ee21f2bddb605e55e6c8c3e3ad6898",
    "0f53125a357dcffafb064976bfac2c47d3e20181720dc0d391ad7bf83608d319",
]
_key_cycle = itertools.cycle(VT_API_KEYS)
# Limit to one concurrent scan per key
scan_semaphore = asyncio.Semaphore(len(VT_API_KEYS))
# Cache per host to avoid re-scanning
_host_cache = {}

BLOCK_MALICIOUS = True
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# Polling settings
POLL_INTERVAL = 1  # seconds between analysis checks
MAX_POLLS = 5      # total attempts (max wait = POLL_INTERVAL * MAX_POLLS)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")


def get_vt_api_key() -> str:
    return next(_key_cycle)


def sync_scan_host(host: str) -> bool:
    """Submit host to VT and poll until complete."""
    api_key = get_vt_api_key()
    headers = {"x-apikey": api_key}
    url = host if host.startswith("http") else f"https://{host}/"
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

    for _ in range(MAX_POLLS):
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=15
            )
        except Exception as e:
            logger.warning(f"[!] VT GET error for {url}: {e}")
            break
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                mal = stats.get("malicious", 0) > 0
                logger.info(f"[VT] analysis for {url} done: malicious={mal}")
                return mal
        else:
            logger.warning(f"[!] VT GET failed {resp.status_code} for {url}")
            break
        time.sleep(POLL_INTERVAL)

    logger.warning(f"[!] VT scan timeout for {url}")
    return False

async def scan_host(host: str) -> bool:
    """Async wrapper: run sync_scan_host under semaphore, with caching."""
    if host in _host_cache:
        return _host_cache[host]
    async with scan_semaphore:
        result = await asyncio.get_event_loop().run_in_executor(None, sync_scan_host, host)
    _host_cache[host] = result
    return result

class AllInOne:
    async def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Serve the CA cert
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(404, b"CA not found")
                return
            cert = open(CA_PATH, "rb").read()
            flow.response = http.Response.make(200, cert, {"Content-Type": "application/x-pem-file"})
            return

        # Only scan top-level HTML navigations
        if flow.request.method == "GET" and "text/html" in flow.request.headers.get("Accept", ""):
            parsed = urlparse(url)
            host = parsed.netloc
            if BLOCK_MALICIOUS and await scan_host(host):
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
