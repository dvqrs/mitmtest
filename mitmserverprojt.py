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

# Hardcoded VirusTotal API keys
VT_API_KEYS = [
    "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416",
    "b7b3510d6136926eb092d853ea0968ca0f0df2228fdb2e302e25ea113520aca0",
    "6e5281c4f459d5192fc42c9282ca94228c535e2329c2f3dda676cc61286cb91e",
    "16539b7c5e8140decd35a6110b00c5a794ee21f2bddb605e55e6c8c3e3ad6898",
    "0f53125a357dcffafb064976bfac2c47d3e20181720dc0d391ad7bf83608d319",
]
# Round-robin iterator for keys and semaphore to limit concurrency
_key_cycle = itertools.cycle(VT_API_KEYS)
scan_semaphore = asyncio.Semaphore(len(VT_API_KEYS))
# Cache results per domain to avoid repeated lookups
_domain_cache = {}
# Optional: add a TTL for cache entries (in seconds)
CACHE_TTL = 3600  # 1 hour
_cache_timestamps = {}

# Whether to block malicious domains
BLOCK_MALICIOUS = True
# Path where mitmproxy stores its CA
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")


def get_vt_api_key() -> str:
    """Round-robin selection of VT API key."""
    return next(_key_cycle)


def check_domain_reputation(domain: str) -> bool:
    """Query VT domain endpoint and return True if any engine flags malicious."""
    # Use cache if fresh
    now = time.time()
    if domain in _domain_cache:
        age = now - _cache_timestamps.get(domain, 0)
        if age < CACHE_TTL:
            return _domain_cache[domain]

    api_key = get_vt_api_key()
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        logger.info(f"[VT] GET reputation for {domain} with key ...{api_key[-6:]}")
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {})
        attrs = data.get("attributes", {}).get("last_analysis_stats", {})
        malicious = attrs.get("malicious", 0) > 0
        # Cache result
        _domain_cache[domain] = malicious
        _cache_timestamps[domain] = now
        logger.info(f"[VT] reputation for {domain}: malicious={malicious}")
        return malicious
    except Exception as e:
        logger.warning(f"[VT] error checking reputation for {domain}: {e}")
        # On error, default to not malicious (or change per risk tolerance)
        return False


class AllInOne:
    async def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Serve CA cert directly
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(404, b"CA not found", {"Content-Type": "text/plain"})
                return
            with open(CA_PATH, "rb") as f:
                cert = f.read()
            flow.response = http.Response.make(
                200,
                cert,
                {
                    "Content-Type": "application/x-pem-file",
                    "Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"
                }
            )
            return

        # Only scan top-level HTML GET requests
        if flow.request.method == "GET" and "text/html" in flow.request.headers.get("Accept", ""):
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Check VT reputation asynchronously
            malicious = await asyncio.get_event_loop().run_in_executor(
                None, check_domain_reputation, domain
            )
            if BLOCK_MALICIOUS and malicious:
                flow.response = http.Response.make(
                    403,
                    b"<h1>403 Forbidden</h1><p>Blocked by VT reputation</p>",
                    {"Content-Type": "text/html"}
                )

    def response(self, flow: http.HTTPFlow):
        # No response modifications
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
