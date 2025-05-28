#!/usr/bin/env python3
import os
import signal
import base64
import logging
import asyncio
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
import requests
from functools import lru_cache
import itertools

# ─────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────
MITM_PORT = 8443  # adjust if needed
BLOCK_MALICIOUS = True
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# ─────────────────────────────────────────────────────────
# VirusTotal API keys (enter directly below)
# ─────────────────────────────────────────────────────────
# Replace these placeholders with your real VirusTotal keys
VT_API_KEYS = [
    "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416",
    "b7b3510d6136926eb092d853ea0968ca0f0df2228fdb2e302e25ea113520aca0",
    "6e5281c4f459d5192fc42c9282ca94228c535e2329c2f3dda676cc61286cb91e",  # optional: remove or leave blank
    "16539b7c5e8140decd35a6110b00c5a794ee21f2bddb605e55e6c8c3e3ad6898",
    "0f53125a357dcffafb064976bfac2c47d3e20181720dc0d391ad7bf83608d319",
]
# Filter out any empty strings
VT_API_KEYS = [k for k in VT_API_KEYS if k]
if not VT_API_KEYS:
    raise RuntimeError(
        "No VirusTotal API keys provided. Please edit the script and populate VT_API_KEYS."
    )
# Create a round-robin iterator
_key_cycle = itertools.cycle(VT_API_KEYS)

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")

# ─────────────────────────────────────────────────────────
# VirusTotal check with LRU cache
# ─────────────────────────────────────────────────────────
@lru_cache(maxsize=512)
def is_malicious(url: str) -> bool:
    """
    Check a URL against VT, rotating API keys and caching verdicts.
    """
    api_key = next(_key_cycle)
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=10
        )
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) > 0
            logger.debug(f"VT[{api_key[:4]}] {url} → malicious={malicious}")
            return malicious
        elif resp.status_code == 429:
            logger.warning(f"[!] VT rate-limit with key {api_key[:4]} for {url}")
            # Default to safe on rate-limit
            return False
        else:
            logger.warning(f"[!] VT API returned {resp.status_code} for {url}")
    except Exception as e:
        logger.warning(f"[!] VT error for {url}: {e}")
    return False

# ─────────────────────────────────────────────────────────
# Addon with VT firewall + CA serving
# ─────────────────────────────────────────────────────────
class AllInOne:
    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")
        # Serve the CA certificate
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(404, b"CA not found", {"Content-Type": "text/plain"})
                return
            with open(CA_PATH, "rb") as f:
                body = f.read()
            flow.response = http.Response.make(
                200, body,
                {"Content-Type": "application/x-pem-file", "Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"}
            )
            return
        # Block malicious URLs
        if BLOCK_MALICIOUS and is_malicious(url):
            logger.warning(f"[BLOCKED] {url}")
            flow.response = http.Response.make(403, b"<h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p>",
                {"Content-Type": "text/html"})

    def http_connect(self, flow: http.HTTPFlow):
        host = flow.request.host
        url = f"https://{host}/"
        if BLOCK_MALICIOUS and is_malicious(url):
            logger.warning(f"[BLOCKED CONNECT] {host}")
            flow.kill()

    def response(self, flow: http.HTTPFlow):
        # Close upstream connection after each response to force new CONNECT next time
        try:
            if flow.server_conn:
                flow.server_conn.close()
        except Exception:
            pass

# ─────────────────────────────────────────────────────────
# Async runner
# ─────────────────────────────────────────────────────────
async def run_proxy():
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)
    m = DumpMaster(opts)
    m.addons.add(AllInOne())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(m.shutdown()))
    await m.run()

if __name__ == "__main__":
    try:
        asyncio.run(run_proxy())
    except KeyboardInterrupt:
        pass
