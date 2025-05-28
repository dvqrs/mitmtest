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
# Config
# ─────────────────────────────────────────────────────────
MITM_PORT = int(os.getenv("MITM_PORT", 8443))
# Support multiple VirusTotal API keys via environment (Railway UI)
# Enter VT_API_KEY for primary key, and optionally VT_API_KEY_2...VT_API_KEY_5 for extras
env_keys = []
# Primary key
primary = os.getenv("VT_API_KEY")
if primary:
    env_keys.append(primary)
# Additional keys
for i in range(2, 6):
    key = os.getenv(f"VT_API_KEY_{i}")
    if key:
        env_keys.append(key)
if not env_keys:
    raise RuntimeError(
        "No VirusTotal API key provided. Set VT_API_KEY (and optionally VT_API_KEY_2...VT_API_KEY_5) in your environment."
    )
# Round-robin iterator
_key_cycle = itertools.cycle(env_keys)

_key_cycle = itertools.cycle(env_keys)

BLOCK_MALICIOUS = True
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

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
    # Round-robin API key
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
            logger.debug(f"VT[{api_key[:4]}] {url}→malicious={malicious}")
            return malicious
        elif resp.status_code == 429:
            logger.warning(f"[!] VT rate-limit with key {api_key[:4]} for {url}")
            # Default to safe (not malicious) on rate-limit
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
        # Serve CA
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
        # Block
        if BLOCK_MALICIOUS and is_malicious(url):
            logger.warning(f"[BLOCKED] {url}")
            flow.response = http.Response.make(
                403, b"<h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p>", {"Content-Type": "text/html"}
            )

    def http_connect(self, flow: http.HTTPFlow):
        host = flow.request.host
        url = f"https://{host}/"
        if BLOCK_MALICIOUS and is_malicious(url):
            logger.warning(f"[BLOCKED CONNECT] {host}")
            flow.kill()

    def response(self, flow: http.HTTPFlow):
        # Tear down upstream connection to force new CONNECT next time
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
