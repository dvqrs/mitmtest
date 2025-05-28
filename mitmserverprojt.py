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

# ─────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────
MITM_PORT = int(os.getenv("MITM_PORT", 8443))
VT_API_KEY = os.getenv("0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416", "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416")
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
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats.get("malicious", 0) > 0
        else:
            logger.warning(f"[!] VT API returned status {resp.status_code} for {url}")
    except Exception as e:
        logger.warning(f"[!] VT check error: {e}")
    return False

# ─────────────────────────────────────────────────────────
# Addon with VT firewall + CA serving
# ─────────────────────────────────────────────────────────
class AllInOne:
    def request(self, flow: http.HTTPFlow):
        """
        Handle normal HTTP/HTTPS requests inside an established tunnel.
        """
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Serve CA cert
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                logger.warning(f"CA not found at {CA_PATH} (generate by visiting any HTTPS site first)")
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
                    "Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"
                }
            )
            return

        # Block malicious URLs
        if BLOCK_MALICIOUS:
            verdict = is_malicious(url)
            logger.info(f"[VT] {url} → malicious={verdict}")
            if verdict:
                logger.warning(f"[BLOCKED] {url}")
                flow.response = http.Response.make(
                    403,
                    b"<h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p>",
                    {"Content-Type": "text/html"}
                )

    def http_connect(self, flow: http.HTTPFlow):
        """
        Intercept HTTPS CONNECT requests and block based on host.
        """
        host = flow.request.host
        url = f"https://{host}/"
        if BLOCK_MALICIOUS:
            verdict = is_malicious(url)
            logger.info(f"[VT CONNECT] {host} → malicious={verdict}")
            if verdict:
                logger.warning(f"[BLOCKED CONNECT] {host}")
                flow.kill()

    def response(self, flow: http.HTTPFlow):
        """
        No custom response logic; default logging still applies.
        """
        return

# ─────────────────────────────────────────────────────────
# Async runner
# ─────────────────────────────────────────────────────────
async def run_proxy():
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)
    m = DumpMaster(opts)
    m.addons.add(AllInOne())

    loop = asyncio.get_running_loop()
    def shutdown():
        logger.info("[*] Shutting down mitmproxy…")
        asyncio.create_task(m.shutdown())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    logger.info(f"[*] mitmproxy all-in-one running on port {MITM_PORT}…")
    await m.run()

# ─────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        asyncio.run(run_proxy())
    except KeyboardInterrupt:
        pass
