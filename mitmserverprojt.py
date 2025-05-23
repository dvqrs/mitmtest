#!/usr/bin/env python3
import os
import base64
import requests
import threading
import signal
import sys

from mitmproxy import http, ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

# ────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────
MITM_PORT      = int(os.getenv("MITMPROXY_PORT", "8443"))
VT_API_KEY     = os.getenv("VT_API_KEY", "<your-virustotal-api-key>")
BLOCK_MALICIOUS = True

# ────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────
def ca_cert_path() -> str:
    # mitmproxy writes its CA here by default
    return os.path.join(ctx.options.confdir, "mitmproxy-ca-cert.pem")

def load_ca_bytes() -> bytes:
    path = ca_cert_path()
    if not os.path.isfile(path):
        ctx.log.warn(f"CA not found at {path} (visit any HTTPS site to generate it)")
        return b""
    with open(path, "rb") as f:
        return f.read()

# ────────────────────────────────────────────────────
# VirusTotal lookup
# ────────────────────────────────────────────────────
def is_malicious(url: str) -> bool:
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=5
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) > 0
    except Exception as e:
        ctx.log.warn(f"VT lookup failed for {url}: {e}")
    return False

# ────────────────────────────────────────────────────
# mitmproxy Add-on
# ────────────────────────────────────────────────────
class AllInOne:
    def request(self, flow: http.HTTPFlow) -> None:
        # CA download request?
        if flow.request.method.upper() == "GET" and flow.request.path == "/mitmproxy-ca-cert.pem" and flow.request.scheme == "http":
            ca_bytes = load_ca_bytes()
            if not ca_bytes:
                flow.response = http.HTTPResponse.make(
                    404, b"CA not generated yet. Visit any HTTPS site through this proxy first.",
                    {"Content-Type": "text/plain"}
                )
            else:
                flow.response = http.HTTPResponse.make(
                    200, ca_bytes,
                    {
                        "Content-Type": "application/x-pem-file",
                        "Content-Length": str(len(ca_bytes))
                    }
                )
                ctx.log.info("[CA] Served mitmproxy root certificate")
            return

        # Otherwise proxy traffic
        url = flow.request.pretty_url
        ctx.log.info(f"[REQUEST] {url}")
        if BLOCK_MALICIOUS and is_malicious(url):
            ctx.log.info(f"[BLOCKED] {url}")
            flow.response = http.HTTPResponse.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked by MITM firewall.</p>",
                {"Content-Type": "text/html"}
            )

    def response(self, flow: http.HTTPFlow) -> None:
        pass

# ────────────────────────────────────────────────────
# AUTO-START mitmproxy
# ────────────────────────────────────────────────────
if __name__ == "__main__":
    # Prepare mitmproxy options
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)
    m = DumpMaster(opts)
    # Register our addon
    m.addons.add(AllInOne())

    # Graceful shutdown on signals
    def shutdown(sig, frame):
        ctx.log.info("Shutting down mitmproxy…")
        m.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    ctx.log.info(f"Starting mitmproxy all-in-one on port {MITM_PORT}...")
    try:
        m.run()
    except KeyboardInterrupt:
        shutdown(None, None)
