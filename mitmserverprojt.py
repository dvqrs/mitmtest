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

# Hardcoded VirusTotal API keys (rotate through them)
VT_API_KEYS = [
    "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416",
    "b7b3510d6136926eb092d853ea0968ca0f0df2228fdb2e302e25ea113520aca0",
    "6e5281c4f459d5192fc42c9282ca94228c535e2329c2f3dda676cc61286cb91e",
    "16539b7c5e8140decd35a6110b00c5a794ee21f2bddb605e55e6c8c3e3ad6898",
    "0f53125a357dcffafb064976bfac2c47d3e20181720dc0d391ad7bf83608d319",
]
_key_cycle = itertools.cycle(VT_API_KEYS)
scan_semaphore = asyncio.Semaphore(len(VT_API_KEYS))

# Cache results per domain to avoid repeated lookups
_domain_cache = {}
CACHE_TTL = 3600  # 1 hour
_cache_timestamps = {}

# Cache for file scans? (Optional: you can keep a short‐term cache of hashes)
_file_cache = {}
_file_cache_timestamps = {}
FILE_CACHE_TTL = 3600

# Block flags
BLOCK_MALICIOUS = True
# MITM CA path (to serve it on /mitmproxy-ca-cert.pem)
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")

def get_vt_api_key() -> str:
    """Round‐robin selection of VT API key."""
    return next(_key_cycle)

def is_domain_malicious(domain: str) -> bool:
    """
    Query VT domain endpoint and return True if any engine flags malicious.
    Uses a simple in‐memory TTL cache.
    """
    now = time.time()
    if domain in _domain_cache:
        age = now - _cache_timestamps.get(domain, 0)
        if age < CACHE_TTL:
            return _domain_cache[domain]

    api_key = get_vt_api_key()
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        logger.info(f"[VT] Checking domain reputation: {domain} (key …{api_key[-6:]})")
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) > 0
        _domain_cache[domain] = malicious
        _cache_timestamps[domain] = now
        logger.info(f"[VT] Domain {domain} → malicious={malicious}")
        return malicious
    except Exception as e:
        logger.warning(f"[VT] error checking domain {domain}: {e}")
        # If VT fails, default to “not malicious” (risky choice)
        return False

async def is_file_malicious(content_bytes: bytes) -> bool:
    """
    Submit the binary payload to VT’s file‐scan endpoint, wait for analysis,
    and return True if VT flags it malicious. Uses in‐memory cache by SHA256.
    """
    import hashlib

    sha256 = hashlib.sha256(content_bytes).hexdigest()
    now = time.time()
    # Use cache if we scanned this exact file (by hash) recently
    if sha256 in _file_cache:
        age = now - _file_cache_timestamps.get(sha256, 0)
        if age < FILE_CACHE_TTL:
            return _file_cache[sha256]

    # Acquire a semaphore token (so we don’t exceed number of keys)
    async with scan_semaphore:
        api_key = get_vt_api_key()
        headers = {"x-apikey": api_key}
        files = {"file": ("upload.bin", content_bytes)}
        try:
            logger.info(f"[VT] Uploading file (sha256={sha256[:10]}…) for scan (key …{api_key[-6:]})")
            upload_resp = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files=files,
                timeout=30
            )
            upload_resp.raise_for_status()
            analysis_id = upload_resp.json()["data"]["id"]
        except Exception as e:
            logger.warning(f"[VT] file upload error: {e}")
            # Treat as “not malicious” on upload failure (you could also choose to block)
            _file_cache[sha256] = False
            _file_cache_timestamps[sha256] = now
            return False

    # Poll for analysis results
    vt_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        try:
            time.sleep(2)  # wait a bit before polling
            headers = {"x-apikey": api_key}
            r = requests.get(vt_url, headers=headers, timeout=10)
            r.raise_for_status()
            j = r.json()
            status = j.get("data", {}).get("attributes", {}).get("status")
            if status == "queued":
                continue
            if status == "completed":
                stats = j.get("data", {}).get("attributes", {}).get("stats", {})
                malicious = stats.get("malicious", 0) > 0
                logger.info(f"[VT] File analysis completed: malicious={malicious}")
                _file_cache[sha256] = malicious
                _file_cache_timestamps[sha256] = now
                return malicious
            else:
                # Unexpected status; break and treat as not malicious
                logger.warning(f"[VT] Unexpected file analysis status: {status}")
                _file_cache[sha256] = False
                _file_cache_timestamps[sha256] = now
                return False
        except Exception as e:
            logger.warning(f"[VT] error polling file analysis: {e}")
            _file_cache[sha256] = False
            _file_cache_timestamps[sha256] = now
            return False

class AllInOne:
    async def request(self, flow: http.HTTPFlow):
        """
        Called on every client → proxy → server request.
        We already check domain reputation here; you could also inspect request payloads.
        """
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # If client explicitly requests the CA, serve it (same as before)
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(
                    404, b"CA not found", {"Content-Type": "text/plain"}
                )
                return
            with open(CA_PATH, "rb") as f:
                cert_bytes = f.read()
            flow.response = http.Response.make(
                200,
                cert_bytes,
                {
                    "Content-Type": "application/x-pem-file",
                    "Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem",
                },
            )
            return

        # Domain‐based blocking (as before)
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        malicious_domain = is_domain_malicious(domain)
        if BLOCK_MALICIOUS and malicious_domain:
            flow.response = http.Response.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked by VT domain reputation</p>",
                {"Content-Type": "text/html"},
            )
            return

        # OPTIONAL: Inspect the request body for suspicious patterns
        # (e.g. SQLi or JS payload). Here’s an example regex check:
        ctype_req = flow.request.headers.get("Content-Type", "").lower()
        if flow.request.method == "POST" and "application/x-www-form-urlencoded" in ctype_req:
            # Get the raw text (forms):
            try:
                text_req = flow.request.get_text(strict=False)
            except ValueError:
                text_req = ""
            # Simple example: block if SQL‐injection patterns appear
            import re
            if re.search(r"(?:')|(?:--)|(/\\*)|(\\*/)|(;)", text_req):
                logger.warning(f"[REQUEST] Possible SQL‐i payload in {url}")
                flow.response = http.Response.make(
                    403,
                    b"<h1>403 Forbidden</h1><p>Blocked suspicious request payload</p>",
                    {"Content-Type": "text/html"},
                )
                return
        # Otherwise, let the request proceed to the server
        # (i.e. do nothing, mitmproxy will forward it)

    async def response(self, flow: http.HTTPFlow):
        """
        Called on every server → proxy → client response.
        Here we inspect the response content to detect malicious payloads.
        """
        if flow.response is None:
            return

        url = flow.request.pretty_url
        logger.info(f"[RESPONSE] {url}")

        # 1) Inspect response HTTP headers
        ctype = flow.response.headers.get("Content-Type", "").lower()
        # If it’s an HTML page, you might scan for embedded malicious JavaScript:
        if "text/html" in ctype or "application/javascript" in ctype:
            try:
                text_resp = flow.response.get_text(strict=False)
            except ValueError:
                text_resp = ""
            # Example: look for extremely obfuscated JS (e.g. eval(base64_decode(…)) )
            import re
            if re.search(r"eval\(.*base64_decode", text_resp):
                logger.warning(f"[RESPONSE] Suspicious obfuscated JS in {url}")
                if BLOCK_MALICIOUS:
                    flow.response = http.Response.make(
                        403,
                        b"<h1>403 Forbidden</h1><p>Blocked obfuscated JavaScript</p>",
                        {"Content-Type": "text/html"},
                    )
                    return

        # 2) If it’s a binary download (e.g. EXE, DLL, PDF, ZIP, application/octet-stream), submit to VT
        binary_types = [
            "application/octet-stream",
            "application/pdf",
            "application/zip",
            "application/x-msdownload",  # .exe
            "application/x-msdos‐program", 
            "application/vnd.microsoft.portable‐executable",
        ]
        if any(bt in ctype for bt in binary_types):
            # Grab the raw bytes
            raw_data = flow.response.raw_content
            # Check cache + scan
            try:
                malicious_file = await is_file_malicious(raw_data)
            except Exception as e:
                logger.warning(f"[RESPONSE] file scanning error: {e}")
                malicious_file = False
            if BLOCK_MALICIOUS and malicious_file:
                logger.warning(f"[RESPONSE] Blocking malicious file from {url}")
                # Replace the body with a 403 page
                flow.response = http.Response.make(
                    403,
                    b"<h1>403 Forbidden</h1><p>Blocked malicious file download</p>",
                    {"Content-Type": "text/html"},
                )
                return

        # 3) Otherwise, let the clean response pass through
        # No modification means mitmproxy will forward it as‐is.

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
