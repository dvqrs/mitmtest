#!/usr/bin/env python3
import logging
import asyncio
import itertools
import os
import signal
import time
import requests
import ipaddress
import re
from urllib.parse import urlparse

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

MITM_PORT = 8443

# Path to mitmproxy's CA cert
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# EICAR test file bytes
EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# VirusTotal API keys (rotate through them)
VT_API_KEYS = [
    "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416",
    "b7b3510d6136926eb092d853ea0968ca0f0df2228fdb2e302e25ea113520aca0",
    "6e5281c4f459d5192fc42c9282ca94228c535e2329c2f3dda676cc61286cb91e",
    "16539b7c5e8140decd35a6110b00c5a794ee21f2bddb605e55e6c8c3e3ad6898",
    "0f53125a357dcffafb064976bfac2c47d3e20181720dc0d391ad7bf83608d319",
]
_key_cycle = itertools.cycle(VT_API_KEYS)

# Semaphores to limit concurrent VT API calls
file_scan_semaphore = asyncio.Semaphore(len(VT_API_KEYS))
domain_check_semaphore = asyncio.Semaphore(len(VT_API_KEYS))

# Cache for domain reputations
_domain_cache = {}
CACHE_TTL = 3600  # 1 hour
_cache_timestamps = {}

# Cache for file-scan results (by SHA256)
_file_cache = {}
_file_cache_timestamps = {}
FILE_CACHE_TTL = 3600  # 1 hour

# Whether to block malicious domains/files
BLOCK_MALICIOUS = True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")


def get_vt_api_key() -> str:
    """Round-robin selection of a VT API key."""
    return next(_key_cycle)


def is_private_or_localhost(hostname: str) -> bool:
    """
    Return True if `hostname` is 'localhost' or a private-network IP.
    Used to skip VT lookups on those.
    """
    hn = hostname.lower().split(":", 1)[0]
    if hn == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(hn)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


async def is_domain_malicious(domain: str) -> bool:
    """
    Asynchronously query VT domain endpoint; return True if malicious.
    Skip VT if domain is private or localhost.
    """
    if is_private_or_localhost(domain):
        return False

    domain_to_check = domain.split(":", 1)[0]
    now = time.time()
    if domain_to_check in _domain_cache:
        age = now - _cache_timestamps.get(domain_to_check, 0)
        if age < CACHE_TTL:
            return _domain_cache[domain_to_check]

    async with domain_check_semaphore:
        api_key = get_vt_api_key()
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/domains/{domain_to_check}"
        try:
            logger.info(f"[VT] Checking domain reputation: {domain_to_check} (key …{api_key[-6:]})")
            r = await asyncio.get_event_loop().run_in_executor(
                None, lambda: requests.get(url, headers=headers, timeout=10)
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) > 0
            _domain_cache[domain_to_check] = malicious
            _cache_timestamps[domain_to_check] = now
            logger.info(f"[VT] Domain {domain_to_check} → malicious={malicious}")
            return malicious
        except Exception as e:
            logger.warning(f"[VT] error checking domain {domain_to_check}: {e}")
            return False


async def is_file_malicious(content_bytes: bytes) -> bool:
    """
    Submit binary to VT's file-scan endpoint, poll until analysis,
    return True if VT flags it malicious. Uses SHA256 cache.
    """
    import hashlib

    sha256 = hashlib.sha256(content_bytes).hexdigest()
    now = time.time()
    if sha256 in _file_cache:
        age = now - _file_cache_timestamps.get(sha256, 0)
        if age < FILE_CACHE_TTL:
            return _file_cache[sha256]

    async with file_scan_semaphore:
        api_key = get_vt_api_key()
        headers = {"x-apikey": api_key}
        files = {"file": ("file", content_bytes)}

        # *** ADDITION: Log right before the upload to VT. ***
        logger.info(f"[VT] → Uploading file to VT (sha256={sha256[:10]}…, key …{api_key[-6:]})")
        try:
            upload_resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    files=files,
                    timeout=30
                )
            )
            upload_resp.raise_for_status()
            analysis_id = upload_resp.json()["data"]["id"]
            logger.info(f"[VT] ← Upload succeeded, analysis_id={analysis_id}")
        except Exception as e:
            logger.warning(f"[VT] file upload error: {e}")
            _file_cache[sha256] = False
            _file_cache_timestamps[sha256] = now
            return False

    vt_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        try:
            logger.info(f"[VT] Polling for {analysis_id} …")
            # Sleep briefly before polling
            await asyncio.sleep(2)

            headers = {"x-apikey": api_key}
            r = await asyncio.get_event_loop().run_in_executor(
                None, lambda: requests.get(vt_url, headers=headers, timeout=10)
            )
            r.raise_for_status()
            j = r.json()
            status = j.get("data", {}).get("attributes", {}).get("status")
            if status == "queued":
                # Still in VT queue; keep waiting
                continue
            if status == "completed":
                stats = j.get("data", {}).get("attributes", {}).get("stats", {})
                malicious = stats.get("malicious", 0) > 0
                logger.info(f"[VT] File {analysis_id} analysis done → malicious={malicious}")
                _file_cache[sha256] = malicious
                _file_cache_timestamps[sha256] = now
                return malicious
            else:
                logger.warning(f"[VT] Unexpected file analysis status '{status}' for {analysis_id}")
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
        Handle EICAR, then perform domain reputation checks.
        """
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # 1) If the client asked for http://eicar.invalid/eicar.com, serve EICAR
        if url.lower() == "http://eicar.invalid/eicar.com":
            flow.response = http.Response.make(
                200,
                EICAR_BYTES,
                {
                    "Content-Type": "application/octet-stream",
                    "Content-Disposition": "attachment; filename=eicar.com",
                },
            )
            return

        # 2) Skip domain check for .ico files
        parsed = urlparse(url)
        path = parsed.path.lower()
        if path.endswith(".ico"):
            return

        # 3) Serve the Mitmproxy CA if requested
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

        # 4) Domain reputation check (async)
        domain = parsed.netloc.lower()
        malicious_domain = await is_domain_malicious(domain)
        if BLOCK_MALICIOUS and malicious_domain:
            flow.response = http.Response.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked by VT domain reputation</p>",
                {"Content-Type": "text/html"},
            )
            return

        # 5) (Optional) Inspect POST payloads for SQLi etc.

    async def response(self, flow: http.HTTPFlow):
        """
        Called on every server → proxy → client response.
        Check CSS, JS, and binaries.
        """
        if flow.response is None:
            return

        url = flow.request.pretty_url
        logger.info(f"[RESPONSE] {url}")

        path = urlparse(url).path.lower()

        # Skip tiny static assets: .ico, .svg, .woff, .woff2, .ttf, .png, .jpg, .gif
        skip_exts = (".ico", ".svg", ".woff", ".woff2", ".ttf", ".png", ".jpg", ".jpeg", ".gif")
        if path.endswith(skip_exts):
            return

        # --- LOOSENED CSS heuristics: no automatic 403 for size/expressions/data:URL ---
        if path.endswith(".css"):
            # Just log the fact that we saw a CSS file; do not block by default
            logger.info(f"[CSS] Allowing CSS asset through: {path}")
            return

        # --- LOOSENED JS heuristics: no automatic 403 for URLs/size/eval(atob) ---
        if path.endswith(".js"):
            logger.info(f"[JS] Allowing JS asset through: {path}")
            return

        # Binary files: PDF, ZIP, EXE, etc. → full VT file scan
        ctype = flow.response.headers.get("Content-Type", "").lower()
        binary_types = [
            "application/octet-stream",
            "application/pdf",
            "application/zip",
            "application/x-msdownload",
            "application/vnd.microsoft.portable-executable",
        ]
        if any(bt in ctype for bt in binary_types):
            raw_data = flow.response.raw_content
            try:
                # Log that we’re about to scan this file
                logger.info(f"[VT] Scanning binary payload from {url} (Content-Type={ctype})")
                malicious_file = await is_file_malicious(raw_data)
            except Exception as e:
                logger.warning(f"[RESPONSE] file scanning error: {e}")
                malicious_file = False

            if BLOCK_MALICIOUS and malicious_file:
                flow.response = http.Response.make(
                    403,
                    b"<h1>403 Forbidden</h1><p>Blocked malicious file download</p>",
                    {"Content-Type": "text/html"},
                )
                return

        # HTML pages: you could scan inline scripts or references, but skip for brevity
        # Everything else passes through


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
