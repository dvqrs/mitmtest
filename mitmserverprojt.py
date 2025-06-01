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
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
VT_API_KEYS = [
    "0d47d2a03a43518344efd52726514f3b9dacc3e190742ee52eae89e6494dc416",
    "b7b3510d6136926eb092d853ea0968ca0f0df2228fdb2e302e25ea113520aca0",
    "6e5281c4f459d5192fc42c9282ca94228c535e2329c2f3dda676cc61286cb91e",
    "16539b7c5e8140decd35a6110b00c5a794ee21f2bddb605e55e6c8c3e3ad6898",
    "0f53125a357dcffafb064976bfac2c47d3e20181720dc0d391ad7bf83608d319",
]
_key_cycle = itertools.cycle(VT_API_KEYS)

# Semaphores and caching
file_scan_semaphore = asyncio.Semaphore(len(VT_API_KEYS))
domain_check_semaphore = asyncio.Semaphore(len(VT_API_KEYS))
_domain_cache = {}
_file_cache = {}
_cache_timestamps = {}
_file_cache_timestamps = {}
CACHE_TTL = 3600
FILE_CACHE_TTL = 3600
BLOCK_MALICIOUS = True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = re.compile(
    r'\.(exe|dll|zip|rar|pdf|docx?|xlsx?|pptx?|jar|com|bat|cmd|scr|msi|ps1|apk|deb|rpm)$',
    re.IGNORECASE
)

# Safe content types (won't scan)
SAFE_CONTENT_TYPES = [
    "text/html",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/json",
    "application/xml",
    "image/",
    "video/",
    "audio/"
]

# ──────────────────────────────────────────────────────────────────────────────
# Core Functions
# ──────────────────────────────────────────────────────────────────────────────

def get_vt_api_key() -> str:
    return next(_key_cycle)

def is_private_or_localhost(hostname: str) -> bool:
    hn = hostname.lower().split(":", 1)[0]
    if hn == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(hn)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

async def is_domain_malicious(domain: str) -> bool:
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
            await asyncio.sleep(2)

            headers = {"x-apikey": api_key}
            r = await asyncio.get_event_loop().run_in_executor(
                None, lambda: requests.get(vt_url, headers=headers, timeout=10)
            )
            r.raise_for_status()
            j = r.json()
            status = j.get("data", {}).get("attributes", {}).get("status")
            if status == "queued":
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

# ──────────────────────────────────────────────────────────────────────────────
# Proxy Handler
# ──────────────────────────────────────────────────────────────────────────────

class AllInOne:
    async def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Serve MITM certificate
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(404, b"CA not found", {"Content-Type": "text/plain"})
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

        # Domain reputation check
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        malicious_domain = await is_domain_malicious(domain)
        if BLOCK_MALICIOUS and malicious_domain:
            flow.response = http.Response.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked by VT domain reputation</p>",
                {"Content-Type": "text/html"},
            )
            return

    async def response(self, flow: http.HTTPFlow):
        if flow.response is None:
            return

        url = flow.request.pretty_url
        logger.info(f"[RESPONSE] {url}")

        # Skip CA certificate serving
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            return

        content = flow.response.raw_content
        content_length = len(content)
        
        # Skip empty or very large responses (>10MB)
        if content_length == 0 or content_length > 10 * 1024 * 1024:
            return

        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query.lower()
        content_disp = flow.response.headers.get("Content-Disposition", "")
        ctype = flow.response.headers.get("Content-Type", "").lower()

        # 1. Check if safe content type
        is_safe_type = any(
            ctype.startswith(safe_type) for safe_type in SAFE_CONTENT_TYPES
        )
        
        # 2. File download detection
        is_download = False
        
        # Content-Disposition checks
        if "attachment" in content_disp.lower():
            is_download = True
        else:
            # Extract filename from Content-Disposition
            filename_match = re.search(r'filename\s*=\s*"([^"]+)"', content_disp, re.IGNORECASE)
            if filename_match:
                filename = filename_match.group(1)
                if SUSPICIOUS_EXTENSIONS.search(filename):
                    is_download = True
        
        # URL path checks
        if not is_download:
            if SUSPICIOUS_EXTENSIONS.search(path):
                is_download = True
            elif "download" in query or "mms-type" in query:
                is_download = True

        # 3. Binary content detection
        is_binary = any(term in ctype for term in [
            "octet-stream", "pdf", "zip", "x-msdownload", 
            "vnd.microsoft.portable-executable"
        ])

        # Scan conditions
        should_scan = (
            (is_download or is_binary) and 
            not is_safe_type and
            content_length >= 50  # Minimum file size
        )

        if should_scan:
            logger.info(f"Scanning file: {url} | Type: {ctype} | Size: {content_length} bytes")
            try:
                malicious = await is_file_malicious(content)
                if malicious:
                    logger.warning(f"Blocking malicious file: {url}")
                    flow.response = http.Response.make(
                        403,
                        b"<h1>403 Forbidden</h1><p>Blocked malicious file download</p>",
                        {"Content-Type": "text/html"},
                    )
            except Exception as e:
                logger.error(f"File scan failed: {str(e)}")

# ──────────────────────────────────────────────────────────────────────────────
# Main Execution
# ──────────────────────────────────────────────────────────────────────────────

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
