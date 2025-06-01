import logging
import asyncio
import itertools
import os
import signal
import time
import requests
import ipaddress
import re
import hashlib
import io
import zipfile
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

# Cache for file‐scan results (by SHA256)
_file_cache = {}
_file_cache_timestamps = {}
FILE_CACHE_TTL = 3600  # 1 hour

# Whether to block malicious domains/files
BLOCK_MALICIOUS = True

# ──────────────────────────────────────────────────────────────────────────────
# NEW: Domains to ignore for EICAR downloads (skip any VT scanning on these)
IGNORED_FILE_DOMAINS = [
    "eicar.org",        # canonical EICAR test site
    # add additional hosts here, e.g. "mmg.whatsapp.net"
]
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")


def get_vt_api_key() -> str:
    """Round‐robin selection of a VT API key."""
    return next(_key_cycle)


def is_private_or_localhost(hostname: str) -> bool:
    """
    Return True if `hostname` is 'localhost' or a private‐network IP.
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
    1) Compute SHA256 of content_bytes.
    2) If cached and not expired, return cached value.
    3) Try GET /api/v3/files/{sha256}.
       • If VT knows it, read last_analysis_stats.malicious.
       • Otherwise, do POST /api/v3/files & poll /api/v3/analyses/{id}.
    4) Cache result and return.
    """
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    now = time.time()

    # Log the hash for debugging
    logger.info(f"[DEBUG] Computed SHA256: {sha256}")

    # 1) Check local cache
    if sha256 in _file_cache:
        age = now - _file_cache_timestamps.get(sha256, 0)
        if age < FILE_CACHE_TTL:
            logger.info(f"[VT] Cache hit for {sha256[:10]}… → malicious={_file_cache[sha256]}")
            return _file_cache[sha256]

    # 2) Acquire semaphore so we don’t exceed VT_API_KEYS rate
    async with file_scan_semaphore:
        api_key = get_vt_api_key()
        headers = {"x-apikey": api_key}

        # 3a) First try: query VT’s /files/{sha256} endpoint
        file_info_url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        try:
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: requests.get(file_info_url, headers=headers, timeout=10)
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                stats = data.get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0) > 0

                _file_cache[sha256] = malicious
                _file_cache_timestamps[sha256] = now

                logger.info(f"[VT] Existing hash lookup: {sha256[:10]}… → malicious={malicious}")
                return malicious

            if resp.status_code != 404:
                # Some other error (rate limit? 403?), treat as “not malicious”
                logger.warning(f"[VT] Unexpected status {resp.status_code} querying {file_info_url}")
                _file_cache[sha256] = False
                _file_cache_timestamps[sha256] = now
                return False

        except Exception as e:
            logger.warning(f"[VT] Error querying file endpoint: {e}")
            _file_cache[sha256] = False
            _file_cache_timestamps[sha256] = now
            return False

        # 3b) If VT never saw the file (404), upload it
        files = {"file": ("file", content_bytes)}
        upload_url = "https://www.virustotal.com/api/v3/files"
        try:
            logger.info(f"[VT] → Uploading file to VT (sha256={sha256[:10]}…, key …{api_key[-6:]})")
            upload_resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: requests.post(upload_url, headers=headers, files=files, timeout=30)
            )
            upload_resp.raise_for_status()
            analysis_id = upload_resp.json()["data"]["id"]
            logger.info(f"[VT] Upload succeeded, analysis_id={analysis_id}")
        except Exception as e:
            logger.warning(f"[VT] File upload error: {e}")
            _file_cache[sha256] = False
            _file_cache_timestamps[sha256] = now
            return False

        # 4) Poll the analysis endpoint until “completed”
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        while True:
            try:
                await asyncio.sleep(2)
                resp2 = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: requests.get(analysis_url, headers=headers, timeout=10)
                )
                resp2.raise_for_status()
                j = resp2.json()
                status = j.get("data", {}).get("attributes", {}).get("status")
                if status == "queued":
                    continue
                if status == "completed":
                    stats = j.get("data", {}).get("attributes", {}).get("stats", {})
                    malicious = stats.get("malicious", 0) > 0
                    logger.info(f"[VT] Analysis done (id={analysis_id}) → malicious={malicious}")

                    _file_cache[sha256] = malicious
                    _file_cache_timestamps[sha256] = now
                    return malicious

                # Unexpected status (e.g., “timeout”)
                logger.warning(f"[VT] Unexpected analysis status '{status}' for {analysis_id}")
                _file_cache[sha256] = False
                _file_cache_timestamps[sha256] = now
                return False

            except Exception as e:
                logger.warning(f"[VT] Error polling file analysis: {e}")
                _file_cache[sha256] = False
                _file_cache_timestamps[sha256] = now
                return False


class AllInOne:
    async def request(self, flow: http.HTTPFlow):
        """
        Called on every client → proxy → server request.
        1) Serve the Mitmproxy CA if requested.
        2) Domain reputation check.
        """
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # 1) Serve the Mitmproxy CA if requested
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

        # 2) Domain reputation check (async)
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
        """
        Called on every server → proxy → client response.
        Enhanced with:
          - Small response skipping
          - File download pattern detection (including .com)
          - Extended binary detection
          - GZIP‐decompression for wrapper flows
          - Skip VT scanning if the response’s domain is in IGNORED_FILE_DOMAINS
          - In‐memory ZIP detection & unwrapping
          - File‐scan with VT “query‐then‐upload”
        """
        if flow.response is None:
            return

        url = flow.request.pretty_url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        logger.info(f"[RESPONSE] {url}")

        # Skip CA certificate serving
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            return

        # Skip small responses (<50 bytes)
        if len(flow.response.raw_content) < 50:
            return

        # If this domain is in the ignore list, skip file scanning entirely:
        if domain in IGNORED_FILE_DOMAINS:
            logger.info(f"[BYPASS] Skipping VT scan for domain: {domain}")
            return

        # Log first 64 bytes and headers for debugging
        sample = flow.response.raw_content[:64]
        logger.info(f"[DEBUG] First 64 bytes of content: {sample!r}")
        logger.info(f"[DEBUG] Content-Type: {flow.response.headers.get('Content-Type')}")
        logger.info(f"[DEBUG] Content-Disposition: {flow.response.headers.get('Content-Disposition')}")

        # If the response is GZIP‐wrapped (protobuf, JSON, etc.), decompress before scanning:
        raw = flow.response.raw_content
        if raw[:3] == b"\x1f\x8b\x08":
            try:
                import gzip
                decompressed = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                raw = decompressed
                logger.info("[DEBUG] Decompressed GZIP wrapper")
            except Exception:
                # If decompression fails, just continue scanning the original raw bytes
                pass

        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        content_disp = flow.response.headers.get("Content-Disposition", "").lower()

        # 1. File download patterns (now including .com)
        is_download = any([
            "attachment" in content_disp,
            "download" in query,
            re.search(r'\.(exe|dll|zip|rar|pdf|docx?|xlsx?|pptx?|jar|com)$', path),
            "mms-type" in query
        ])

        # 2. Extended binary detection
        ctype = flow.response.headers.get("Content-Type", "").lower()
        is_binary = any(term in ctype for term in [
            "octet-stream", "pdf", "zip",
            "x-msdownload", "vnd.microsoft.portable-executable",
            "video", "image"
        ])

        # 3. If it looks like a file, handle potential ZIP wrapper and scan
        if is_download or is_binary:
            # Detect ZIP magic header (PK\x03\x04)
            if raw[:4] == b"PK\x03\x04":
                try:
                    z = zipfile.ZipFile(io.BytesIO(raw))
                    # Assume the first entry is our file (e.g., eicar.com)
                    inner_name = z.namelist()[0]
                    inner_bytes = z.read(inner_name)
                    inner_sha256 = hashlib.sha256(inner_bytes).hexdigest()
                    logger.info(f"[DEBUG] Unzipped '{inner_name}', inner SHA256: {inner_sha256}")
                    malicious = await is_file_malicious(inner_bytes)
                except Exception as exc:
                    logger.warning(f"[DEBUG] Failed to unzip; scanning raw instead: {exc}")
                    malicious = await is_file_malicious(raw)
            else:
                # Not a ZIP—scan the raw (possibly decompressed) bytes directly
                malicious = await is_file_malicious(raw)

            # If VT flags it malicious, block the response
            if malicious:
                logger.warning(f"[BLOCK] Malicious file blocked: {url}")
                flow.response = http.Response.make(
                    403,
                    b"<h1>403 Forbidden</h1><p>Blocked malicious file download</p>",
                    {"Content-Type": "text/html"},
                )


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

