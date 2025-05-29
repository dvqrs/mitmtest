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
from collections import defaultdict
import threading
from typing import Optional, Set

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

# Performance settings
VT_TIMEOUT = 5  # Reduced from 15 seconds
VT_POLL_ATTEMPTS = 3  # Reduced from 10 attempts
VT_POLL_INTERVAL = 2  # Reduced from 5 seconds
BACKGROUND_SCAN_DELAY = 0.1  # Allow request to proceed immediately
DOMAIN_WHITELIST_TIME = 300  # Cache clean domains for 5 minutes

# Round-robin iterator for keys and semaphore to limit concurrency
_key_cycle = itertools.cycle(VT_API_KEYS)
scan_semaphore = asyncio.Semaphore(len(VT_API_KEYS) * 2)  # Increased concurrency

# Enhanced caching with timestamps
_domain_cache = {}  # domain -> (is_malicious, timestamp)
_pending_scans = set()  # domains currently being scanned
_background_tasks = set()  # track background tasks

BLOCK_MALICIOUS = True
CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy")


def get_vt_api_key() -> str:
    return next(_key_cycle)


def normalize_domain(url: str) -> str:
    """Extract normalized domain from URL (removes http/https distinction)"""
    parsed = urlparse(url)
    return parsed.netloc.lower()


def is_cache_valid(domain: str) -> bool:
    """Check if cached result is still valid"""
    if domain not in _domain_cache:
        return False
    
    is_malicious, timestamp = _domain_cache[domain]
    age = time.time() - timestamp
    
    # Cache malicious domains longer, clean domains shorter
    max_age = 3600 if is_malicious else DOMAIN_WHITELIST_TIME
    return age < max_age


def sync_scan_domain(domain: str) -> bool:
    """Fast VT submit-and-poll for a domain with reduced timeouts"""
    api_key = get_vt_api_key()
    headers = {"x-apikey": api_key}
    
    # First try to get existing analysis
    domain_id = base64.urlsafe_b64encode(f"http://{domain}".encode()).decode().strip("=")
    
    logger.info(f"[VT] Checking existing analysis for {domain}")
    try:
        get_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{domain_id}",
            headers=headers,
            timeout=VT_TIMEOUT
        )
        if get_resp.status_code == 200:
            data = get_resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            if stats:
                malicious = stats.get("malicious", 0) > 0
                logger.info(f"[VT] Found existing analysis for {domain}: malicious={malicious}")
                return malicious
    except Exception as e:
        logger.debug(f"[VT] No existing analysis for {domain}: {e}")
    
    # Submit new analysis with reduced timeout
    logger.info(f"[VT] Submitting new analysis for {domain}")
    try:
        post = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": f"http://{domain}"},
            timeout=VT_TIMEOUT
        )
    except Exception as e:
        logger.warning(f"[!] VT POST error for {domain}: {e}")
        return False
        
    if post.status_code != 200:
        logger.warning(f"[!] VT POST failed {post.status_code} for {domain}")
        return False
        
    analysis_id = post.json().get("data", {}).get("id")
    if not analysis_id:
        return False

    # Quick polling with reduced attempts
    for attempt in range(VT_POLL_ATTEMPTS):
        try:
            get = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=VT_TIMEOUT
            )
        except Exception as e:
            logger.warning(f"[!] VT GET error for {domain} (attempt {attempt + 1}): {e}")
            break
            
        if get.status_code == 200:
            attrs = get.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                malicious = stats.get("malicious", 0) > 0
                logger.info(f"[VT] Quick analysis for {domain} completed: malicious={malicious}")
                return malicious
        else:
            logger.warning(f"[!] VT GET failed {get.status_code} for {domain}")
            break
            
        if attempt < VT_POLL_ATTEMPTS - 1:
            time.sleep(VT_POLL_INTERVAL)

    logger.info(f"[VT] Quick scan timeout for {domain}, assuming safe")
    return False  # Assume safe if we can't get quick results


async def background_scan_domain(domain: str):
    """Background scan that doesn't block the request"""
    try:
        async with scan_semaphore:
            result = await asyncio.get_event_loop().run_in_executor(None, sync_scan_domain, domain)
        
        # Cache the result
        _domain_cache[domain] = (result, time.time())
        _pending_scans.discard(domain)
        
        if result:
            logger.warning(f"[!] MALICIOUS domain detected in background: {domain}")
        else:
            logger.info(f"[VT] Background scan completed - {domain} is clean")
            
    except Exception as e:
        logger.error(f"[!] Background scan error for {domain}: {e}")
        _pending_scans.discard(domain)


async def check_domain_safety(domain: str) -> Optional[bool]:
    """
    Check if domain is safe. Returns:
    - True if definitely malicious (block immediately)
    - False if definitely safe
    - None if unknown (allow but scan in background)
    """
    # Check cache first
    if is_cache_valid(domain):
        is_malicious, _ = _domain_cache[domain]
        return is_malicious
    
    # If already scanning in background, allow request
    if domain in _pending_scans:
        return None
    
    # Start background scan
    _pending_scans.add(domain)
    task = asyncio.create_task(background_scan_domain(domain))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    
    # For first-time domains, do a very quick check
    # This adds minimal delay but catches obvious threats
    try:
        # Quick reputation check using domain URL endpoint with very short timeout
        api_key = get_vt_api_key()
        domain_id = base64.urlsafe_b64encode(f"http://{domain}".encode()).decode().strip("=")
        
        async with scan_semaphore:
            def quick_check():
                try:
                    resp = requests.get(
                        f"https://www.virustotal.com/api/v3/urls/{domain_id}",
                        headers={"x-apikey": api_key},
                        timeout=2  # Very short timeout
                    )
                    if resp.status_code == 200:
                        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        return stats.get("malicious", 0) > 5  # Only block if many engines flag it
                except:
                    pass
                return False
            
            # Quick check with 2s timeout total
            try:
                is_malicious = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(None, quick_check),
                    timeout=2.0
                )
                if is_malicious:
                    _domain_cache[domain] = (True, time.time())
                    _pending_scans.discard(domain)
                    return True
            except asyncio.TimeoutError:
                pass
                
    except Exception as e:
        logger.debug(f"[VT] Quick check failed for {domain}: {e}")
    
    return None  # Allow request, background scan will update cache


class AllInOne:
    async def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        logger.info(f"[REQUEST] {url}")

        # Serve CA cert
        if flow.request.path == "/mitmproxy-ca-cert.pem":
            if not os.path.isfile(CA_PATH):
                flow.response = http.Response.make(404, b"CA not found", {"Content-Type": "text/plain"})
                return
            with open(CA_PATH, "rb") as f:
                cert = f.read()
            flow.response = http.Response.make(
                200,
                cert,
                {"Content-Type": "application/x-pem-file", "Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"}
            )
            return

        # Only scan top-level HTML GET requests
        if (BLOCK_MALICIOUS and 
            flow.request.method == "GET" and 
            "text/html" in flow.request.headers.get("Accept", "")):
            
            domain = normalize_domain(url)
            safety_result = await check_domain_safety(domain)
            
            if safety_result is True:  # Definitely malicious
                logger.warning(f"[!] BLOCKING malicious domain: {domain}")
                flow.response = http.Response.make(
                    403,
                    b"<h1>403 Forbidden</h1><p>This domain has been blocked due to security concerns detected by VirusTotal.</p>",
                    {"Content-Type": "text/html"}
                )
            # If safety_result is False (safe) or None (unknown), allow the request

    def response(self, flow: http.HTTPFlow):
        pass


async def cleanup_background_tasks():
    """Clean up completed background tasks periodically"""
    while True:
        await asyncio.sleep(60)  # Clean up every minute
        completed_tasks = [task for task in _background_tasks if task.done()]
        for task in completed_tasks:
            _background_tasks.discard(task)
        
        # Clean old cache entries
        current_time = time.time()
        expired_domains = []
        for domain, (is_malicious, timestamp) in _domain_cache.items():
            max_age = 3600 if is_malicious else DOMAIN_WHITELIST_TIME
            if current_time - timestamp > max_age:
                expired_domains.append(domain)
        
        for domain in expired_domains:
            del _domain_cache[domain]
            
        if expired_domains:
            logger.info(f"[CACHE] Cleaned {len(expired_domains)} expired entries")


async def run_proxy():
    loop = asyncio.get_running_loop()
    
    # Start background cleanup task
    cleanup_task = asyncio.create_task(cleanup_background_tasks())
    
    opts = Options(listen_host="0.0.0.0", listen_port=MITM_PORT, ssl_insecure=True)
    m = DumpMaster(opts)
    m.addons.add(AllInOne())
    
    def shutdown_handler():
        logger.info("[*] Shutting down...")
        cleanup_task.cancel()
        asyncio.create_task(m.shutdown())
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_handler)
        
    logger.info(f"[*] mitmproxy running on port {MITM_PORT} with optimized VT scanning...")
    logger.info(f"[*] VT timeout: {VT_TIMEOUT}s, Poll attempts: {VT_POLL_ATTEMPTS}, Background delay: {BACKGROUND_SCAN_DELAY}s")
    
    try:
        await m.run()
    finally:
        cleanup_task.cancel()


if __name__ == "__main__":
    asyncio.run(run_proxy())
