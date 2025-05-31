# ... (other imports and code remain unchanged)

TRUSTED_DOMAINS = (
    "whatsapp.com",
    "whatsapp.net",
    "google.com",
    "gstatic.com",
)

# Inside the response method:
async def response(self, flow: http.HTTPFlow):
    if flow.response is None:
        return

    parsed = urlparse(flow.request.pretty_url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # ────────────── Trusted UI asset filter ──────────────
    # Let WhatsApp and other known UIs send normal assets, but scan risky files
    if domain.endswith("whatsapp.com") or domain.endswith("whatsapp.net"):
        # Let emoji, CSS, scripts, images through unscanned
        if path.endswith((".css", ".js", ".svg", ".woff", ".woff2", ".webp", ".png", ".jpg", ".jpeg", ".gif", ".ico")):
            return

    if domain.endswith("google.com") or domain.endswith("gstatic.com"):
        if path.endswith((".css", ".js", ".woff", ".woff2", ".png", ".svg", ".ico")):
            return

    # Continue with file scanning logic... (this part of your original code follows)

    # Skip tiny static assets
    skip_exts = (".ico", ".svg", ".woff", ".woff2", ".ttf", ".png", ".jpg", ".jpeg", ".gif", ".webp")
    if path.endswith(skip_exts):
        return

    # CSS files: heuristic scan
    if path.endswith(".css"):
        text = flow.response.get_text(strict=False)
        if len(text) > 100 * 1024 or "url(data:" in text or "expression(" in text:
            flow.response = http.Response.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked suspicious CSS</p>",
                {"Content-Type": "text/html"},
            )
        return

    # JS files: check for obfuscation or suspicious constructs
    if path.endswith(".js"):
        text = flow.response.get_text(strict=False)
        if "eval(atob" in text or re.search(r'https?://[^"\s]+', text) or len(text) > 500 * 1024:
            flow.response = http.Response.make(
                403,
                b"<h1>403 Forbidden</h1><p>Blocked suspicious JavaScript</p>",
                {"Content-Type": "text/html"},
            )
        return

    # Binary files: file scan
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
