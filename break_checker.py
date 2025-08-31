"""BreakChecker: domain crawler, contact extractor and breach checker.

Overview
--------
BreakChecker scans a target domain in well-defined stages to discover
subdomains, crawl accessible web pages, extract emails and phone numbers,
and then check these contacts against breach sources (HIBP and LeakCheck).

Execution Stages
----------------
1) Subdomain Enumeration: Uses ``subfinder`` when available, with fallbacks
   to crt.sh, HackerTarget, and Anubis DB.
2) Accessibility Probe: Asynchronously tests each host for HTTP/HTTPS reachability.
3) Crawl & Render: A focused, in-domain crawler renders pages with Playwright,
   following page links and script sources up to a configurable depth.
4) Extraction & Normalization: Emails and phones are discovered from HTML and
   visible text, validated and normalized, and attributed to source URLs.
5) Breach Checks: Emails are looked up via a HaveIBeenPwned proxy; phone numbers
   via LeakCheck.
6) Reporting: Results are summarized and saved to JSON, CSV, or Markdown.

Configuration
-------------
Settings are loaded from ``config.json`` if present, otherwise from environment
variables. Recognized keys/env vars:

- ``hibp_api_key`` / ``HIBP_API_KEY``: HIBP proxy API key
- ``leakcheck_api_key`` / ``LEAKCHECK_API_KEY``: LeakCheck API key
- ``crawl_depth`` / ``CRAWL_DEPTH``: Maximum crawl depth

CLI Usage
---------
    python3 break_checker.py [options] domain

Options:
- ``-d``, ``--depth``: Maximum crawl depth
- ``-v``, ``--verbose``: Enable debug logging
- ``-j``, ``--json``: Save results as DOMAIN-TIMESTAMP.json (default)
- ``--csv``: Save results as DOMAIN-TIMESTAMP.csv
- ``--md``, ``--report``: Save results as DOMAIN-TIMESTAMP.md
- ``-c``, ``--concurrency``: Number of concurrent workers
"""

import os
import re
import sys
import json
import argparse
import asyncio
import logging
from logging.handlers import RotatingFileHandler
import time
from urllib.parse import (
    urljoin,
    urlparse,
    parse_qs,
    parse_qsl,
    unquote,
    urlencode,
    urlunparse,
    urldefrag,
)
from collections import deque, defaultdict
import datetime
import phonenumbers
import requests
from bs4 import BeautifulSoup
import shutil
import subprocess
from typing import Set, List, Optional, Dict, Tuple
import aiohttp
from playwright.async_api import async_playwright, Error as PWError
from email_validator import validate_email, EmailNotValidError
import socket
import errno
import ssl
import tldextract
import html
import unicodedata


# ---------------------- Logging ----------------------


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure logging sinks and return this module's logger.

    Args:
        level: The log level for the root logger (e.g., ``logging.INFO``).

    Returns:
        A logger scoped to this module. Logs are written to stdout/stderr and
        to a rotating file ``break_checker.log`` (configurable via
        ``BREACH_LOG_FILE``).
    """
    log_file = os.environ.get("BREACH_LOG_FILE", "break_checker.log")
    root_logger = logging.getLogger()

    if getattr(configure_logging, "_configured", False):
        root_logger.setLevel(level)
        return logging.getLogger(__name__)

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10_000_000,
        backupCount=10,
        encoding="utf-8",
        delay=True,
    )

    def namer(default_name):
        base, ext = os.path.splitext(log_file)
        parts = default_name.split(".")
        if parts[-1].isdigit():
            return f"{base}_{parts[-1]}{ext}"
        return default_name

    file_handler.namer = namer
    file_handler.setFormatter(formatter)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    root_logger.addHandler(file_handler)
    root_logger.addHandler(stream_handler)
    root_logger.setLevel(level)

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    configure_logging._configured = True
    return logging.getLogger(__name__)


logger = configure_logging()


 


# ---------------------- Config & domain validation ----------------------


def load_config() -> dict:
    """Load optional API keys and settings from ``config.json``.

    Returns:
        A dictionary like ``{"hibp_api_key": str|None, "leakcheck_api_key": str|None, "crawl_depth": int}``.
    """
    config = {"hibp_api_key": None,
              "leakcheck_api_key": None, "crawl_depth": 3}
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                config.update({k: v for k, v in data.items() if v})
            logger.debug("Loaded configuration from config.json")
    except Exception as exc:
        logger.debug("Could not load config.json: %s", exc)
    return config


def validate_domain(user_input: str, *, check_dns: bool = True) -> Tuple[bool, str, str]:
    """Validate and sanitize a domain suitable for scanning.

    Args:
        user_input: Raw domain or URL-like string (``example.com`` or ``https://example.com``).
        check_dns: When ``True``, require the hostname to resolve via DNS.

    Returns:
        Tuple ``(ok, domain_ascii, message)`` where:
        - ``ok`` is ``True`` when the domain is valid (and resolvable if requested).
        - ``domain_ascii`` contains the ASCII/IDNA domain without scheme, port, or www.
        - ``message`` is a human-readable validation message.
    """
    if not user_input or not user_input.strip():
        return False, "", "No domain provided"

    raw = user_input.strip()
    parsed = urlparse(raw if "//" in raw else f"//{raw}")
    host = parsed.netloc or parsed.path

    if host.lower().startswith("www."):
        host = host[4:]
    if ":" in host:
        host = host.split(":", 1)[0]
    host = host.strip(".").lower()
    if not host:
        return False, "", "No domain provided"

    try:
        host_ascii = host.encode("idna").decode("ascii")
    except Exception:
        return False, "", "Invalid internationalized domain"

    if len(host_ascii) > 253:
        return False, "", "Domain exceeds maximum length"

    labels = host_ascii.split(".")
    if len(labels) < 2 or len(labels[-1]) < 2:
        return False, "", "Domain must include a valid TLD"

    label_re = re.compile(
        r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$")
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False, "", "Domain label length invalid"
        if not label_re.fullmatch(label):
            return False, "", "Invalid domain format"

    if check_dns:
        try:
            socket.gethostbyname(host_ascii)
            return True, host_ascii, "Valid and resolvable"
        except Exception:
            return False, "", "Domain is not resolvable"

    return True, host_ascii, "Valid"


# ---------------------- Subdomain enumeration ----------------------


def enumerate_subdomains(domain: str) -> Set[str]:
    """Enumerate likely subdomains for a domain.

    Notes:
    - Prefer the local ``subfinder`` binary if available (fast, comprehensive).
    - Fallbacks: crt.sh, HackerTarget, and Anubis DB.
    - Wildcard entries like ``*.example.com`` are de-wildcarded and deduplicated.

    Args:
        domain: Apex domain to enumerate (e.g., ``example.com``).

    Returns:
        Set of lower-cased hostnames including the apex domain.
    """
    subs = set()

    if shutil.which("subfinder"):
        try:
            logger.debug("Running subfinder for %s", domain)
            result = subprocess.run(
                ["subfinder", "-silent", "-d", domain],
                capture_output=True, text=True, check=False, timeout=60
            )
            subs.update(line.strip()
                        for line in result.stdout.splitlines() if line.strip())
            logger.debug("subfinder returned %d subdomains", len(subs))
        except Exception as exc:
            logger.info("subfinder failed: %s", exc)

    if not subs:
        # crt.sh
        try:
            url = f"https://crt.sh/json?q={domain}"
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                for entry in resp.json():
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if "*" in sub:
                            sub = sub.lstrip("*.")  # drop wildcard marker
                        if sub and sub.endswith(domain):
                            subs.add(sub)
            else:
                logger.debug("crt.sh returned status %d.", resp.status_code)
        except Exception as exc:
            logger.debug("crt.sh lookup failed: %s", exc)

        # HackerTarget
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if "," in line:
                        subdomain = line.split(",")[0].strip().lower()
                        if subdomain.endswith(domain):
                            subs.add(subdomain)
            else:
                logger.debug("HackerTarget returned status %d.",
                             resp.status_code)
        except Exception as exc:
            logger.debug("HackerTarget lookup failed: %s", exc)

        # Anubis-DB
        try:
            url = f"https://anubisdb.com/anubis/subdomains/{domain}"
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                for subdomain in resp.json():
                    subdomain = subdomain.strip().lower()
                    if subdomain.endswith(domain):
                        subs.add(subdomain)
            else:
                logger.debug("Anubis-DB returned status %d.", resp.status_code)
        except Exception as exc:
            logger.debug("Anubis lookup failed: %s", exc)

    subs.add(domain)  # always include apex
    logger.info("Found %d subdomains for %s", len(subs), domain)
    return subs


# ---------------------- Liveness probing (IPv4, retry, HEAD→GET) ----------------------


async def _probe_once(session: aiohttp.ClientSession, method: str, url: str) -> bool:
    """Perform a single HTTP probe and report liveness.

    Sends one request with the given method to the URL using the provided
    ``aiohttp`` session. Any HTTP response with status < 400 is considered
    alive; network/protocol errors are treated as not alive.

    Args:
        session: Shared ``aiohttp`` client session.
        method: HTTP method to send (e.g., ``"HEAD"``, ``"GET"``).
        url: Absolute URL to request.

    Returns:
        True if a response is received with status < 400; otherwise False.
    """
    try:
        async with session.request(method, url, allow_redirects=True) as resp:
            # Only <400 counts as alive; 403/405/503 are treated as dead
            return resp.status < 400
    except Exception as exc:
        logger.debug("Probe error %s %s: %s", method, url, exc)
        return False


async def choose_scheme(session: aiohttp.ClientSession, host: str, *, retries: int = 2, per_try_delay: float = 0.35) -> Optional[str]:
    """Probe which scheme is reachable for a host.

    Tries ``https`` first, then ``http``. Uses an IPv4-only connector and
    performs a cheap ``HEAD`` followed by a ``GET`` if needed. Retries include
    a small backoff delay.

    Args:
        session: Shared aiohttp session.
        host: Hostname without scheme or path.
        retries: Additional attempts per scheme.
        per_try_delay: Base delay applied between attempts (seconds).

    Returns:
        "https" or "http" if the host responds (<400), otherwise None.
    """
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        for attempt in range(retries + 1):
            # Try HEAD first (cheap), then GET if needed
            if await _probe_once(session, "HEAD", base) or await _probe_once(session, "GET", base):
                logger.debug("%s is reachable via %s", host, scheme)
                return scheme
            await asyncio.sleep(per_try_delay * (attempt + 1))
    logger.debug("%s is not reachable via HTTP or HTTPS", host)
    return None


async def filter_accessible_subdomains(subdomains: Set[str], *, concurrency: int = 5, retries: int = 2) -> Dict[str, str]:
    """Filter discovered subdomains down to those with a live web endpoint.

    Args:
        subdomains: Candidate hostnames to probe.
        concurrency: Maximum concurrent probes.
        retries: Attempts per scheme in the chooser.

    Returns:
        Mapping of ``{host: scheme}`` for hosts that responded successfully.
    """
    live: Dict[str, str] = {}
    timeout = aiohttp.ClientTimeout(total=10)
    connector = aiohttp.TCPConnector(
        limit=concurrency, family=socket.AF_INET, ttl_dns_cache=120)
    hosts = sorted(list(subdomains))  # stabilize order

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = [choose_scheme(session, host, retries=retries)
                 for host in hosts]
        results = await asyncio.gather(*tasks)

    for host, scheme in zip(hosts, results):
        if scheme:
            live[host] = scheme
        else:
            logger.debug("Removing unreachable subdomain: %s", host)

    logger.info("Accessible subdomains: %d of %d", len(live), len(subdomains))
    return live


# ---------------------- Fetching (download-skip + Playwright fallback) ----------------------

# Global: non-HTML file extensions to skip during crawling
NON_HTML_EXTS = {
    "pdf", "zip", "gz", "bz2", "xz", "7z", "rar", "exe", "msi", "dmg", "iso",
    "png", "jpg", "jpeg", "gif", "svg", "bmp", "webp", "ico",
    "mp3", "mp4", "m4a", "aac", "wav", "flac", "ogg", "webm",
    "avi", "mov", "mkv",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
}

# Global: path substrings indicating likely file downloads
SKIP_PATH_KEYWORDS = (
    "/download/", "/downloads/", "/file/", "/files/", "/attachment/",
    "/attachments/", "/export/", "/exports/", "/wp-content/uploads/",
    "/media/", "/assets/", "/static/"
)


def should_skip_url_by_path(url: str) -> bool:
    """Determine if a URL likely targets a non-HTML asset.

    Args:
        url: Absolute or relative URL string.

    Returns:
        True if the path contains download-like segments or a known
        non-HTML file extension; otherwise False.
    """
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(k in path for k in SKIP_PATH_KEYWORDS):
        return True
    if "." in path:
        ext = path.rsplit(".", 1)[-1]
        return ext in NON_HTML_EXTS
    return False


def is_probably_html(content_type: str) -> bool:
    """Check whether an HTTP Content-Type denotes HTML.

    Args:
        content_type: The value of the ``Content-Type`` header.

    Returns:
        True for ``text/html`` or ``application/xhtml+xml`` (ignoring charset);
        otherwise False.
    """
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    return ct in ("text/html", "application/xhtml+xml")


async def get_stable_content(
    page,
    *,
    total_ms: int = 18000,
    idle_ms: int = 1500,
    hydrate_ms: int = 250,
    min_text_len: int = 80, 
) -> str | None:
    """
    Return 'good enough' HTML:
      1) Try immediately after DOMContentLoaded → early exit if it looks real.
      2) Brief hydration wait (React/Vue) → try again.
      3) One-time network-idle wait (SPA data fetch) → try again.
    All within a hard deadline. Returns None if the page never stabilizes.
    
    Args:
        page: Playwright page object to read from.
        total_ms: Total time budget in milliseconds.
        idle_ms: Timeout for ``networkidle`` wait in milliseconds.
        hydrate_ms: Short hydration pause in milliseconds before re-checking.
        min_text_len: Threshold for considering the page "good enough".

    Returns:
        HTML string if stabilization succeeded within the deadline; otherwise ``None``.
    """
    deadline = time.monotonic() + total_ms / 1000.0

    async def read_html() -> str | None:
        try:
            return await page.content()
        except PWError:
            return None

    async def text_len() -> int:
        try:
            return await page.evaluate(
                "document.body && document.body.innerText ? document.body.innerText.length : 0"
            )
        except PWError:
            return 0

    while time.monotonic() < deadline:
        try:
            # 1) Reach a minimally useful state fast
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=min(2000, int((deadline - time.monotonic())*1000)))
            except PWError:
                pass

            # Early exit: static pages shouldn't pay a hydration tax
            html = await read_html()
            if html and await text_len() >= min_text_len:
                return html

            # 2) Tiny hydration window for client-side frameworks
            await page.wait_for_timeout(min(hydrate_ms, max(0, int((deadline - time.monotonic())*1000))))
            html = await read_html()
            if html and await text_len() >= min_text_len:
                return html

            # 3) One-time SPA fetch/render window (don't loop on networkidle)
            try:
                await page.wait_for_load_state("networkidle", timeout=min(idle_ms, int((deadline - time.monotonic())*1000)))
            except PWError:
                pass
            html = await read_html()
            if html and await text_len() >= min_text_len:
                return html

            # If we’re here, we didn’t get meaningful content; brief pause and loop within budget
            await page.wait_for_timeout(min(200, max(0, int((deadline - time.monotonic())*1000))))

        except PWError:
            # Random flake; short nap and try again until the deadline
            await page.wait_for_timeout(min(200, max(0, int((deadline - time.monotonic())*1000))))

    return None




async def http_fallback(context, url: str, timeout: int = 60000) -> Optional[str]:
    """Fetch text via Playwright's context HTTP client.

    Args:
        context: A Playwright browser context.
        url: Absolute URL to fetch.
        timeout: Request timeout in milliseconds.

    Returns:
        Response body text if the request succeeds; otherwise ``None``.
    """
    try:
        r = await context.request.get(url, timeout=timeout)
        if r.ok:
            return await r.text()
    except Exception:
        pass
    return None


# Hosts that repeatedly refuse or fail connections are marked as dead to avoid
# wasting time re-trying them during a single run.
_DEAD_HOSTS: set[str] = set()
# Track per-host failure counts that trigger dead-host marking.
_DEAD_HOST_FAILS: Dict[str, int] = defaultdict(int)


def _classify_net_error(exc: Exception) -> str:
    """Summarize a network/client error into a compact label for logging.

    Args:
        exc: The raised exception from a network operation.

    Returns:
        A short label such as "refused", "dns", "tls", "timeout",
        "connect", or "other".
    """
    if isinstance(exc, aiohttp.ClientConnectorError):
        os_err = getattr(exc, "os_error", None)
        if isinstance(os_err, OSError):
            if os_err.errno == errno.ECONNREFUSED:
                return "refused"
            if os_err.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
                return "unreachable"
            if os_err.errno in (errno.ECONNRESET,):
                return "reset"
        return "connect"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, asyncio.TimeoutError) or "TimeoutError" in exc.__class__.__name__:
        return "timeout"
    msg = str(exc)
    if "ERR_CONNECTION_REFUSED" in msg or "ECONNREFUSED" in msg:
        return "refused"
    if "ERR_NAME_NOT_RESOLVED" in msg:
        return "dns"
    if "ERR_TIMED_OUT" in msg:
        return "timeout"
    return "other"


# ---------- Persistent Playwright (single global context) ----------
# Shared Playwright engine objects, initialized on demand and reused across pages:
# - _PW: Playwright runtime instance
# - _PW_BROWSER: headless Chromium browser
# - _PW_CTX: shared browser context (assets like images/media/fonts are blocked)
_PW = None
_PW_BROWSER = None
_PW_CTX = None


async def _ensure_pw_started():
    """Start Playwright once and create a shared global context.

    Returns:
        None. Initializes module-level ``_PW``, ``_PW_BROWSER``, and ``_PW_CTX``.
    """
    global _PW, _PW_BROWSER, _PW_CTX
    if _PW is not None:
        return
    _PW = await async_playwright().start()
    _PW_BROWSER = await _PW.chromium.launch(headless=True)
    _PW_CTX = await _PW_BROWSER.new_context(
        ignore_https_errors=True,
        bypass_csp=True,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36",
        locale="en-US",
        timezone_id="UTC",
    )
    # Block heavy assets globally to keep renders fast and quiet
    await _PW_CTX.route("**/*", lambda route: (
        route.abort() if route.request.resource_type in {"image", "media", "font"}
        else route.continue_()
    ))


async def _shutdown_pw():
    """Cleanly close the shared Playwright resources if they were started.

    Returns:
        None. Resets the module-level Playwright globals to ``None``.
    """
    global _PW, _PW_BROWSER, _PW_CTX
    try:
        if _PW_CTX is not None:
            await _PW_CTX.close()
    except Exception:
        pass
    try:
        if _PW_BROWSER is not None:
            await _PW_BROWSER.close()
    except Exception:
        pass
    try:
        if _PW is not None:
            await _PW.stop()
    except Exception:
        pass
    _PW = None
    _PW_BROWSER = None
    _PW_CTX = None


async def _render_with_pw(url: str) -> Optional[str]:
    """Render a URL using the shared Playwright browser/context.

    Includes one self-heal retry if the browser died under load.

    Args:
        url: Absolute URL to render.

    Returns:
        HTML string when rendering succeeds; otherwise ``None``.
    """
    await _ensure_pw_started()
    assert _PW_CTX is not None

    async def _once() -> Optional[str]:
        page = await _PW_CTX.new_page()
        try:
            try:
                await page.goto(url, timeout=25000, wait_until="commit")
            except PWError as exc:
                # salvage whatever we can
                try:
                    html_text = await page.content()
                    if html_text:
                        return html_text
                except Exception:
                    pass
                html_text = await http_fallback(_PW_CTX, url)
                if html_text:
                    return html_text
                logger.debug("Browser nav issue (%s) at %s",
                             _classify_net_error(exc), url)
                return None

            html_text = await get_stable_content(page, total_ms=18000)
            if html_text:
                return html_text

            html_text = await http_fallback(_PW_CTX, page.url)
            if html_text:
                return html_text

            try:
                return await page.content()
            except PWError:
                return None
        finally:
            try:
                await page.close()
            except Exception:
                pass

    # Try once, then try restart on browser death
    try:
        html_text = await _once()
        if html_text is not None:
            return html_text
    except PWError as exc:
        msg = str(exc).lower()
        if "closed" in msg or "target closed" in msg or "browser has been closed" in msg:
            logger.debug("Playwright browser died; restarting...")
            await _shutdown_pw()
            await _ensure_pw_started()
            try:
                return await _once()
            except Exception:
                return None
        return None
    except Exception:
        return None

    return None

async def fetch_url(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    """Fetch page text, rendering HTML with Playwright when appropriate.
    Policy:
      - If it's clearly a download → skip.
      - If it's clearly text but NOT HTML → fetch with aiohttp and return text.
      - If it's (likely) HTML → ALWAYS render with Playwright.
      - If HEAD lies or is missing → do ONE GET to sniff headers/body,
        but DO NOT return HTML from aiohttp; escalate to Playwright instead.

    Args:
        session: Shared aiohttp client session.
        url: Absolute URL to fetch.

    Returns:
        Text content if fetched or rendered successfully; otherwise ``None``.
    """
    try:
        # 0) Cheap path/extension skip
        if should_skip_url_by_path(url):
            logger.debug("Skipping by path/extension: %s", url)
            return None

        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host in _DEAD_HOSTS:
            logger.debug("Skipping %s (host marked dead)", url)
            return None

        # 1) Advisory HEAD
        head_status = None
        content_type = ""
        content_disp = ""
        try:
            async with session.head(url, allow_redirects=True, timeout=12) as resp:
                head_status = resp.status
                content_type = (resp.headers.get("Content-Type") or "").strip()
                content_disp = (resp.headers.get("Content-Disposition") or "").strip()
        except Exception as exc:
            logger.debug("HEAD error (%s) at %s", _classify_net_error(exc), url)

        # Attachments are not HTML pages; skip
        if content_disp and "attachment" in content_disp.lower():
            logger.debug("Skipping by Content-Disposition attachment: %s", url)
            return None

        # 2) If HEAD was bad/inconclusive → one GET to sniff
        sniff_text = None
        if head_status is None or head_status >= 400 or not content_type:
            try:
                async with session.get(url, allow_redirects=True, timeout=20) as resp:
                    if resp.status >= 400:
                        logger.debug("Skip: GET %s returned %s", url, resp.status)
                        return None
                    # Prefer GET's Content-Type when present
                    sniff_ct = (resp.headers.get("Content-Type") or "").strip()
                    if sniff_ct:
                        content_type = sniff_ct
                    sniff_text = await resp.text(errors="replace")
            except Exception as exc:
                reason = _classify_net_error(exc)
                logger.debug("GET failed after bad/no HEAD (%s) %s", reason, url)
                if reason == "refused" and host:
                    _DEAD_HOST_FAILS[host] += 1
                    if _DEAD_HOST_FAILS[host] >= 2:
                        _DEAD_HOSTS.add(host)
                return None

        # 3) Non-HTML text assets: return them (no browser)
        if content_type and not is_probably_html(content_type):
            # Treat text/* and application/javascript as "textual but not HTML"
            if content_type.lower().startswith("text/") or content_type.lower().startswith("application/javascript"):
                if sniff_text is not None:
                    return sniff_text
                # If we didn't GET yet, do a single GET now to return the text
                try:
                    async with session.get(url, allow_redirects=True, timeout=20) as resp:
                        if resp.status < 400:
                            return await resp.text(errors="replace")
                        logger.debug("Skip: GET %s returned %s", url, resp.status)
                        return None
                except Exception as exc:
                    logger.debug("GET failed for text asset %s: %s", url, exc)
            # Non-text, non-HTML (binary): skip
            return None

        # 4) HTML (or unknown that smells like HTML): ALWAYS render with Playwright
        # If we sniffed a body, and it contains <html>, we STILL render (by policy).
        logger.debug("Rendering (HTML): %s", url)
        html_text = await _render_with_pw(url)
        if html_text is None:
            await asyncio.sleep(0.35)
            html_text = await _render_with_pw(url)
        return html_text

    except Exception as e:
        reason = _classify_net_error(e)
        logger.debug("Fetch error (%s) at %s: %s", reason, url, e)
        return None



# ---------------------- URL canonicalization helpers ----------------------

# Global: query parameters treated as tracking/analytics and removed
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_reader", "utm_name", "utm_place", "utm_creative",
    "gclid", "dclid", "fbclid", "mc_cid", "mc_eid", "igshid",
    "ref_src", "ref_url", "ref", "mkt_tok", "spm", "cn-reloaded",
}
TRACKING_PREFIXES = ("utm_", "_hs", "vero_")


def _should_drop_param(k: str) -> bool:
    """Check if a query parameter is tracking/analytics-related.

    Args:
        k: Query parameter name.

    Returns:
        True if the parameter should be removed as tracking/analytics; otherwise False.
    """
    k_low = k.lower()
    if k_low in TRACKING_PARAMS:
        return True
    return any(k_low.startswith(p) for p in TRACKING_PREFIXES)


def _normalize_path(path: str) -> str:
    """Normalize a URL path for canonicalization.

    - Collapse multiple slashes into a single slash (``//`` → ``/``)
    - Remove trailing slash except when the path is just ``/``

    Args:
        path: Raw path component to normalize.

    Returns:
        Normalized path suitable for canonical URL construction.
    """
    # Collapse multiple slashes, keep a single leading slash
    path = re.sub(r"/{2,}", "/", path)
    # Remove trailing slash except root
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def canonicalize_url(base_url: str, link: str, *, scope_host: str) -> Optional[str]:
    """Resolve and normalize an in-scope link to a canonical absolute URL.

    Steps:
    - Resolve against ``base_url`` and drop URL fragment.
    - Enforce ``http/https`` schemes and scope by hostname.
    - Normalize path and clean/sort query parameters, dropping trackers.

    Args:
        base_url: The page URL the link was found on.
        link: The raw link/href value.
        scope_host: Hostname suffix that defines in-scope URLs.

    Returns:
        Canonical absolute URL string when in scope; otherwise ``None``.
    """
    if not link:
        return None
    link = link.strip()
    # Ignore javascript/mailto/tel here; those are handled separately elsewhere
    if link.startswith(("javascript:", "data:", "blob:")):
        return None

    # Guard against malformed IPv6/bad hrefs raising ValueError
    try:
        abs_url = urljoin(base_url, link)
        abs_url, _ = urldefrag(abs_url)
        parsed = urlparse(abs_url)
    except Exception:
        return None

    if parsed.scheme not in ("http", "https"):
        return None

    # Scope check by hostname (safe) instead of netloc
    hostname = (parsed.hostname or "").lower()
    if not hostname.endswith(scope_host):
        return None

    # Normalize path
    path = parsed.path or "/"
    path = _normalize_path(path)

    # Clean query: drop tracking, sort remaining, dedupe
    query = ""
    if parsed.query:
        pairs = []
        for k, v in parse_qsl(parsed.query, keep_blank_values=False):
            if _should_drop_param(k):
                continue
            pairs.append((k, v))
        if pairs:
            pairs.sort(key=lambda kv: (kv[0], kv[1]))
            query = urlencode(pairs, doseq=True)

    # IPv6-safe netloc reconstruction + default-port stripping
    port = parsed.port
    if (parsed.scheme == "http" and port in (None, 80)) or (parsed.scheme == "https" and port in (None, 443)):
        netloc = hostname
    else:
        netloc = f"{hostname}:{port}" if port else hostname

    # no params, no fragment
    return urlunparse((parsed.scheme, netloc, path, "", query, ""))


def _url_struct_key(u: str) -> Tuple[str, str, Tuple[Tuple[str, str], ...]]:
    """Compute a structural URL key for robust de-duplication.

    Args:
        u: Absolute URL string.

    Returns:
        Tuple of ``(host, normalized_path_without_html_or_trailing_slash,
        first_5_sorted_query_pairs)`` used to collapse near-duplicates.
    """
    p = urlparse(u)
    host = (p.hostname or "").lower()
    path = (p.path or "/").rstrip("/")
    if path.endswith(".html"):
        path = path[:-5] or "/"
    q_pairs = tuple(sorted(parse_qsl(p.query, keep_blank_values=False)))[:5]
    return (host, path, q_pairs)


# ---------------------- Extraction helpers ----------------------

# Global: TLDs/extensions that should NOT appear as email TLDs in regex
EMAIL_IGNORE_EXTS = (
    "png", "jpg", "jpeg", "gif", "svg", "bmp", "webp", "ico",
    "css", "js", "json", "xml", "csv", "txt", "pdf",
    "doc", "docx", "xls", "xlsx",
)

# Global: email extraction regex (excludes common file extensions as TLDs)
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?!(?:" +
    "|".join(EMAIL_IGNORE_EXTS) + r")\b)[a-zA-Z]{2,}"
)

# Global: phone extraction regex (tolerant digits and separators)
PHONE_RE = re.compile(r"\+?\d[\d\s()\-]{6,}\d")

# Global: mapping from TLD to default phone region code
_TLD_TO_REGION: Dict[str, str] = {
    "gr": "GR", "us": "US", "uk": "GB", "gb": "GB", "de": "DE", "fr": "FR", "it": "IT", "es": "ES", "pt": "PT", "nl": "NL",
    "be": "BE", "se": "SE", "no": "NO", "fi": "FI", "dk": "DK", "pl": "PL", "cz": "CZ", "sk": "SK", "hu": "HU", "ro": "RO",
    "bg": "BG", "at": "AT", "ch": "CH", "ie": "IE", "tr": "TR", "ua": "UA", "ru": "RU", "il": "IL", "ca": "CA", "au": "AU",
    "nz": "NZ", "mx": "MX", "br": "BR", "ar": "AR", "cl": "CL", "co": "CO", "za": "ZA", "in": "IN", "sg": "SG", "hk": "HK",
    "tw": "TW", "jp": "JP", "kr": "KR", "my": "MY", "id": "ID", "th": "TH", "ph": "PH", "vn": "VN",
}


def _guess_region_from_domain(domain: str) -> Optional[str]:
    """Infer a default phone region from a domain's TLD.

    Args:
        domain: Target domain (e.g., ``example.gr``).

    Returns:
        ISO 3166-1 alpha-2 country code (e.g., ``"GR"``) or ``None``.
    """
    tld = domain.rsplit(".", 1)[-1].lower()
    return _TLD_TO_REGION.get(tld)


def _clean_angle_brackets(s: str) -> str:
    """Trim surrounding angle brackets if present.

    Args:
        s: Input string possibly wrapped in ``<`` and ``>``.

    Returns:
        The inner string without surrounding brackets; otherwise the original.
    """
    s = s.strip()
    if s.startswith("<") and s.endswith(">"):
        return s[1:-1]
    return s

# ---- New: targeted text/email normalization helpers ----

def _decode_backslash_escapes(s: str) -> str:
    """Decode selective backslash escapes common in script blobs.

    Args:
        s: Raw string possibly containing ``\\uXXXX`` or ``\\xNN`` sequences.

    Returns:
        String with Unicode/hex escapes decoded; other escapes are preserved.
    """
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\x([0-9a-fA-F]{2})",  lambda m: chr(int(m.group(1), 16)), s)
    return s


# Global: regex to trim leading/trailing wrapper punctuation (e.g., <...>, "...")
_PUNCT_EDGES = re.compile(r"^\s*([<\[\(\{\"']*)(.*?)([>\]\)\}\"']*)\s*$")


def _strip_edge_punct(s: str) -> str:
    """Strip wrapper punctuation from the string edges only.

    Args:
        s: Input string possibly wrapped by punctuation (e.g., ``<...>``, ``"..."``).

    Returns:
        The inner string without leading/trailing wrapper punctuation.
    """
    m = _PUNCT_EDGES.match(s)
    if not m:
        return s.strip()
    core = m.group(2).strip()
    return core


def _norm_text(s: str) -> str:
    """Normalize text derived from HTML or script content.

    Steps:
    - Unescape HTML entities (e.g., ``&lt;``, ``&#x3c;``)
    - Decode ``\\uXXXX``/``\\xNN`` sequences
    - Apply Unicode normalization (NFKC) and drop control chars except whitespace

    Args:
        s: Raw text to normalize.

    Returns:
        A cleaned, normalized string suitable for regex extraction.
    """
    s = html.unescape(s)
    s = _decode_backslash_escapes(s)
    s = unicodedata.normalize("NFKC", s)
    return "".join(
        ch for ch in s
        if (unicodedata.category(ch)[0] != "C") or ch in "\n\r\t"
    )


def normalize_email(email: str) -> Optional[str]:
    """Validate and normalize an email address.

    Args:
        email: Raw email candidate as found on a page.

    Returns:
        Lower-cased, validated address suitable for de-duplication; or ``None``
        if invalid.
    """
    candidate = _strip_edge_punct(_norm_text(unquote(email.strip())))
    try:
        valid = validate_email(candidate.lower(), check_deliverability=True)
        return valid.normalized.lower()
    except EmailNotValidError as exc:
        logger.debug("Email validation failed for %s: %s", email, exc)
        return None


def normalize_phone(phone: str, default_region: Optional[str] = None) -> Optional[str]:
    """Normalize a phone number to digits-only national format when valid.

    Args:
        phone: Raw phone string as found on a page.
        default_region: Preferred region when parsing non-E.164 numbers.

    Returns:
        Digits-only national number (length >= 7) if valid; otherwise ``None``.
    """
    raw = phone.strip()
    try_order: List[Optional[str]] = [default_region,
                                      None] if not raw.startswith("+") else [None, default_region]
    for region in try_order:
        if region is None and not raw.startswith("+"):
            continue
        try:
            parsed = phonenumbers.parse(raw, region)
            if phonenumbers.is_valid_number(parsed):
                national = phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
                digits = "".join(ch for ch in national if ch.isdigit())
                if len(digits) >= 7:
                    return digits
        except phonenumbers.NumberParseException:
            pass
    return None


def _extract_mailto_addresses(href: str) -> List[str]:
    """Extract one or more email addresses from a ``mailto:`` URL.

    Supports forms like:
    - ``mailto:user@example.com``
    - ``mailto://user@example.com``
    - ``mailto:?to=user@example.com&cc=a@b.com;b@c.com``

    Args:
        href: Raw ``mailto:`` link value.

    Returns:
        List of extracted addresses (unvalidated). May be empty.
    """
    out: List[str] = []
    try:
        h = href.strip()
        if not h.lower().startswith("mailto:"):
            return out
        rest = h.split(":", 1)[1]
        if rest.startswith("//"):
            rest = rest.lstrip("/")
        addr_part, _, query = rest.partition("?")
        addr_part = _clean_angle_brackets(unquote(addr_part)).strip()
        if addr_part:
            out.extend(re.split(r"[;,]", addr_part))
        if query:
            qs = parse_qs(query)
            for key in ("to", "cc", "bcc"):
                for item in qs.get(key, []):
                    out.extend(re.split(r"[;,]", unquote(item)))
    except Exception as exc:
        logger.debug("Failed to parse mailto %s: %s", href, exc)
    return [a.strip() for a in out if a and a.strip()]


def _extract_tel_numbers(href: str) -> List[str]:
    """Extract phone candidates from a ``tel:`` URL.

    Supports ``tel:+123...`` and ``tel://+123...`` and strips any query.

    Args:
        href: Raw ``tel:`` link value.

    Returns:
        List with one candidate phone string (unvalidated) or empty list.
    """
    out: List[str] = []
    try:
        h = href.strip()
        if not h.lower().startswith("tel:"):
            return out
        rest = h.split(":", 1)[1]
        if rest.startswith("//"):
            rest = rest.lstrip("/")
        number, _, _ = rest.partition("?")
        out.append(unquote(number.strip()))
    except Exception as exc:
        logger.debug("Failed to parse tel %s: %s", href, exc)
    return out


# ---------------------- Crawler ----------------------


class Crawler:
    """Asynchronous breadth-first crawler limited to the target domain.

    Responsibilities:
    - Maintain in-scope URL queue and structural de-duplication.
    - Fetch and render pages, then extract and normalize contacts.
    - Track discovery sources and basic acceptance/drop metrics.
    """

    def __init__(self, domain: str, max_depth: int = 3, concurrency: int = 5):
        """Initialize a domain-scoped crawler.

        Args:
            domain: Target domain (apex) to constrain crawling.
            max_depth: Maximum link/script depth from each start URL.
            concurrency: Number of concurrent fetch/process tasks.
        """
        self.domain = domain
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.visited: Set[str] = set()
        self._queued: Set[str] = set()
        # structural de-dup
        self._seen_keys: Set[Tuple[str, str,
                                   Tuple[Tuple[str, str], ...]]] = set()
        self.emails: Dict[str, str] = {}  # canonical -> canonical (lower-case)
        self.phones: Dict[str, str] = {}  # normalized digits
        self.email_sources: Dict[str, str] = {}
        self.phone_sources: Dict[str, str] = {}
        self.default_region: Optional[str] = _guess_region_from_domain(domain)

        # --- org-scope email filtering setup (tldextract) ---
        self._tld = tldextract.TLDExtract(
            cache_dir=None, suffix_list_urls=None)
        _ext = self._tld(domain)
        self._org = _ext.top_domain_under_public_suffix
        self._emails_kept = 0
        self._emails_dropped = 0
        self._phones_kept = 0
        self._phones_dropped = 0
        logger.debug(
            "Initializing internal crawler for https://%s (org=%s)",
            domain, self._org or "?"
        )

    def add_email(self, email: str, source: str, snippet: str = "") -> None:
        """Validate, org-scope filter, and store an email with its source.

        Args:
            email: Raw email candidate.
            source: URL where the email was discovered.
            snippet: Optional nearby text for debug logging.
        """
        canon = normalize_email(email)
        if not canon:
            return

        # org-scope filter: keep iff registered_domain(email) == registered_domain(target)
        try:
            domain_part = canon.rsplit("@", 1)[-1]
            e_ext = self._tld(domain_part)
            email_org = e_ext.top_domain_under_public_suffix
        except Exception as exc:
            self._emails_dropped += 1
            logger.debug("Dropping email (parse error): %s (%s)", email, exc)
            return

        keep = bool(email_org) and (email_org == self._org)
        if not keep:
            self._emails_dropped += 1
            logger.debug(
                "Dropping non-org email: %s (email_org=%s, target_org=%s, source=%s)",
                canon, email_org, self._org, source
            )
            return

        is_new = canon not in self.emails
        if is_new:
            self.emails[canon] = canon
            self.email_sources[canon] = source
            self._emails_kept += 1
            logger.info("Found email: %s (source: %s)", canon, source)
        else:
            logger.debug("Duplicate email: %s (new source: %s)", canon, source)

        if logger.isEnabledFor(logging.DEBUG) and snippet:
            logger.debug("Email snippet: %s",
                         " ".join(snippet.strip().split()))

    def add_phone(self, phone: str, source: str, snippet: str = "") -> None:
        """Validate and store a phone number with its discovery source.

        The normalized representation is digits-only (national format). Invalid
        candidates are dropped to minimize false positives.

        Args:
            phone: Raw phone candidate.
            source: URL where the phone was discovered.
            snippet: Optional nearby text for debug logging.
        """
        norm = normalize_phone(phone, self.default_region)
        if norm:
            is_new = norm not in self.phones
            if is_new:
                self.phones[norm] = norm
                self.phone_sources[norm] = source
                self._phones_kept += 1
                logger.info("Found phone: %s (source: %s)", norm, source)
            else:
                logger.debug(
                    "Duplicate phone: %s (new source: %s)", norm, source)
            if logger.isEnabledFor(logging.DEBUG) and snippet:
                logger.debug("Phone snippet: %s",
                             " ".join(snippet.strip().split()))
        else:
            self._phones_dropped += 1

    async def crawl(self, start_url: str):
        """Breadth-first crawl starting from the supplied URL.

        Args:
            start_url: Seed URL to begin crawling for this domain.
        """
        logger.debug("Starting the inner crawler at %s", start_url)
        queue = deque([(start_url, 0)])
        self._queued.add(start_url)
        timeout = aiohttp.ClientTimeout(total=45)
        connector = aiohttp.TCPConnector(
            limit=self.concurrency, family=socket.AF_INET, ttl_dns_cache=120
        )
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            while queue:
                tasks = []
                while queue and len(tasks) < self.concurrency:
                    url, depth = queue.popleft()

                    # Structural de-dup check and depth gate
                    key = _url_struct_key(url)
                    if depth > self.max_depth or key in self._seen_keys:
                        continue
                    self._seen_keys.add(key)

                    if url in self.visited:
                        continue
                    self.visited.add(url)

                    tasks.append(self._process_url(session, url, depth, queue))
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=False)

    async def _process_url(self, session: aiohttp.ClientSession, url: str, depth: int, queue: deque):
        """Fetch, extract, and enqueue new links/scripts from a single URL.

        Args:
            session: Shared ``aiohttp`` session for this crawl.
            url: Absolute URL to process.
            depth: Current crawl depth.
            queue: BFS queue to extend with discovered items.
        """
        logger.debug("Crawling %s (depth: %d)", url, depth)
        try:
            content = await asyncio.wait_for(fetch_url(session, url), timeout=70)
        except asyncio.TimeoutError:
            logger.debug("Timed out fetching %s", url)
            return
        except Exception as e:
            logger.debug("Error fetching %s: %r", url, e)
            return
        if not content:
            return

        parsed_url = urlparse(url)
        # If it's a JS file we fetched as text, don't try phone numbers (too noisy)
        if parsed_url.path.lower().endswith(('.js', '.mjs')):
            self.extract_data(content, url, allow_phones=False)
            return

        self.extract_data(content, url)

        soup = BeautifulSoup(content, "html.parser")
        # Also search rendered text for emails split by HTML tags
        self.extract_data(soup.get_text(" "), url)

        # Explicitly capture mailto:/tel: with normalization
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            low = href.lower()
            if low.startswith("mailto:"):
                for addr in _extract_mailto_addresses(href):
                    self.add_email(addr, url, f"mailto:{addr}")
            elif low.startswith("tel:"):
                for num in _extract_tel_numbers(href):
                    text_snip = a.get_text(" ", strip=True) or href
                    self.add_phone(num, url, text_snip)

        # Follow in-scope links (HTML pages) with deterministic ordering
        links = []
        for link in soup.find_all("a", href=True):
            cand = canonicalize_url(url, link["href"], scope_host=self.domain)
            if cand and not should_skip_url_by_path(cand):
                links.append(cand)
        for cand in sorted(set(links)):
            k = _url_struct_key(cand)
            if k not in self._seen_keys and cand not in self._queued:
                queue.append((cand, depth + 1))
                self._queued.add(cand)
                logger.debug("Discovered link %s", cand)

        # Crawl JS sources too, deterministic ordering
        scripts = []
        for script in soup.find_all("script", src=True):
            cand = canonicalize_url(url, script["src"], scope_host=self.domain)
            if cand and not should_skip_url_by_path(cand) and cand.lower().endswith((".js", ".mjs")):
                scripts.append(cand)
        for cand in sorted(set(scripts)):
            k = _url_struct_key(cand)
            if k not in self._seen_keys and cand not in self._queued:
                queue.append((cand, depth + 1))
                self._queued.add(cand)
                logger.debug("Discovered script %s", cand)

    def extract_data(self, text: str, url: str, *, allow_phones: bool = True):
        """Extract normalized emails and phone numbers from page text.

        Args:
            text: Raw or rendered page text.
            url: Source URL for attribution/logging.
            allow_phones: When False, only extract emails (e.g., from JS files).
        """
        before_emails = len(self.emails)
        before_phones = len(self.phones)

        # Safe, targeted normalization (no unicode_escape sledgehammer)
        text = _norm_text(text)

        for m in EMAIL_RE.finditer(text):
            snippet = text[max(m.start()-20, 0): m.end()+20].replace("\n", " ")
            self.add_email(m.group(), url, snippet)

        if allow_phones:
            for m in PHONE_RE.finditer(text):
                snippet = text[max(m.start()-20, 0): m.end()+20].replace("\n", " ")
                self.add_phone(m.group(), url, snippet)

        new_emails = len(self.emails) - before_emails
        new_phones = len(self.phones) - before_phones
        if (new_emails > 0 or new_phones > 0) and logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Extracted %d valid email(s) and %d valid phone(s) from %s",
                new_emails, new_phones, url
            )


# ---------------------- Breach checkers ----------------------


def check_hibp(email: str, api_key: Optional[str]) -> Optional[List[str]]:
    """Look up email breaches via a HaveIBeenPwned proxy API.

    Args:
        email: Email address to query.
        api_key: API key for the HIBP proxy.

    Returns:
        List of breach names, an empty list if not found, or ``None`` on
        error/rate limit.
    """
    if not api_key:
        return None

    url = f"http://83.212.80.246:8600/proxy/haveibeenpwned/{email}/"
    headers = {"Accept": "application/json",
               "Authorization": f"Api-Key {api_key}"}
    try:
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 200:
            breaches = [b.get("Name") for b in resp.json()]
            if breaches:
                logger.warning(
                    "BREACH (HIBP): %s is in %d breach(es).", email, len(breaches))
            else:
                logger.info(
                    "OK (HIBP): %s was not found in any breaches.", email)
            time.sleep(6)  # friendly pacing
            return breaches
        if resp.status_code == 404:
            logger.info("OK (HIBP): %s was not found in any breaches.", email)
            time.sleep(6)
            return []
        if resp.status_code == 429:
            logger.warning("HIBP rate limit hit. Sleeping for 10s.")
            time.sleep(10)
            return None
        logger.warning("Unexpected HIBP proxy response: %s %s",
                       resp.status_code, resp.text)
    except Exception as exc:
        logger.warning("HIBP proxy lookup failed for %s: %s", email, exc)
    return None


# Global: local request timestamps for LeakCheck rate limiting
_leakcheck_recent = deque()


def check_leakcheck_phone(phone: str, api_key: Optional[str]) -> Optional[List[str]]:
    """Look up phone breaches via the LeakCheck v2 API.

    Args:
        phone: Digits-only national phone number.
        api_key: LeakCheck API key.

    Returns:
        List of breach source names, an empty list if not found, or ``None`` on
        error/rate limit.
    """
    if not api_key:
        return None

    now = time.time()
    while _leakcheck_recent and now - _leakcheck_recent[0] >= 1.2:
        _leakcheck_recent.popleft()
    if len(_leakcheck_recent) >= 3:
        sleep_for = 1.2 - (now - _leakcheck_recent[0])
        logger.debug(
            "LeakCheck local rate limit reached, sleeping %.2fs", sleep_for)
        time.sleep(max(0, sleep_for))
    _leakcheck_recent.append(time.time())

    url = f"https://leakcheck.io/api/v2/query/{phone}"
    headers = {"Accept": "application/json", "X-API-Key": api_key}
    params = {"type": "phone"}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and data.get("success") is True:
                if data.get("found"):
                    sources = []
                    for item in data.get("result", []):
                        src = item.get("source")
                        if isinstance(src, dict):
                            name = src.get("name")
                            if name:
                                sources.append(name)
                        elif src:
                            sources.append(str(src))
                    sources = list(dict.fromkeys(sources))
                    logger.warning(
                        "BREACH (LeakCheck): %s is in %d breach(es).", phone, len(sources))
                    return sources
                logger.info(
                    "OK (LeakCheck): %s was not found in any breaches.", phone)
                return []
        if resp.status_code == 429:
            logger.warning("LeakCheck rate limit hit. Sleeping for 10s.")
            time.sleep(10)
            return None
        logger.warning("Unexpected LeakCheck response: %s %s",
                       resp.status_code, resp.text)
    except Exception as exc:
        logger.warning("LeakCheck lookup failed for %s: %s", phone, exc)
    return None


# ---------------------- Results & reporting ----------------------


def save_results(
    results: dict,
    domain: str,
    *,
    fmt: str = "json",
    output_path: str | None = None,
) -> str:
    """Serialize and persist scan results.

    Args:
        results: Dictionary returned by :func:`scan_domain`.
        domain: The scanned domain (used in default filename).
        fmt: One of ``"json"``, ``"csv"``, or ``"md"``.
        output_path: Optional explicit output filename.

    Returns:
        The path to the created file.
    """

    email_sources = results.get("email_sources", {})
    phone_sources = results.get("phone_sources", {})
    breached_emails = results.get("breached_emails", {})
    breached_phones = results.get("breached_phones", {})

    emails = [
        {
            "email": email,
            "source": email_sources.get(email, ""),
            "breaches": breached_emails.get(email, []),
        }
        for email in results.get("emails", set())
    ]
    emails.sort(key=lambda x: x["email"])

    phones = [
        {
            "phone": phone,
            "source": phone_sources.get(phone, ""),
            "breaches": breached_phones.get(phone, []),
        }
        for phone in results.get("phones", set())
    ]
    phones.sort(key=lambda x: x["phone"])

    summary = {
        "num_subdomains": len(results.get("subdomains", [])),
        "num_endpoints": results.get("num_endpoints", 0),
        "num_emails": len(results.get("emails", [])),
        "num_phones": len(results.get("phones", [])),
        "num_breached_emails": len(breached_emails),
        "num_breached_phones": len(breached_phones),
        "emails_dropped": results.get("emails_dropped", 0),
        "phones_dropped": results.get("phones_dropped", 0),
    }

    report = {
        "scan_domain": domain,
        "scan_start": results.get("scan_start"),
        "scan_end": results.get("scan_end"),
        "scan_duration": results.get("scan_duration"),
        "summary": summary,
        "subdomains": sorted(results.get("subdomains", [])),
        "emails": emails,
        "phones": phones,
    }

    base = domain.replace("/", "_")
    timestamp = datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    if not output_path:
        output_path = f"{base}-{timestamp}.{fmt}"
    if fmt == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        import csv
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["scan_start", report.get("scan_start")])
            writer.writerow(["scan_end", report.get("scan_end")])
            writer.writerow(["scan_duration", report.get("scan_duration")])
            writer.writerow([])
            for key, value in summary.items():
                writer.writerow([key, value])
            writer.writerow([])
            writer.writerow(["type", "value", "source", "breaches"])
            for sub in report["subdomains"]:
                writer.writerow(["subdomain", sub, "", ""])
            for item in emails:
                writer.writerow(
                    ["email", item["email"], item["source"], ", ".join(item["breaches"])])
            for item in phones:
                writer.writerow(
                    ["phone", item["phone"], item["source"], ", ".join(item["breaches"])])
    elif fmt == "md":
        lines = [f"# Scan Report for {domain}", ""]
        lines.append(f"Start: {report.get('scan_start')}")
        lines.append(f"End: {report.get('scan_end')}")
        lines.append(f"Duration: {report.get('scan_duration')}")
        lines.append("")
        lines.append("## Summary")
        for key, value in summary.items():
            lines.append(f"- {key.replace('_', ' ')}: {value}")
        lines.append("")
        lines.append("## Subdomains")
        for sub in report["subdomains"]:
            lines.append(f"- {sub}")
        lines.append("")
        lines.append("## Emails")
        lines.append("| Email | Source | Breaches |")
        lines.append("| --- | --- | --- |")
        for item in emails:
            lines.append(
                f"| {item['email']} | {item['source']} | {', '.join(item['breaches'])} |")
        lines.append("")
        lines.append("## Phones")
        lines.append("| Phone | Source | Breaches |")
        lines.append("| --- | --- | --- |")
        for item in phones:
            lines.append(
                f"| {item['phone']} | {item['source']} | {', '.join(item['breaches'])} |")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    else:
        raise ValueError(f"Unknown format: {fmt}")

    logger.debug("Results successfully saved to %s", output_path)
    return output_path


# ---------------------- High level scan ----------------------


async def scan_domain(
    domain: str,
    depth: int = 3,
    hibp_key: Optional[str] = None,
    leakcheck_key: Optional[str] = None,
    *,
    verbose: bool = False,
    concurrency: int = 5,
    save: bool = False,
    fmt: str = "json",
    output_path: Optional[str] = None,
) -> dict:
    """Crawl a domain and optionally check contacts against breach data.

    Args:
        domain: Validated target domain (ASCII/IDNA normalized).
        depth: Maximum crawl depth.
        hibp_key: API key for HaveIBeenPwned proxy.
        leakcheck_key: API key for LeakCheck.
        verbose: Enable debug logging for more detail.
        concurrency: Number of concurrent workers for fetching/crawling.
        save: When True, persist results via :func:`save_results`.
        fmt: Output format for saving ("json", "csv", or "md").
        output_path: Optional explicit output file path.

    Returns:
        Dictionary with subdomains, emails, phones, breach mappings,
        per-item sources, and scan timing/summary.
    """
    start_time = time.time()
    start_dt = datetime.datetime.now(datetime.timezone.utc)
    logger.info("Starting scan for %s (depth: %d, concurrency: %d)",
                domain, depth, concurrency)

    stage = 1
    logger.info("Stage %d: Enumerating subdomains for %s", stage, domain)
    subs = enumerate_subdomains(domain)

    stage += 1
    logger.info(
        "Stage %d: Filtering %d subdomains for web accessibility...", stage, len(subs))
    subdomain_schemes = await filter_accessible_subdomains(subs, concurrency=concurrency, retries=2)
    logger.info("Found %d accessible web hosts.", len(subdomain_schemes))
    if verbose:
        logger.debug("%d of %d subdomains are accessible",
                     len(subdomain_schemes), len(subs))
        for sub in sorted(subdomain_schemes):
            logger.debug(" [+] %s", sub)

    logger.info("Using internal Python crawler.")
    crawler = Crawler(domain, max_depth=depth, concurrency=concurrency)

    # ---- Start Playwright (single global context); shut it down after crawl/breaches ----
    await _ensure_pw_started()

    stage += 1
    logger.info("Stage %d: Crawling %d URL(s) to find contacts...",
                stage, len(subdomain_schemes))
    for sub, scheme in sorted(subdomain_schemes.items()):  # stabilize order
        start_url = f"{scheme}://{sub}"
        if verbose:
            logger.debug("Crawling %s", start_url)
        logger.info("Starting crawl at %s", start_url)
        await crawler.crawl(start_url)

    logger.info("Crawl phase complete. Found %d emails and %d phone numbers.", len(
        crawler.emails), len(crawler.phones))
    logger.debug("Email filter (org) stats: kept=%d, dropped=%d",
                 getattr(crawler, "_emails_kept", 0),
                 getattr(crawler, "_emails_dropped", 0))
    logger.debug("Phone filter stats: kept=%d, dropped=%d",
                 getattr(crawler, "_phones_kept", 0),
                 getattr(crawler, "_phones_dropped", 0))

    stage += 1
    breached_emails: Dict[str, List[str]] = {}
    logger.info("Stage %d: Checking %d emails for breaches via HIBP...",
                stage, len(crawler.emails))
    for email in crawler.emails.values():
        breaches = check_hibp(email, hibp_key)
        if breaches:
            breached_emails[email] = breaches

    stage += 1
    breached_phones: Dict[str, List[str]] = {}
    logger.info("Stage %d: Checking %d phone numbers for breaches via LeakCheck...",
                stage, len(crawler.phones))
    for phone in crawler.phones.values():
        breaches = check_leakcheck_phone(phone, leakcheck_key)
        if breaches:
            breached_phones[phone] = breaches

    # ---- stop Playwright after all work is done ----
    await _shutdown_pw()


    results = {
        "subdomains": set(subdomain_schemes.keys()),
        "emails": set(crawler.emails.values()),
        "phones": set(crawler.phones.values()),
        "breached_emails": breached_emails,
        "breached_phones": breached_phones,
        "email_sources": crawler.email_sources,
        "phone_sources": crawler.phone_sources,
        "num_endpoints": len(crawler.visited),
        "emails_dropped": getattr(crawler, "_emails_dropped", 0),
        "phones_dropped": getattr(crawler, "_phones_dropped", 0),
    }

    end_dt = datetime.datetime.now(datetime.timezone.utc)
    duration = time.time() - start_time
    results["scan_duration"] = duration
    ts_format = "%Y-%m-%d %H:%M:%S %Z"
    results["scan_start"] = start_dt.strftime(ts_format)
    results["scan_end"] = end_dt.strftime(ts_format)

    # Unified final summary log for both CLI and API callers
    logger.info("%s", "=" * 60)
    logger.info("Scan Complete for %s in %.2f seconds.",
                domain, results.get("scan_duration", 0.0))
    logger.info("Scan started at %s and ended at %s",
                results.get("scan_start"), results.get("scan_end"))
    logger.info(
        "Summary: Crawled %d endpoints, %d subdomains, %d emails (%d breached, %d dropped) and %d phones (%d breached, %d dropped).",
        results.get("num_endpoints", 0),
        len(results.get("subdomains", [])),
        len(results.get("emails", [])),
        len(results.get("breached_emails", {})),
        results.get("emails_dropped", 0),
        len(results.get("phones", [])),
        len(results.get("breached_phones", {})),
        results.get("phones_dropped", 0),
    )
    if save:
        try:
            saved_to = save_results(results, domain, fmt=fmt, output_path=output_path)
            logger.info("Saved results to %s", saved_to)
        except Exception as exc:
            logger.warning("Failed to save results: %s", exc)
    logger.info("%s", "=" * 60)

    return results


# ---------------------- CLI ----------------------


def parse_args(default_depth: int) -> argparse.Namespace:
    """Define and parse CLI arguments for the scanner.

    Args:
        default_depth: Fallback value for ``--depth``.

    Returns:
        An ``argparse.Namespace`` with parsed options.
    """
    parser = argparse.ArgumentParser(
        description="Crawl a domain and check contacts against breach data")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-d", "--depth", type=int, default=default_depth,
                        metavar="N", help="Maximum crawl depth (default: %(default)s)")
    parser.add_argument("-c", "--concurrency", type=int, default=5,
                        metavar="N", help="Number of concurrent workers")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    fmt_group = parser.add_mutually_exclusive_group()
    fmt_group.add_argument("-j", "--json", action="store_true",
                           help="Save results as DOMAIN-TIMESTAMP.json (default)")
    fmt_group.add_argument("--csv", action="store_true",
                           help="Save results as DOMAIN-TIMESTAMP.csv")
    fmt_group.add_argument("--md", "--report", dest="md", action="store_true",
                           help="Save results as DOMAIN-TIMESTAMP.md markdown report")
    parser.add_argument(
        "-o", "--output", help="Optional output file path", default=None)
    return parser.parse_args()


async def main() -> dict:
    """Entry point for CLI execution.

    Loads configuration, validates the input domain, orchestrates the scan, and
    writes the selected report format.

    Returns:
        Raw results dictionary with contacts, breaches, and metadata.
    """
    cfg = load_config()
    default_depth = int(os.environ.get(
        "CRAWL_DEPTH", cfg.get("crawl_depth", 3)))
    args = parse_args(default_depth)

    configure_logging(logging.DEBUG if args.verbose else logging.INFO)

    valid, domain_norm, msg = validate_domain(args.domain, check_dns=True)
    if not valid:
        logger.error(msg)
        sys.exit(1)
    else:
        logger.debug("Domain %s is valid and resolvable.", domain_norm)

    hibp_key = os.environ.get("HIBP_API_KEY") or cfg.get("hibp_api_key")
    leak_key = os.environ.get(
        "LEAKCHECK_API_KEY") or cfg.get("leakcheck_api_key")

    if args.csv:
        fmt = "csv"
    elif args.md:
        fmt = "md"
    else:
        fmt = "json"

    results = await scan_domain(
        domain_norm,
        args.depth,
        hibp_key,
        leak_key,
        verbose=args.verbose,
        concurrency=args.concurrency,
        save=True,
        fmt=fmt,
        output_path=args.output,
    )
    return results


if __name__ == "__main__":
    asyncio.run(main())
