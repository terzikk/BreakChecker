"""Domain crawler, subdomain enumerator and breach checker.

Usage:
  python3 break_checker.py [options] domain

The script now accepts command line arguments. API credentials and crawl depth
are loaded from `config.json` if present, falling back to environment variables:

  HIBP_API_KEY      - HaveIBeenPwned API key
  LEAKCHECK_API_KEY - LeakCheck API key (optional, for phone checks)
  CRAWL_DEPTH       - Maximum crawl depth (default 3)

Create `config.json` in the same directory with keys hibp_api_key, leakcheck_api_key,
and crawl_depth to avoid setting environment variables each run.

Command line options:
  -d, --depth         Maximum crawl depth
  -v, --verbose       Enable debug logging
  -j, --json          Save results as DOMAIN-TIMESTAMP.json
  --csv               Save results as DOMAIN-TIMESTAMP.csv
  --md, --report      Save results as DOMAIN-TIMESTAMP.md
  -c, --concurrency   Number of concurrent workers
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
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from collections import deque
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

# ---------------------- Logging ----------------------


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure root logging and return module logger with .log backups."""
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
    """Load optional API keys and settings from config.json."""
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
    """Validate and sanitize a domain provided by a user."""
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
    """Enumerate subdomains via subfinder or free sources. Wildcards are sanitized."""
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
            resp = requests.get(url, timeout=15)
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
            resp = requests.get(url, timeout=15)
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
            resp = requests.get(url, timeout=15)
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
    try:
        async with session.request(method, url, allow_redirects=True) as resp:
            # Only <400 counts as alive; 403/405/503 are treated as dead
            return resp.status < 400
    except Exception as exc:
        logger.debug("Probe error %s %s: %s", method, url, exc)
        return False


async def choose_scheme(session: aiohttp.ClientSession, host: str, *, retries: int = 1, per_try_delay: float = 0.2) -> Optional[str]:
    """Return reachable scheme ('https' or 'http') using IPv4-only connector with retries."""
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


async def filter_accessible_subdomains(subdomains: Set[str], *, concurrency: int = 5, retries: int = 1) -> Dict[str, str]:
    """Return mapping of reachable subdomains to their scheme using asynchronous probes."""
    live: Dict[str, str] = {}
    timeout = aiohttp.ClientTimeout(total=6)
    connector = aiohttp.TCPConnector(
        limit=concurrency, family=socket.AF_INET, ttl_dns_cache=60)
    hosts = list(subdomains)

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

# Extensions and path keywords that are very likely non-HTML downloads
NON_HTML_EXTS = {
    "pdf", "zip", "gz", "bz2", "xz", "7z", "rar", "exe", "msi", "dmg", "iso",
    "png", "jpg", "jpeg", "gif", "svg", "bmp", "webp", "ico",
    "mp3", "mp4", "m4a", "aac", "wav", "flac", "ogg", "webm",
    "avi", "mov", "mkv",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
}

SKIP_PATH_KEYWORDS = (
    "/download/", "/downloads/", "/file/", "/files/", "/attachment/",
    "/attachments/", "/export/", "/exports/", "/wp-content/uploads/",
    "/media/", "/assets/", "/static/"
)


def should_skip_url_by_path(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(k in path for k in SKIP_PATH_KEYWORDS):
        return True
    if "." in path:
        ext = path.rsplit(".", 1)[-1]
        return ext in NON_HTML_EXTS
    return False


def is_probably_html(content_type: str) -> bool:
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    return ct in ("text/html", "application/xhtml+xml")


async def get_stable_content(page, *, total_ms: int = 10000) -> Optional[str]:
    deadline = time.monotonic() + total_ms / 1000.0
    while time.monotonic() < deadline:
        try:
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=1500)
            except PWError:
                pass
            url_before = page.url
            html = await page.content()
            await page.wait_for_timeout(200)
            if page.url == url_before:
                return html
        except PWError:
            await page.wait_for_timeout(250)
    return None


async def http_fallback(context, url: str, timeout: int = 45000) -> Optional[str]:
    try:
        r = await context.request.get(url, timeout=timeout)
        if r.ok:
            return await r.text()
    except Exception:
        pass
    return None

_DEAD_HOSTS: set[str] = set()


def _classify_net_error(exc: Exception) -> str:
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


async def fetch_url(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    """Fetch a URL; only render with Playwright for likely-HTML that responds.
    All failures/skips are logged at DEBUG so they don't clutter stdout."""
    try:
        if should_skip_url_by_path(url):
            logger.debug("Skipping by path/extension: %s", url)
            return None

        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host in _DEAD_HOSTS:
            logger.debug("Skipping %s (host marked dead)", url)
            return None

        # HEAD preflight
        content_type = None
        content_disp = None
        try:
            async with session.head(url, allow_redirects=True, timeout=10) as resp:
                content_type = resp.headers.get("Content-Type", "")
                content_disp = resp.headers.get("Content-Disposition", "")
                if resp.status >= 400:
                    logger.debug("Skip: %s returned %s on HEAD",
                                 url, resp.status)
                    return None
        except Exception as exc:
            reason = _classify_net_error(exc)
            logger.debug("Skip: %s on HEAD %s", reason, url)
            if reason == "refused" and host:
                _DEAD_HOSTS.add(host)
            return None

        if content_disp and "attachment" in content_disp.lower():
            logger.debug("Skipping by Content-Disposition attachment: %s", url)
            return None

        if content_type and not is_probably_html(content_type):
            if content_type.lower().startswith("text/") or content_type.lower().startswith("application/javascript"):
                try:
                    async with session.get(url, allow_redirects=True, timeout=20) as resp:
                        if resp.status < 400:
                            return await resp.text(errors="replace")
                        logger.debug("Skip: GET %s returned %s",
                                     url, resp.status)
                        return None
                except Exception as exc:
                    logger.debug("GET failed for text asset %s: %s", url, exc)
            return None

        if not content_type:
            try:
                async with session.get(url, allow_redirects=True, timeout=15) as resp:
                    if resp.status >= 400:
                        logger.debug("Skip: %s returned %s on GET",
                                     url, resp.status)
                        return None
                    sniff = resp.headers.get("Content-Type", "")
                    if sniff and not is_probably_html(sniff):
                        if sniff.lower().startswith("text/") or sniff.lower().startswith("application/javascript"):
                            return await resp.text(errors="replace")
                        return None
            except Exception as exc:
                reason = _classify_net_error(exc)
                logger.debug("Skip: %s on GET %s", reason, url)
                if reason == "refused" and host:
                    _DEAD_HOSTS.add(host)
                return None

        # Playwright only for cooperative HTML
        logger.debug("Rendering (HTML): %s", url)
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context(ignore_https_errors=True, bypass_csp=True)
                page = await context.new_page()
                await page.route("**/*", lambda route: (
                    route.abort() if route.request.resource_type in {
                        "image", "media", "font"} else route.continue_()
                ))
                try:
                    await page.goto(url, timeout=45000, wait_until="domcontentloaded")
                except PWError as exc:
                    reason = _classify_net_error(exc)
                    logger.debug("Browser skip: %s at %s", reason, url)
                    if reason == "refused" and host:
                        _DEAD_HOSTS.add(host)
                    return None

                html = await get_stable_content(page, total_ms=8000)
                if html:
                    return html

                html = await http_fallback(context, page.url)
                if html:
                    return html

                try:
                    return await page.content()
                except PWError:
                    return None
            finally:
                await browser.close()
    except Exception as e:
        # Unexpected exceptions only — still keep them at DEBUG per your preference
        reason = _classify_net_error(e)
        logger.debug("Fetch error (%s) at %s: %s", reason, url, e)
        return None


# ---------------------- Extraction helpers ----------------------

EMAIL_IGNORE_EXTS = (
    "png", "jpg", "jpeg", "gif", "svg", "bmp", "webp", "ico",
    "css", "js", "json", "xml", "csv", "txt", "pdf",
    "doc", "docx", "xls", "xlsx",
)

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?!(?:" +
    "|".join(EMAIL_IGNORE_EXTS) + r")\b)[a-zA-Z]{2,}"
)

PHONE_RE = re.compile(r"\+?\d[\d\s()\-]{6,}\d")

_TLD_TO_REGION: Dict[str, str] = {
    "gr": "GR", "us": "US", "uk": "GB", "gb": "GB", "de": "DE", "fr": "FR", "it": "IT", "es": "ES", "pt": "PT", "nl": "NL",
    "be": "BE", "se": "SE", "no": "NO", "fi": "FI", "dk": "DK", "pl": "PL", "cz": "CZ", "sk": "SK", "hu": "HU", "ro": "RO",
    "bg": "BG", "at": "AT", "ch": "CH", "ie": "IE", "tr": "TR", "ua": "UA", "ru": "RU", "il": "IL", "ca": "CA", "au": "AU",
    "nz": "NZ", "mx": "MX", "br": "BR", "ar": "AR", "cl": "CL", "co": "CO", "za": "ZA", "in": "IN", "sg": "SG", "hk": "HK",
    "tw": "TW", "jp": "JP", "kr": "KR", "my": "MY", "id": "ID", "th": "TH", "ph": "PH", "vn": "VN",
}


def _guess_region_from_domain(domain: str) -> Optional[str]:
    tld = domain.rsplit(".", 1)[-1].lower()
    return _TLD_TO_REGION.get(tld)


def _clean_angle_brackets(s: str) -> str:
    s = s.strip()
    if s.startswith("<") and s.endswith(">"):
        return s[1:-1]
    return s


def normalize_email(email: str) -> Optional[str]:
    """Validate and normalize an email; canonical form is lower-case for dedup."""
    # strip wrappers and decode percent encodings
    cleaned = _clean_angle_brackets(
        unquote(email.strip().strip("'").strip('"')))
    try:
        # Lower-case entire address so case-variants collapse
        valid = validate_email(cleaned.lower(), check_deliverability=True)
        return valid.normalized.lower()
    except EmailNotValidError as exc:
        logger.debug("Email validation failed for %s: %s", email, exc)
        return None


def normalize_phone(phone: str, default_region: Optional[str] = None) -> Optional[str]:
    """
    Return phone in national digits-only if valid (>=7 digits). Tries E.164 and region fallback.
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
    """
    Extract one or more email addresses from a mailto: URL.
    Handles forms like:
      mailto:user@example.com
      mailto://user@example.com
      mailto:?to=user@example.com&cc=a@b.com;b@c.com
    """
    out: List[str] = []
    try:
        # Normalize prefix and strip scheme
        h = href.strip()
        if not h.lower().startswith("mailto:"):
            return out
        rest = h.split(":", 1)[1]
        if rest.startswith("//"):
            rest = rest.lstrip("/")  # handle 'mailto://user@...'
        # Split address part and query
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
    # Clean up empties/whitespace
    return [a.strip() for a in out if a and a.strip()]


def _extract_tel_numbers(href: str) -> List[str]:
    """
    Extract a phone string from tel: URL.
    Handles tel:+123..., tel://+123..., and strips query.
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
    """Asynchronous breadth-first crawler limited to the target domain."""

    def __init__(self, domain: str, max_depth: int = 3, concurrency: int = 5):
        self.domain = domain
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.visited: Set[str] = set()
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
        logger.debug(
            "Initializing internal crawler for https://%s (org=%s)",
            domain, self._org or "?"
        )

    def add_email(self, email: str, source: str, snippet: str = "") -> None:
        """Store email (org-scope filtered) and log discovery once unless verbose."""
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

        # kept: identical INFO logs as before
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
        norm = normalize_phone(phone, self.default_region)
        if norm:
            is_new = norm not in self.phones
            if is_new:
                self.phones[norm] = norm
                self.phone_sources[norm] = source
                logger.info("Found phone: %s (source: %s)", norm, source)
            else:
                logger.debug(
                    "Duplicate phone: %s (new source: %s)", norm, source)
            if logger.isEnabledFor(logging.DEBUG) and snippet:
                logger.debug("Phone snippet: %s",
                             " ".join(snippet.strip().split()))

    async def crawl(self, start_url: str):
        """Breadth-first crawl starting from the supplied URL."""
        logger.debug("Starting the inner crawler at %s", start_url)
        queue = deque([(start_url, 0)])
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(
            limit=self.concurrency, family=socket.AF_INET, ttl_dns_cache=60)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            while queue:
                tasks = []
                while queue and len(tasks) < self.concurrency:
                    url, depth = queue.popleft()
                    if depth > self.max_depth or url in self.visited:
                        continue
                    self.visited.add(url)
                    tasks.append(self._process_url(session, url, depth, queue))
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=False)

    async def _process_url(self, session: aiohttp.ClientSession, url: str, depth: int, queue: deque):
        logger.debug("Crawling %s (depth: %d)", url, depth)
        content = await fetch_url(session, url)
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

        # Follow in-scope links
        for link in soup.find_all("a", href=True):
            new_url = urljoin(url, link["href"])
            parsed = urlparse(new_url)
            if parsed.scheme.startswith("http") and parsed.netloc.endswith(self.domain):
                if new_url not in self.visited and not should_skip_url_by_path(new_url):
                    queue.append((new_url, depth + 1))
                    logger.debug("Discovered link %s", new_url)

        # Crawl JS sources too
        for script in soup.find_all("script", src=True):
            src = urljoin(url, script["src"])
            parsed = urlparse(src)
            if parsed.scheme.startswith("http") and parsed.netloc.endswith(self.domain):
                if src not in self.visited and not should_skip_url_by_path(src):
                    queue.append((src, depth + 1))
                    logger.debug("Discovered script %s", src)

    def extract_data(self, text: str, url: str, *, allow_phones: bool = True):
        before_emails = len(self.emails)
        before_phones = len(self.phones)

        for m in EMAIL_RE.finditer(text):
            snippet = text[max(m.start()-20, 0): m.end()+20].replace("\n", " ")
            self.add_email(m.group(), url, snippet)

        if allow_phones:
            for m in PHONE_RE.finditer(text):
                snippet = text[max(m.start()-20, 0)
                                   : m.end()+20].replace("\n", " ")
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
    """Return list of breaches for an email using a HaveIBeenPwned proxy API."""
    if not api_key:
        return None

    url = f"http://83.212.80.246:8600/proxy/haveibeenpwned/{email}/"
    headers = {"Accept": "application/json",
               "Authorization": f"Api-Key {api_key}"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
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


_leakcheck_recent = deque()


def check_leakcheck_phone(phone: str, api_key: Optional[str]) -> Optional[List[str]]:
    """Return breach sources for a phone number using the LeakCheck v2 API."""
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
        resp = requests.get(url, headers=headers, params=params, timeout=10)
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
    """Persist scan results to disk and return the file path."""

    email_sources = results.get("email_sources", {})
    phone_sources = results.get("phone_sources", {})
    breached_emails = results.get("breached_emails", {})
    breached_phones = results.get("breached_phones", {})

    emails = []
    for email in sorted(results.get("emails", set())):
        emails.append(
            {
                "email": email,
                "source": email_sources.get(email, ""),
                "breaches": breached_emails.get(email, []),
            }
        )

    phones = []
    for phone in sorted(results.get("phones", set())):
        phones.append(
            {
                "phone": phone,
                "source": phone_sources.get(phone, ""),
                "breaches": breached_phones.get(phone, []),
            }
        )

    report = {
        "scan_domain": domain,
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "subdomains": sorted(results.get("subdomains", [])),
        "emails": emails,
        "phones": phones,
    }

    base = domain.replace("/", "_")
    timestamp = datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    if not output_path:
        output_path = f"{base}-{timestamp}.{fmt}"

    logger.info("Saving results to %s...", output_path)
    if fmt == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    elif fmt == "csv":
        import csv
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
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
) -> dict:
    """Crawl a domain and optionally check contacts against breach data."""
    start_time = time.time()
    logger.info("Starting scan for %s (depth: %d, concurrency: %d)",
                domain, depth, concurrency)

    stage = 1
    logger.info("Stage %d: Enumerating subdomains for %s", stage, domain)
    subs = enumerate_subdomains(domain)

    stage += 1
    logger.info(
        "Stage %d: Filtering %d subdomains for web accessibility...", stage, len(subs))
    subdomain_schemes = await filter_accessible_subdomains(subs, concurrency=concurrency, retries=1)
    logger.info("Found %d accessible web hosts.", len(subdomain_schemes))
    if verbose:
        logger.debug("%d of %d subdomains are accessible",
                     len(subdomain_schemes), len(subs))
        for sub in sorted(subdomain_schemes):
            logger.debug(" [+] %s", sub)

    logger.info("Using internal Python crawler.")
    crawler = Crawler(domain, max_depth=depth, concurrency=concurrency)

    stage += 1
    logger.info("Stage %d: Crawling %d URL(s) to find contacts...",
                stage, len(subdomain_schemes))
    for sub, scheme in subdomain_schemes.items():
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

    results = {
        "subdomains": set(subdomain_schemes.keys()),
        "emails": set(crawler.emails.values()),
        "phones": set(crawler.phones.values()),
        "breached_emails": breached_emails,
        "breached_phones": breached_phones,
        "email_sources": crawler.email_sources,
        "phone_sources": crawler.phone_sources,
    }

    duration = time.time() - start_time
    results["scan_duration"] = duration
    return results

# ---------------------- CLI ----------------------


def parse_args(default_depth: int) -> argparse.Namespace:
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

    results = await scan_domain(
        domain_norm,
        args.depth,
        hibp_key,
        leak_key,
        verbose=args.verbose,
        concurrency=args.concurrency,
    )

    if args.csv:
        fmt = "csv"
    elif args.md:
        fmt = "md"
    else:
        fmt = "json"

    save_results(results, domain_norm, fmt=fmt, output_path=args.output)

    logging.info("%s", "=" * 60)
    logging.info("Scan Complete for %s in %.2f seconds.",
                 domain_norm, results.get("scan_duration", 0.0))
    logging.info(
        "Summary: Found %d subdomains, %d emails (%d breached), and %d phones (%d breached).",
        len(results["subdomains"]),
        len(results["emails"]),
        len(results["breached_emails"]),
        len(results["phones"]),
        len(results.get("breached_phones", {})),
    )
    logging.info("%s", "=" * 60)
    return results

if __name__ == "__main__":
    asyncio.run(main())
