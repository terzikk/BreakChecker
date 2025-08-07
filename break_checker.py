"""Domain crawler, subdomain enumerator and breach checker.

Usage:
  python3 break_checker.py [options] domain

The script now accepts command line arguments. API credentials and crawl depth
are loaded from ``config.json`` if present, falling back to environment variables:

  HIBP_API_KEY   - HaveIBeenPwned API key
  CRAWL_DEPTH    - Maximum crawl depth (default 3)

Create ``config.json`` in the same directory with keys ``hibp_api_key`` and
``crawl_depth`` to avoid setting environment variables each run. If the
``katana`` command is available it will be used for deeper and faster crawling. Katana
collects additional URLs which are then processed by this script.

Command line options:
  -d, --depth        Maximum crawl depth
  -v, --verbose      Enable debug logging
  -j, --json         Save results as DOMAIN-TIMESTAMP.json
  --csv             Save results as DOMAIN-TIMESTAMP.csv
  --md, --report    Save results as DOMAIN-TIMESTAMP.md
  -c, --concurrency  Number of concurrent workers
"""

# This script gathers subdomains for a target domain, crawls each host for
# contact information such as emails and phone numbers, and optionally checks
# discovered emails against public breach data. Emails are deduplicated
# case-insensitively but saved exactly as found. Phone numbers are validated
# and stored in a normalized E.164 format for easier processing.


import os
import re
import sys
import json
import argparse
import asyncio
import logging
from logging.handlers import RotatingFileHandler
import time
from urllib.parse import urljoin, urlparse
from collections import deque
import datetime
import phonenumbers
import requests
from bs4 import BeautifulSoup
import shutil
import subprocess
from typing import Set, List, Optional, Dict, Tuple
import aiohttp
from playwright.async_api import async_playwright
from email_validator import validate_email, EmailNotValidError
import socket


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure root logging and return module logger."""
    log_file = os.environ.get("BREACH_LOG_FILE", "break_checker.log")
    root_logger = logging.getLogger()
    # Remove all handlers before adding new ones to avoid duplicates
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_file, maxBytes=1_000_000, backupCount=3)
    stream_handler = logging.StreamHandler()

    for handler in (file_handler, stream_handler):
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    root_logger.setLevel(level)
    # Verbose HTTP connection logs when debugging
    logging.getLogger("urllib3").setLevel(level)
    return logging.getLogger(__name__)


logger = configure_logging()


# Standard library modules provide URL handling and queues while
# requests/BeautifulSoup handle HTTP fetching and parsing. "subprocess" is
# used to call external enumeration tools when available.

# ---------------------- Helper functions ----------------------


def load_config() -> dict:
    """Load optional API keys and settings from config.json."""
    config = {
        "hibp_api_key": None,
        "leakcheck_api_key": None,
        "crawl_depth": 3,
    }
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                config.update({k: v for k, v in data.items() if v})
            logger.debug("Loaded configuration from config.json")
    except Exception as exc:
        # Missing or invalid config is silently ignored
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

    host = host.strip('.').lower()
    if not host:
        return False, "", "No domain provided"

    try:
        host_ascii = host.encode("idna").decode("ascii")
    except Exception:
        return False, "", "Invalid internationalized domain"

    if len(host_ascii) > 253:
        return False, "", "Domain exceeds maximum length"

    labels = host_ascii.split('.')
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


def enumerate_subdomains(domain: str) -> Set[str]:
    """Enumerate subdomains using subfinder if available or multiple free sources as fallback.

    Wildcard entries like ``*.example.com`` are stripped of the ``*`` to avoid
    invalid hostnames being crawled.
    """
    logger.info("Enumerating subdomains for %s", domain)
    subs = set()

    # Try the "subfinder" tool first as it is fast and comprehensive
    if shutil.which("subfinder"):
        try:
            logger.debug("Running subfinder for %s", domain)
            result = subprocess.run([
                "subfinder",
                "-silent",
                "-d",
                domain,
            ], capture_output=True, text=True, check=False, timeout=60)
            subs.update(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
            logger.debug("subfinder returned %d subdomains", len(subs))
        except Exception as exc:
            # Ignore failures and fall back to web-based enumeration
            logger.info("subfinder failed: %s", exc)

    # Use multiple free sources as fallback or supplement
    if not subs:
        logger.debug(
            "Subfinder wasn't found, querying API sources...")
        # Primary: crt.sh
        try:
            logger.debug("Querying crt.sh for subdomains.")
            url = f"https://crt.sh/json?q={domain}"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if '*' in sub:
                            sub = sub.lstrip('*.')
                        if sub and sub.endswith(domain):
                            subs.add(sub)
                logger.debug("crt.sh returned %d subdomains", len(subs))
            else:
                logger.debug("crt.sh returned status %d.", resp.status_code)
        except Exception as exc:
            logger.debug("crt.sh lookup failed: %s", exc)

        # Supplement 1: HackerTarget
        try:
            logger.debug("Querying HackerTarget for subdomains.")
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                hackertarget_count = 0
                for line in resp.text.splitlines():
                    if "," in line:
                        subdomain = line.split(",")[0].strip().lower()
                        if subdomain.endswith(domain) and subdomain not in subs:
                            subs.add(subdomain)
                            hackertarget_count += 1
                logger.debug("HackerTarget added %d new subdomains",
                             hackertarget_count)
            else:
                logger.debug("HackerTarget returned status %d.",
                             resp.status_code)
        except Exception as exc:
            logger.debug("HackerTarget lookup failed: %s", exc)

        # Supplement 2: Anubis-DB
        try:
            logger.debug("Querying Anubis-DB for subdomains.")
            url = f"https://anubisdb.com/anubis/subdomains/{domain}"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                anubis_count = 0
                for subdomain in data:
                    subdomain = subdomain.strip().lower()
                    if subdomain.endswith(domain) and subdomain not in subs:
                        subs.add(subdomain)
                        anubis_count += 1
                logger.debug("Anubis added %d new subdomains", anubis_count)
            else:
                logger.debug("Anubis-DB returned status %d.", resp.status_code)
        except Exception as exc:
            logger.debug("Anubis lookup failed: %s", exc)

    # Always include main domain
    subs.add(domain)
    logger.info("Found %d subdomains for %s", len(subs), domain)
    return subs


async def choose_scheme(session: aiohttp.ClientSession, host: str) -> Optional[str]:
    """Asynchronously return the reachable scheme for *host* or ``None`` if unreachable."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            async with session.head(url, allow_redirects=True) as resp:
                if resp.status < 400:
                    logger.debug("%s is reachable via %s", host, scheme)
                    return scheme
        except Exception as exc:
            logger.debug("Error checking %s via %s: %s", host, scheme, exc)
            continue
    logger.debug("%s is not reachable via HTTP or HTTPS", host)
    return None


async def filter_accessible_subdomains(subdomains: Set[str], *, concurrency: int = 20) -> Dict[str, str]:
    """Return mapping of reachable subdomains to their scheme using asynchronous probes."""
    live: Dict[str, str] = {}
    timeout = aiohttp.ClientTimeout(total=5)
    connector = aiohttp.TCPConnector(limit=concurrency)
    hosts = list(subdomains)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = [choose_scheme(session, host) for host in hosts]
        results = await asyncio.gather(*tasks)

    for host, scheme in zip(hosts, results):
        if scheme:
            live[host] = scheme
        else:
            logger.debug("Removing unreachable subdomain: %s", host)

    logger.info("Accessible subdomains: %d of %d", len(live), len(subdomains))
    return live


def gather_with_katana(start_url: str, depth: int) -> Set[str]:
    """Run katana and return discovered URLs only."""
    if not shutil.which("katana"):
        return set()

    urls: Set[str] = set()

    cmd = [
        "katana",
        "-u",
        start_url,
        "-d",
        str(depth),
        "-silent",
        "-j",
    ]

    try:
        logger.info("Running katana against %s", start_url)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("katana non-json line: %s", line)
                continue

            endpoint = (
                data.get("url")
                or data.get("request", {}).get("endpoint")
                or start_url
            )
            if endpoint not in urls:
                urls.add(endpoint)
                logger.debug("katana scanned %s", endpoint)

        proc.wait(timeout=60 * depth)
        logger.debug("katana found %d urls", len(urls))
    except Exception as exc:
        logger.warning("katana execution failed: %s", exc)

    return urls


async def fetch_url(session, url: str) -> Optional[str]:
    """Fetch a URL using Playwright (for JavaScript-rendered content)."""
    try:
        logger.debug("Launching browser to fetch %s...", url)
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, timeout=20000)
            content = await page.content()
            await browser.close()
            return content
    except Exception as e:
        logger.warning("Playwright error at %s: %s", url, e)
        return None

# Common file extensions that should not be treated as valid email TLDs.  These
# often appear in asset paths like ``image@2x.png`` and can be misdetected as
EMAIL_IGNORE_EXTS = (
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "bmp",
    "webp",
    "ico",
    "css",
    "js",
    "json",
    "xml",
    "csv",
    "txt",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
)

# Email regex with a negative lookahead so addresses ending with the above
# extensions are ignored.
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?!(?:"
    + "|".join(EMAIL_IGNORE_EXTS)
    + r")\b)[a-zA-Z]{2,}"
)
PHONE_RE = re.compile(r"\+?\d[\d\s()\-]{6,}\d")


def normalize_email(email: str) -> Optional[str]:
    """Validate and normalize an email address after regex extraction.

    Using ``email-validator`` catches syntactic errors and domains that do
    not exist, providing a second layer of validation for higher accuracy.
    """
    try:
        valid = validate_email(email, check_deliverability=True)
        return valid.normalized
    except EmailNotValidError as exc:
        logger.debug("Email validation failed for %s: %s", email, exc)
        return None


def normalize_phone(phone: str) -> Optional[str]:
    """Return the phone number in local format if it appears valid."""
    try:
        parsed = phonenumbers.parse(phone, None)
        if phonenumbers.is_valid_number(parsed):
            # Get the national significant number without spaces
            local = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            digits_only = ''.join(filter(str.isdigit, local))
            return digits_only
    except phonenumbers.NumberParseException:
        pass
    return None


class Crawler:
    """Simple asynchronous breadth-first crawler limited to the target domain."""

    def __init__(self, domain: str, max_depth: int = 3, concurrency: int = 5):
        # Domain suffix used to restrict crawling
        self.domain = domain
        # Maximum link depth to follow
        self.max_depth = max_depth
        # How many fetches to run concurrently
        self.concurrency = concurrency
        # Track visited URLs to avoid loops
        self.visited: Set[str] = set()
        # Containers for discovered data (canonical -> original)
        self.emails: dict[str, str] = {}
        self.phones: dict[str, str] = {}
        # Maps for the first seen location of each item
        self.email_sources: dict[str, str] = {}
        self.phone_sources: dict[str, str] = {}

        logger.debug(
            "Initializing internal crawler for https://%s", domain
        )

    def add_email(self, email: str, source: str, snippet: str = "") -> None:
        """Store email and log discovery once unless verbose."""
        canon = normalize_email(email)
        if not canon:
            return
        trimmed_snippet = " ".join(snippet.strip().split())
        is_new = canon not in self.emails
        if is_new:
            self.emails[canon] = canon
            self.email_sources[canon] = source
            logger.info(
                "Found email: %s (source: %s)", canon, source
            )
        else:
            logger.debug(
                "Duplicate email found: %s (new source: %s)", canon, source
            )
        if logger.isEnabledFor(logging.DEBUG) and trimmed_snippet:
            logger.debug("Email snippet: %s", trimmed_snippet)

    def add_phone(self, phone: str, source: str, snippet: str = "") -> None:
        """Store phone and log once unless verbose."""
        norm = normalize_phone(phone)

        if norm:
            trimmed_snippet = " ".join(snippet.strip().split())
            is_new = norm not in self.phones
            if is_new:
                self.phones[norm] = norm
                self.phone_sources[norm] = source
                logger.info(
                    "Found phone: %s (source: %s)", norm, source
                )
            else:
                logger.debug(
                    "Duplicate phone found: %s (new source: %s)", norm, source
                )
            if logger.isEnabledFor(logging.DEBUG) and trimmed_snippet:
                logger.debug("Phone snippet: %s", trimmed_snippet)

    async def crawl(self, start_url: str):
        """Breadth-first crawl starting from the supplied URL."""
        logger.debug("Starting the inner crawler at %s", start_url)
        queue = deque([(start_url, 0)])
        async with aiohttp.ClientSession() as session:
            while queue:
                tasks = []
                while queue and len(tasks) < self.concurrency:
                    url, depth = queue.popleft()
                    if depth > self.max_depth or url in self.visited:
                        continue
                    self.visited.add(url)
                    logger.debug("Queueing %s (depth %d)", url, depth)
                    tasks.append(self._process_url(session, url, depth, queue))
                if tasks:
                    await asyncio.gather(*tasks)

    async def _process_url(self, session: aiohttp.ClientSession, url: str, depth: int, queue: deque):
        logger.debug("Crawling %s (depth: %d)", url, depth)
        content = await fetch_url(session, url)
        if not content:
            return
        logger.debug("Extracting contact data from %s", url)
        self.extract_data(content, url)
        soup = BeautifulSoup(content, "html.parser")
        # also search the rendered text for emails split by HTML tags
        self.extract_data(soup.get_text(" "), url)
        # capture mailto: links explicitly (case-insensitive)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.lower().startswith("mailto:"):
                addr = href.split(":", 1)[1].split("?", 1)[0].strip()
                if addr:
                    snippet = f"mailto:{addr}"
                    self.add_email(addr, url, snippet)
        for link in soup.find_all("a", href=True):
            new_url = urljoin(url, link["href"])
            parsed = urlparse(new_url)
            if parsed.scheme.startswith("http") and parsed.netloc.endswith(self.domain):
                if new_url not in self.visited:
                    queue.append((new_url, depth + 1))
                    logger.debug("Discovered link %s", new_url)
        # also crawl JS sources so we don't miss inline references
        for script in soup.find_all("script", src=True):
            src = urljoin(url, script["src"])
            parsed = urlparse(src)
            if parsed.scheme.startswith("http") and parsed.netloc.endswith(self.domain):
                if src not in self.visited:
                    queue.append((src, depth + 1))
                    logger.debug("Discovered script %s", src)

    def extract_data(self, text: str, url: str):
        """Pull data of interest out of page text."""
        email_matches = list(EMAIL_RE.finditer(text))
        phone_matches = list(PHONE_RE.finditer(text))
        for m in email_matches:
            snippet = text[max(m.start()-20, 0): m.end()+20].replace("\n", " ")
            self.add_email(m.group(), url, snippet)
        for m in phone_matches:
            snippet = text[max(m.start()-20, 0): m.end()+20].replace("\n", " ")
            self.add_phone(m.group(), url, snippet)
        if email_matches or phone_matches:
            logger.debug(
                "Extracted %d emails and %d phones", len(
                    email_matches), len(phone_matches)
            )


# ---------------------- Breach checkers ----------------------

def check_hibp(email: str, api_key: Optional[str]) -> Optional[List[str]]:
    """
    Return list of breaches for an email using a HaveIBeenPwned proxy API.
    """
    if not api_key:
        return None

    url = f"http://83.212.80.246:8600/proxy/haveibeenpwned/{email}/"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Api-Key {api_key}"
    }
    try:
        logger.debug("Checking HIBP proxy for %s", email)
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            breaches = [b.get("Name") for b in resp.json()]
            if breaches:
                logger.warning(
                    "BREACH (HIBP): %s is in %d breach(es).",
                    email,
                    len(breaches),
                )
            else:
                logger.info(
                    "OK (HIBP): %s was not found in any breaches.", email)
            time.sleep(6)
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


# Track timestamps of recent LeakCheck requests to enforce local rate limits
_leakcheck_recent = deque()


def check_leakcheck_phone(phone: str, api_key: Optional[str]) -> Optional[List[str]]:
    """Return breach sources for a phone number using the LeakCheck v2 API."""
    if not api_key:
        return None

    # Enforce a local rate limit of 3 queries per second
    now = time.time()
    while _leakcheck_recent and now - _leakcheck_recent[0] >= 1.2:
        _leakcheck_recent.popleft()
    if len(_leakcheck_recent) >= 3:
        sleep_for = 1.2 - (now - _leakcheck_recent[0])
        logger.debug(
            "LeakCheck local rate limit reached, sleeping %.2fs", sleep_for
        )
        time.sleep(max(0, sleep_for))
    _leakcheck_recent.append(time.time())

    url = f"https://leakcheck.io/api/v2/query/{phone}"
    headers = {"Accept": "application/json", "X-API-Key": api_key}
    params = {"type": "phone"}
    try:
        logger.debug("Checking LeakCheck for %s", phone)
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
                        "BREACH (LeakCheck): %s is in %d breach(es).",
                        phone,
                        len(sources),
                    )
                    return sources
                logger.info(
                    "OK (LeakCheck): %s was not found in any breaches.", phone
                )
                return []
        if resp.status_code == 429:
            logger.warning("LeakCheck rate limit hit. Sleeping for 10s.")
            time.sleep(10)
            return None
        logger.warning(
            "Unexpected LeakCheck response: %s %s", resp.status_code, resp.text
        )
    except Exception as exc:
        logger.warning("LeakCheck lookup failed for %s: %s", phone, exc)
    return None


def save_results(
    results: dict,
    domain: str,
    *,
    fmt: str = "json",
    output_path: str | None = None,
) -> str:
    """Persist scan results to disk and return the file path."""

    crawler = results.get("crawler")
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
        "scan_time": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
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
                    [
                        "email",
                        item["email"],
                        item["source"],
                        ", ".join(item["breaches"]),
                    ]
                )
            for item in phones:
                writer.writerow(
                    [
                        "phone",
                        item["phone"],
                        item["source"],
                        ", ".join(item["breaches"]),
                    ]
                )
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
            breaches = ", ".join(item["breaches"])
            lines.append(
                f"| {item['email']} | {item['source']} | {breaches} |")
        lines.append("")
        lines.append("## Phones")
        lines.append("| Phone | Source | Breaches |")
        lines.append("| --- | --- | --- |")
        for item in phones:
            breaches = ", ".join(item["breaches"])
            lines.append(
                f"| {item['phone']} | {item['source']} | {breaches} |")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    else:
        raise ValueError(f"Unknown format: {fmt}")

    logger.debug("Results successfully saved to %s", output_path)

    return output_path

# ---------------------- High level scan function ----------------------


async def scan_domain(
    domain: str,
    depth: int = 3,
    hibp_key: Optional[str] = None,
    leakcheck_key: Optional[str] = None,
    *,
    verbose: bool = False,
    concurrency: int = 5,
) -> dict:
    """Crawl a domain and optionally check emails against HIBP.

    The returned dictionary now exposes the discovered subdomains, emails and
    phone numbers directly so callers like the microservice can easily
    serialize the data as JSON.
    """
    start_time = time.time()
    logger.info(
        "Starting scan for %s (depth: %d, concurrency: %d)",
        domain,
        depth,
        concurrency,
    )

    stage = 1
    logger.info("Stage %d: Enumerating subdomains for %s", stage, domain)
    subs = enumerate_subdomains(domain)

    stage += 1
    logger.info(
        "Stage %d: Filtering %d subdomains for web accessibility...",
        stage,
        len(subs),
    )
    subdomain_schemes = await filter_accessible_subdomains(subs, concurrency=concurrency)
    logger.info("Found %d accessible web hosts.", len(subdomain_schemes))
    if verbose:
        logger.debug(
            "%d of %d subdomains are accessible", len(
                subdomain_schemes), len(subs)
        )
        for sub in sorted(subdomain_schemes):
            logger.debug(" [+] %s", sub)

    use_katana = shutil.which("katana") is not None
    if use_katana and verbose:
        logger.debug("Using katana for deep enumeration")
    if use_katana:
        logger.info("Using Katana crawler.")
    else:
        logger.info("Using internal Python crawler (Katana not found).")

    crawler = Crawler(
        domain, max_depth=0 if use_katana else depth, concurrency=concurrency)

    stage += 1
    logger.info(
        "Stage %d: Crawling %d URL(s) to find contacts...",
        stage,
        len(subdomain_schemes),
    )

    for sub, scheme in subdomain_schemes.items():
        start_url = f"{scheme}://{sub}"
        if verbose:
            logger.debug("Crawling %s", start_url)
        logger.info("Starting crawl at %s", start_url)
        if use_katana:
            urls = gather_with_katana(start_url, depth)
            if not urls:
                urls = {start_url}
            for link in urls:
                await crawler.crawl(link)
        else:
            await crawler.crawl(start_url)

    logger.info(
        "Crawl phase complete. Found %d emails and %d phone numbers.",
        len(crawler.emails),
        len(crawler.phones),
    )

    stage += 1
    breached_emails = {}
    logger.info("Stage %d: Checking %d emails for breaches via HIBP...",
                stage, len(crawler.emails))
    for email in crawler.emails.values():
        breaches = check_hibp(email, hibp_key)
        if breaches:
            breached_emails[email] = breaches

    stage += 1
    breached_phones = {}
    logger.info("Stage %d: Checking %d phone numbers for breaches via LeakCheck...",
                stage, len(crawler.phones))
    for phone in crawler.phones.values():
        breaches = check_leakcheck_phone(phone, leakcheck_key)
        if breaches:
            breached_phones[phone] = breaches

    results = {
        "crawler": crawler,
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


# ---------------------- Main logic ----------------------

def parse_args(default_depth: int) -> argparse.Namespace:
    """Return parsed command line arguments."""
    parser = argparse.ArgumentParser(
        description="Crawl a domain and check emails against breach data",
    )
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument(
        "-d",
        "--depth",
        type=int,
        default=default_depth,
        metavar="N",
        help="Maximum crawl depth (default: %(default)s)",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=5,
        metavar="N",
        help="Number of concurrent workers",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    fmt_group = parser.add_mutually_exclusive_group()
    fmt_group.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Save results as DOMAIN-TIMESTAMP.json (default)",
    )
    fmt_group.add_argument(
        "--csv",
        action="store_true",
        help="Save results as DOMAIN-TIMESTAMP.csv",
    )
    fmt_group.add_argument(
        "--md",
        "--report",
        dest="md",
        action="store_true",
        help="Save results as DOMAIN-TIMESTAMP.md markdown report",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file path",
        default=None,
    )
    return parser.parse_args()


async def main() -> dict:
    """Entry point for command line execution."""
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
    logging.info(
        "Scan Complete for %s in %.2f seconds.",
        domain_norm,
        results.get("scan_duration", 0.0),
    )
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


# Run when executed directly
if __name__ == "__main__":
    asyncio.run(main())
