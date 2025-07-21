"""Domain crawler, subdomain enumerator and breach checker.

Usage:
  python3 breach_checker.py

The script prompts for the target domain. API credentials and crawl depth are
loaded from ``config.json`` if present, falling back to environment variables:

  HIBP_API_KEY   - HaveIBeenPwned API key
  CRAWL_DEPTH    - Maximum crawl depth (default 3)

Create ``config.json`` in the same directory with keys ``hibp_api_key`` and
``crawl_depth`` to avoid setting environment variables each run. If the
``katana`` command is available it will be used for deeper crawling with the
regex rules from ``field-config.yaml``; its output is scanned for emails and
phone numbers as well as additional URLs before pages are processed by this
script.
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
import asyncio
import logging
from logging.handlers import RotatingFileHandler
from urllib.parse import urljoin, urlparse
from collections import deque
import phonenumbers
import requests
from bs4 import BeautifulSoup
import shutil
import subprocess
from typing import Set, List, Optional
import aiohttp
from playwright.async_api import async_playwright


def configure_logging() -> logging.Logger:
    """Configure root logging with rotation and console output."""
    log_file = os.environ.get("BREACH_LOG_FILE", "breach_checker.log")
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s:%(name)s:%(message)s")
        file_handler = RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=3)
        stream_handler = logging.StreamHandler()
        for handler in (file_handler, stream_handler):
            handler.setFormatter(formatter)
            root_logger.addHandler(handler)
        root_logger.setLevel(logging.INFO)
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


def enumerate_subdomains(domain: str) -> Set[str]:
    """Enumerate subdomains using subfinder if available or crt.sh fallback.

    Wildcard entries like ``*.example.com`` are stripped of the ``*`` to avoid
    invalid hostnames being crawled.
    """
    logger.info("Enumerating subdomains for %s", domain)
    subs = set()
    # Try the "subfinder" tool first as it is fast and comprehensive
    if shutil.which("subfinder"):
        try:
            result = subprocess.run([
                "subfinder",
                "-silent",
                "-d",
                domain,
            ], capture_output=True, text=True, check=False, timeout=60)
            subs.update(line.strip()
                        for line in result.stdout.splitlines() if line.strip())
            logger.debug("subfinder returned %d results", len(subs))
        except Exception as exc:
            # Ignore failures and fall back to web-based enumeration
            logger.debug("subfinder failed: %s", exc)
    # Fallback to crt.sh if none found
    if not subs:
        try:
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
        except Exception as exc:
            # Any network/JSON error simply results in returning the main domain
            logger.debug("crt.sh lookup failed: %s", exc)
    # Always include main domain
    subs.add(domain)
    logger.info("Found %d subdomains", len(subs))
    return subs


def choose_scheme(host: str) -> str:
    """Return 'https' if the host appears reachable via HTTPS, else 'http'."""
    for scheme in ("https", "http"):
        try:
            resp = requests.head(f"{scheme}://{host}",
                                 timeout=5, allow_redirects=True)
            if resp.status_code < 400:
                logger.debug("%s is reachable via %s", host, scheme)
                return scheme
        except Exception as exc:
            logger.debug("Error checking %s via %s: %s", host, scheme, exc)
            continue
    logger.debug("Defaulting to http for %s", host)
    return "http"


def gather_with_katana(start_url: str, depth: int, field_file: str):
    """Run katana and parse its output for URLs and data."""
    if not shutil.which("katana"):
        return set(), set(), set()

    urls: Set[str] = set()
    emails: Set[str] = set()
    phones: Set[str] = set()

    cmd = [
        "katana",
        "-u",
        start_url,
        "-d",
        str(depth),
        "-silent",
        "-f",
        "email,phone",
        "-flc",
        field_file,
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
            for u in URL_RE.findall(line):
                urls.add(u)
                logger.info("katana crawling %s", u)
            for email in EMAIL_RE.findall(line):
                emails.add(email.strip())
                logger.info("katana found email %s", email.strip())
            for phone in PHONE_RE.findall(line):
                phones.add(phone.strip())
                logger.info("katana found phone %s", phone.strip())
        proc.wait(timeout=60 * depth)
        logger.debug(
            "katana found %d urls, %d emails, %d phones", len(
                urls), len(emails), len(phones)
        )
    except Exception as exc:
        logger.warning("katana execution failed: %s", exc)

    return urls, emails, phones


async def fetch_url(session, url: str) -> Optional[str]:
    """Fetch a URL using Playwright (for JavaScript-rendered content)."""
    try:
        logger.info("Fetching %s", url)
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


# Regular expressions used during scraping
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
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


def normalize_email(email: str) -> str:
    """Return a canonical form of an email address for deduplication."""
    return email.strip().lower()


def normalize_phone(phone: str) -> Optional[str]:
    """Return the phone number in E.164 format if it appears valid."""
    try:
        parsed = phonenumbers.parse(phone, None)
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )
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

    def add_email(self, email: str, source: str, snippet: str = "") -> None:
        """Store email if not already seen (case-insensitive)."""
        canon = normalize_email(email)
        if canon not in self.emails:
            self.emails[canon] = email.strip()
            self.email_sources[canon] = source
        logger.info("Email %s found at %s | %s", email, source, snippet)

    def add_phone(self, phone: str, source: str, snippet: str = "") -> None:
        """Store phone in normalized form if valid and not already seen."""
        norm = normalize_phone(phone)

        if norm:
            if norm not in self.phones:
                self.phones[norm] = norm
                self.phone_sources[norm] = source
            logger.info("Phone %s found at %s | %s", norm, source, snippet)

    async def crawl(self, start_url: str):
        """Breadth-first crawl starting from the supplied URL."""
        logger.info("Starting crawl at %s", start_url)
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
        logger.info("Crawling %s", url)
        logger.debug("Processing %s", url)
        content = await fetch_url(session, url)
        if not content:
            return
        self.extract_data(content, url)
        soup = BeautifulSoup(content, "html.parser")
        # also search the rendered text for emails split by HTML tags
        self.extract_data(soup.get_text(" "), url)
        # capture mailto: links explicitly (case-insensitive)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.lower().startswith("mailto:"):
                addr = href.split(":", 1)[1].split("?", 1)[0]
                self.add_email(addr, url, "mailto link")
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
    """Return list of breaches for an email using HaveIBeenPwned."""
    if not api_key:
        return None
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "DomainCrawler/1.0",
    }
    try:
        logger.debug("Checking HIBP for %s", email)
        resp = requests.get(
            url, headers=headers, params={"truncateResponse": "false"}, timeout=10
        )
        if resp.status_code == 200:
            breaches = [b.get("Name") for b in resp.json()]
            logger.debug("%s found in %d breaches", email, len(breaches))
            return breaches
        if resp.status_code == 404:
            logger.debug("%s not found in HIBP", email)
            return []
    except Exception as exc:
        logger.warning("HIBP lookup failed for %s: %s", email, exc)
    return None


def save_results(results: dict) -> None:
    """Write emails, phones and their sources to output files."""
    crawler = results.get("crawler")
    emails = results.get("emails", set())
    phones = results.get("phones", set())
    email_sources = results.get("email_sources", {})
    phone_sources = results.get("phone_sources", {})
    breached_emails = results.get("breached_emails", {})

    def write_list(filename: str, data):
        with open(filename, "w", encoding="utf-8") as f:
            for item in sorted(data):
                f.write(str(item) + "\n")

    def write_map(filename: str, values: dict[str, str], sources: dict[str, str]):
        with open(filename, "w", encoding="utf-8") as f:
            for canon, value in sorted(values.items()):
                src = sources.get(canon, "")
                f.write(f"{value}\t{src}\n")

    if crawler:
        write_map("email_sources.txt", crawler.emails, email_sources)
        write_map("phone_sources.txt", crawler.phones, phone_sources)
    write_list("emails.txt", emails)
    write_list("phones.txt", phones)
    write_list("breached_emails.txt", breached_emails.keys())
    logger.info("Results written to output files")

# ---------------------- High level scan function ----------------------


async def scan_domain(domain: str, depth: int = 3, hibp_key: Optional[str] = None, *, verbose: bool = False) -> dict:
    """Crawl a domain and optionally check emails against HIBP.

    The returned dictionary now exposes the discovered subdomains, emails and
    phone numbers directly so callers like the microservice can easily
    serialize the data as JSON.
    """
    if verbose:
        print(f"Enumerating subdomains for {domain}...")
    logger.info("Scanning domain %s at depth %d", domain, depth)
    subdomains = enumerate_subdomains(domain)
    if verbose:
        for sub in sorted(subdomains):
            print(f" [+] {sub}")

    use_katana = shutil.which("katana") is not None
    field_file = os.path.join(os.path.dirname(__file__), "field-config.yaml")

    if use_katana and verbose:
        print("Using katana for deep enumeration")
    if use_katana:
        logger.info("katana available; using for enumeration")
    else:
        logger.info("katana not available; using internal crawler only")

    crawler = Crawler(domain, max_depth=0 if use_katana else depth)

    for sub in subdomains:
        scheme = choose_scheme(sub)
        start_url = f"{scheme}://{sub}"
        if verbose:
            print(f"\nCrawling {start_url} ...")
        logger.info("Crawling %s", start_url)
        if use_katana:
            urls, emails, phones = gather_with_katana(
                start_url, depth, field_file)
            for e in emails:
                crawler.add_email(e, start_url, "katana")
            for p in phones:
                crawler.add_phone(p, start_url, "katana")
            if not urls:
                urls = {start_url}
            for link in urls:
                await crawler.crawl(link)
        else:
            await crawler.crawl(start_url)

    breached_emails = {}
    for email in crawler.emails.values():
        breaches = check_hibp(email, hibp_key)
        if breaches:
            breached_emails[email] = breaches

    # Expose the collected data directly for easier consumption by callers.
    logger.info(
        "Scan complete: %d emails, %d phones, %d breached emails",
        len(crawler.emails),
        len(crawler.phones),
        len(breached_emails),
    )
    results = {
        "crawler": crawler,
        "subdomains": subdomains,
        "emails": set(crawler.emails.values()),
        "phones": set(crawler.phones.values()),
        "breached_emails": breached_emails,
        "email_sources": crawler.email_sources,
        "phone_sources": crawler.phone_sources,
    }

    save_results(results)
    return results


# ---------------------- Main logic ----------------------

async def main():
    """Entry point for command line execution."""
    # ---- domain prompt ----
    domain = input("Enter domain name (e.g., example.com): ").strip()
    if not domain:
        print("No domain provided. Exiting.")
        sys.exit(1)

    # ---- load optional settings from config file and environment ----
    cfg = load_config()
    depth = int(os.environ.get("CRAWL_DEPTH", cfg.get("crawl_depth", 3)))
    hibp_key = os.environ.get("HIBP_API_KEY") or cfg.get("hibp_api_key")
    logger.debug("Using crawl depth %d", depth)

    results = await scan_domain(domain, depth, hibp_key, verbose=True)
    subdomains = results["subdomains"]
    emails = results["emails"]
    phones = results["phones"]
    breached_emails = results["breached_emails"]

    # ---- print summary to console ----
    print("\n--------- Summary ---------")
    print(f"Emails found: {len(emails)}")
    print(f"Breached emails: {len(breached_emails)}")
    print(f"Phone numbers found: {len(phones)}")

    if breached_emails:
        print("\nBreached Emails:")
        for email, breaches in breached_emails.items():
            print(f" - {email}: {', '.join(breaches)}")

    print("\nResults saved to emails.txt, breached_emails.txt, phones.txt")
    logger.info("Summary: %d emails, %d phones, %d breached",
                len(emails), len(phones), len(breached_emails))

    # ---- return results so callers can use them ----
    return results


# Run when executed directly
if __name__ == "__main__":
    results = asyncio.run(main())
