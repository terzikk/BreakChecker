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
from urllib.parse import urljoin, urlparse
from collections import deque
import phonenumbers
import requests
from bs4 import BeautifulSoup
import shutil
import subprocess
from typing import Set, List, Optional
import aiohttp

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
    except Exception:
        # Missing or invalid config is silently ignored
        pass
    return config


def enumerate_subdomains(domain: str) -> Set[str]:
    """Enumerate subdomains using subfinder if available or crt.sh fallback.

    Wildcard entries like ``*.example.com`` are stripped of the ``*`` to avoid
    invalid hostnames being crawled.
    """
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
        except Exception:
            # Ignore failures and fall back to web-based enumeration
            pass
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
        except Exception:
            # Any network/JSON error simply results in returning the main domain
            pass
    # Always include main domain
    subs.add(domain)
    return subs


def choose_scheme(host: str) -> str:
    """Return 'https' if the host appears reachable via HTTPS, else 'http'."""
    for scheme in ("https", "http"):
        try:
            resp = requests.head(f"{scheme}://{host}",
                                 timeout=5, allow_redirects=True)
            if resp.status_code < 400:
                return scheme
        except Exception:
            continue
    return "http"


def gather_with_katana(start_url: str, depth: int, field_file: str):
    """Run katana and parse its output for URLs and data."""
    if not shutil.which("katana"):
        return set(), set(), set()

    urls: Set[str] = set()
    emails: Set[str] = set()
    phones: Set[str] = set()

    try:
        result = subprocess.run(
            [
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
            ],
            capture_output=True,
            text=True,
            timeout=60 * depth,
            check=False,
        )
        output = result.stdout
        urls.update(URL_RE.findall(output))
        for email in EMAIL_RE.findall(output):
            emails.add(email.strip())
        for phone in PHONE_RE.findall(output):
            phones.add(phone.strip())
    except Exception:
        pass

    return urls, emails, phones


async def fetch_url(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    """Fetch a URL and return text content for HTML, JS or plain text pages."""
    try:
        async with session.get(url, timeout=10, allow_redirects=True) as resp:
            if resp.status == 200 and any(
                resp.headers.get("content-type", "").startswith(t)
                for t in ["text/html", "text/plain", "application/javascript"]
            ):
                return await resp.text()
    except Exception:
        # Network errors are ignored to keep crawling resilient
        pass
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

    def add_email(self, email: str) -> None:
        """Store email if not already seen (case-insensitive)."""
        canon = normalize_email(email)
        if canon not in self.emails:
            self.emails[canon] = email.strip()

    def add_phone(self, phone: str) -> None:
        """Store phone in normalized form if valid and not already seen."""
        norm = normalize_phone(phone)
        if norm and norm not in self.phones:
            self.phones[norm] = norm

    async def crawl(self, start_url: str):
        """Breadth-first crawl starting from the supplied URL."""
        queue = deque([(start_url, 0)])
        async with aiohttp.ClientSession() as session:
            while queue:
                tasks = []
                while queue and len(tasks) < self.concurrency:
                    url, depth = queue.popleft()
                    if depth > self.max_depth or url in self.visited:
                        continue
                    self.visited.add(url)
                    tasks.append(self._process_url(session, url, depth, queue))
                if tasks:
                    await asyncio.gather(*tasks)

    async def _process_url(self, session: aiohttp.ClientSession, url: str, depth: int, queue: deque):
        content = await fetch_url(session, url)
        if not content:
            return
        self.extract_data(content)
        soup = BeautifulSoup(content, "html.parser")
        # also search the rendered text for emails split by HTML tags
        self.extract_data(soup.get_text(" "))
        # capture mailto: links explicitly (case-insensitive)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.lower().startswith("mailto:"):
                addr = href.split(":", 1)[1].split("?", 1)[0]
                self.add_email(addr)
        for link in soup.find_all("a", href=True):
            new_url = urljoin(url, link["href"])
            parsed = urlparse(new_url)
            if parsed.scheme.startswith("http") and parsed.netloc.endswith(self.domain):
                if new_url not in self.visited:
                    queue.append((new_url, depth + 1))
        # also crawl JS sources so we don't miss inline references
        for script in soup.find_all("script", src=True):
            src = urljoin(url, script["src"])
            parsed = urlparse(src)
            if parsed.scheme.startswith("http") and parsed.netloc.endswith(self.domain):
                if src not in self.visited:
                    queue.append((src, depth + 1))

    def extract_data(self, text: str):
        """Pull data of interest out of page text."""
        for email in EMAIL_RE.findall(text):
            self.add_email(email)
        for phone in PHONE_RE.findall(text):
            self.add_phone(phone)


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
        resp = requests.get(
            url, headers=headers, params={"truncateResponse": "false"}, timeout=10
        )
        if resp.status_code == 200:
            return [b.get("Name") for b in resp.json()]
        if resp.status_code == 404:
            return []
    except Exception:
        pass
    return None

# ---------------------- High level scan function ----------------------


async def scan_domain(domain: str, depth: int = 3, hibp_key: Optional[str] = None, *, verbose: bool = False) -> dict:
    """Crawl a domain and optionally check emails against HIBP.

    The returned dictionary now exposes the discovered subdomains, emails and
    phone numbers directly so callers like the microservice can easily
    serialize the data as JSON.
    """
    if verbose:
        print(f"Enumerating subdomains for {domain}...")
    subdomains = enumerate_subdomains(domain)
    if verbose:
        for sub in sorted(subdomains):
            print(f" [+] {sub}")

    use_katana = shutil.which("katana") is not None
    field_file = os.path.join(os.path.dirname(__file__), "field-config.yaml")

    if use_katana and verbose:
        print("Using katana for deep enumeration")

    crawler = Crawler(domain, max_depth=0 if use_katana else depth)

    for sub in subdomains:
        scheme = choose_scheme(sub)
        start_url = f"{scheme}://{sub}"
        if verbose:
            print(f"\nCrawling {start_url} ...")
        if use_katana:
            urls, emails, phones = gather_with_katana(
                start_url, depth, field_file)
            for e in emails:
                crawler.add_email(e)
            for p in phones:
                crawler.add_phone(p)
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
    return {
        "crawler": crawler,
        "subdomains": subdomains,
        "emails": set(crawler.emails.values()),
        "phones": set(crawler.phones.values()),
        "breached_emails": breached_emails,
    }


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

    results = await scan_domain(domain, depth, hibp_key, verbose=True)
    subdomains = results["subdomains"]
    emails = results["emails"]
    phones = results["phones"]
    breached_emails = results["breached_emails"]
    # ---- write results to files ----

    def save_set(filename: str, data: Set[str]):
        with open(filename, "w", encoding="utf-8") as f:
            for item in sorted(data):
                f.write(item + "\n")

    save_set("emails.txt", emails)
    save_set("phones.txt", phones)
    save_set("breached_emails.txt", set(breached_emails.keys()))

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

    # ---- return results so callers can use them ----
    return results


# Run when executed directly
if __name__ == "__main__":
    results = asyncio.run(main())
