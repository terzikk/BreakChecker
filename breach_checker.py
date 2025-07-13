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
# discovered emails against public breach data. All emails and phone numbers
# are normalized and deduplicated before breach checks and saving to disk.


import os
import re
import sys
import json
import asyncio
from urllib.parse import urljoin, urlparse
from collections import deque
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
    """Enumerate subdomains using subfinder if available or crt.sh fallback."""
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
            subs.update(line.strip() for line in result.stdout.splitlines() if line.strip())
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
                        sub = sub.strip()
                        if sub.endswith(domain):
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
            resp = requests.head(f"{scheme}://{host}", timeout=5, allow_redirects=True)
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
            emails.add(normalize_email(email))
        for phone in PHONE_RE.findall(output):
            norm = normalize_phone(phone)
            if norm:
                phones.add(norm)
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
EMAIL_RE = re.compile(r"[\w.\-]+@[\w.\-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\s\-]{7,}\d")


def normalize_email(email: str) -> str:
    """Return a canonical form of an email address for deduplication."""
    return email.strip().lower()


def normalize_phone(phone: str) -> Optional[str]:
    """Remove formatting characters from a phone number and validate length."""
    digits = re.sub(r"\D", "", phone)
    return digits if len(digits) >= 7 else None


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
        # Containers for discovered data
        self.emails: Set[str] = set()
        self.phones: Set[str] = set()

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
            self.emails.add(normalize_email(email))
        for phone in PHONE_RE.findall(text):
            norm = normalize_phone(phone)
            if norm:
                self.phones.add(norm)


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

    print(f"Enumerating subdomains for {domain}...")
    subdomains = enumerate_subdomains(domain)
    for sub in sorted(subdomains):
        print(f" [+] {sub}")

    # ---- crawl each discovered host ----

    use_katana = shutil.which("katana") is not None
    field_file = os.path.join(os.path.dirname(__file__), "field-config.yaml")
    if use_katana:
        print("Using katana for deep enumeration")
        crawler = Crawler(domain, max_depth=0)
        for sub in subdomains:
            scheme = choose_scheme(sub)
            start_url = f"{scheme}://{sub}"
            print(f"\nRunning katana on {start_url} ...")
            urls, emails, phones = gather_with_katana(start_url, depth, field_file)
            crawler.emails.update(emails)
            crawler.phones.update(phones)
            if not urls:
                urls = {start_url}
            for link in urls:
                await crawler.crawl(link)
    else:
        crawler = Crawler(domain, max_depth=depth)
        for sub in subdomains:
            scheme = choose_scheme(sub)
            url = f"{scheme}://{sub}"
            print(f"\nCrawling {url} ...")
            await crawler.crawl(url)

    # ---- check breach APIs ----
    breached_emails = {}
    for email in crawler.emails:
        breaches = check_hibp(email, hibp_key)
        if breaches:
            breached_emails[email] = breaches
    # ---- write results to files ----
    def save_set(filename: str, data: Set[str]):
        with open(filename, "w", encoding="utf-8") as f:
            for item in sorted(data):
                f.write(item + "\n")

    save_set("emails.txt", crawler.emails)
    save_set("phones.txt", crawler.phones)
    save_set("breached_emails.txt", set(breached_emails.keys()))

    # ---- print summary to console ----
    print("\n--------- Summary ---------")
    print(f"Emails found: {len(crawler.emails)}")
    print(f"Breached emails: {len(breached_emails)}")
    print(f"Phone numbers found: {len(crawler.phones)}")

    if breached_emails:
        print("\nBreached Emails:")
        for email, breaches in breached_emails.items():
            print(f" - {email}: {', '.join(breaches)}")

    print("\nResults saved to emails.txt, breached_emails.txt, phones.txt")

    # ---- end of processing ----


# Run when executed directly
if __name__ == "__main__":
    asyncio.run(main())

