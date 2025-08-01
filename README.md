# BreakChecker Microservice

BreakChecker is a domain discovery and breach checking tool. It can scan a
website, harvest any emails or phone numbers, and verify them against breach
sources. The project provides both a command line interface and a small Django
REST API.

## How it works

The scanner runs in several distinct stages:

1. **Enumerate subdomains** – `subfinder` is used when available and falls back
   to free services like crt.sh, HackerTarget and Anubis DB.
2. **Check accessibility** – each discovered subdomain is probed for HTTP/HTTPS
   support so only reachable hosts are crawled.
3. **Crawl the site** – if the `katana` crawler is installed it is used for
   deeper enumeration, otherwise an internal asynchronous crawler collects pages
   with Playwright. Links and scripts are followed up to the configured depth.
4. **Extract contacts** – emails and phone numbers are validated, normalized and
   stored together with the page on which they were seen.
5. **Breach lookups** – emails are checked via a HaveIBeenPwned proxy API and
   phones via the LeakCheck API when API keys are supplied.

The collected data can be written to JSON, CSV or Markdown reports. Verbose mode
adds detailed logs about every step.

## Installation

Install the pinned Python requirements:

```bash
pip install -r requirements.txt
```

Some stages optionally use external tools (``subfinder`` and ``katana``). They
are installed automatically in the provided Docker image, but you can also
install them manually for the CLI.

## Configuration

The crawler reads its settings from environment variables or an optional
`config.json` file:

- `HIBP_API_KEY` – key for the HaveIBeenPwned proxy.
- `LEAKCHECK_API_KEY` – key for phone lookups with LeakCheck.
- `CRAWL_DEPTH` – maximum crawl depth (default `3`).

`config.json` overrides the environment and should look like:

```json
{
  "hibp_api_key": "YOUR_HIBP_KEY",
  "leakcheck_api_key": "YOUR_LEAKCHECK_KEY",
  "crawl_depth": 3
}
```

## CLI usage

```bash
export HIBP_API_KEY=YOUR_HIBP_KEY
# optional: export LEAKCHECK_API_KEY=YOUR_LEAKCHECK_KEY
python break_checker.py example.com -d 2 -c 5 -v --json
```

Each argument configures how the scan is performed:

- `domain` – the domain to crawl and check
- `-d`, `--depth` – maximum crawl depth (default taken from `CRAWL_DEPTH` or 3)
- `-c`, `--concurrency` – number of concurrent workers (default 5)
- `-v`, `--verbose` – show detailed progress and write logs to `break_checker.log`
- `-j`, `--json` – save results to `DOMAIN-TIMESTAMP.json` (default format)
- `--csv` – save results to `DOMAIN-TIMESTAMP.csv`
- `--md`, `--report` – save results to `DOMAIN-TIMESTAMP.md`
- `-o`, `--output` – optional custom path for the report file

Logs are written to `break_checker.log` in the working directory and printed on
the console. Set the `BREACH_LOG_FILE` environment variable to change the log
file location.

## API server

The included Django project exposes a single `/api/scan/` endpoint. Start the
server with:

```bash
export HIBP_API_KEY=YOUR_HIBP_KEY
export LEAKCHECK_API_KEY=YOUR_LEAKCHECK_KEY  # optional
python manage.py runserver
```

Then send a POST request:

```json
{ "domain": "example.com", "depth": 2 }
```

The response lists all subdomains, emails and phone numbers (digits only)
together with any breach data.

Example response:

```json
{
  "domain": "example.com",
  "summary": {
    "num_subdomains": 3,
    "num_emails": 2,
    "num_phones": 1,
    "num_breached_emails": 1,
    "num_breached_phones": 1
  },
  "subdomains": [
    "app.example.com",
    "mail.example.com",
    "www.example.com"
  ],
  "emails": [
    {
      "address": "user@example.com",
      "source": "https://www.example.com/about",
      "breaches": ["Adobe", "LinkedIn"]
    },
    {
      "address": "info@example.com",
      "source": "https://www.example.com/contact",
      "breaches": []
    }
  ],
  "phones": [
    {
      "number": "5551234567",
      "source": "https://www.example.com/contact",
      "breaches": ["ExampleBreach"]
    }
  ]
}
```

## Docker

A ready-to-run Docker image is provided. Build and launch it with Docker Compose
once the required API keys are set:

```bash
docker-compose up --build
```

The API will be available on <http://localhost:8000/>.
