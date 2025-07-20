# BreakChecker Microservice

This repository crawls a domain, collects emails/phones, and checks them against breach data. A simple Django REST Framework microservice exposes this functionality over HTTP.

## Installation

Install the pinned dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Two environment variables configure the crawler:

- `HIBP_API_KEY` – HaveIBeenPwned API key.
- `CRAWL_DEPTH` – maximum crawl depth (defaults to `3`).
- `BREACH_LOG_FILE` – optional path to the log file (defaults to
  `breach_checker.log`).

When a `config.json` file exists in the repository root it overrides the
environment variables. The file should contain:

```json
{
  "hibp_api_key": "YOUR_HIBP_KEY",
  "crawl_depth": 3
}
```


## Running the CLI script

```bash
export HIBP_API_KEY=YOUR_HIBP_KEY
# optional: export CRAWL_DEPTH=2
# optional: export BREACH_LOG_FILE=/path/to/scan.log
python breach_checker.py
```
Follow the prompts to scan a domain and save results locally. The configuration
can also be provided in `config.json` as shown above.

## Running the API server

Use Django's built-in server for testing. The server reads `HIBP_API_KEY` and
`CRAWL_DEPTH` from the environment:

```bash
export HIBP_API_KEY=YOUR_HIBP_KEY
# optional: export CRAWL_DEPTH=2
# optional: export BREACH_LOG_FILE=/path/to/scan.log
python manage.py runserver
```

Then send a POST request to `/api/scan/` with JSON:

```json
{ "domain": "example.com", "depth": 2 }
```

The response includes discovered subdomains, emails, phones and breach info.

## Deploying with Docker Compose

The repository includes a `Dockerfile` and `docker-compose.yml` for running the
service in a container. Set the required environment variables and start the
stack:

```bash
export HIBP_API_KEY=YOUR_HIBP_KEY
# optional: export CRAWL_DEPTH=2
# optional: export BREACH_LOG_FILE=/path/to/scan.log
docker-compose up --build
```

The API will be available on `http://localhost:8000/`.

## Output files

After a scan, several files are written in the current directory:

- `emails.txt` – list of discovered email addresses.
- `email_sources.txt` – email addresses paired with the URL where they were first seen.
- `phones.txt` – normalized phone numbers.
- `phone_sources.txt` – phone numbers with their source URL.
- `breached_emails.txt` – emails that were found in breaches.

Debug logs record every discovery including a short snippet of the surrounding
text.

