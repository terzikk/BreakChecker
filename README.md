# BreakChecker Microservice

This repository crawls a domain, collects emails/phones, and checks them against breach data. A simple Django REST Framework microservice exposes this functionality over HTTP.

## Configuration

Two environment variables configure the crawler:

- `HIBP_API_KEY` – HaveIBeenPwned API key.
- `CRAWL_DEPTH` – maximum crawl depth (defaults to `3`).

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
python manage.py runserver
```

Then send a POST request to `/api/scan/` with JSON:

```json
{ "domain": "example.com", "depth": 2 }
```

The response includes discovered subdomains, emails, phones and breach info.

