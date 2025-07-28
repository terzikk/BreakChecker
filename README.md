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
python break_checker.py example.com --depth 2 --json
```
Run the script with the target domain as an argument. Add `--json` to write a
`results.json` file and `--verbose` to display detailed log output.
Configuration can also be provided in `config.json` as shown above.

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

## Deploying with Docker Compose

The repository includes a `Dockerfile` and `docker-compose.yml` for running the
service in a container. Set the required environment variables and start the
stack:

```bash
export HIBP_API_KEY=YOUR_HIBP_KEY
# optional: export CRAWL_DEPTH=2
docker-compose up --build
```

The API will be available on `http://localhost:8000/`.

