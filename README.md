# BreakChecker Microservice

This repository crawls a domain, collects emails/phones, and checks them against breach data. A simple Django REST Framework microservice exposes this functionality over HTTP.

## Running the CLI script

```bash
python breach_checker.py
```
Follow the prompts to scan a domain and save results locally.

## Running the API server

Use Django's built-in server for testing:

```bash
python manage.py runserver
```

Then send a POST request to `/api/scan/` with JSON:

```json
{ "domain": "example.com", "depth": 2 }
```

The response includes discovered subdomains, emails, phones and breach info.

