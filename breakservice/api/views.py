"""API views for the BreakChecker microservice.

Exposes a single endpoint that orchestrates the full scan pipeline and returns
structured results. The endpoint mirrors the CLI stages:
1) Validate input domain
2) Load configuration and effective depth/keys
3) Run the asynchronous scan (subdomains + probes + crawl + extract + breaches)
4) Shape and return a stable JSON payload for clients
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from asgiref.sync import async_to_sync
import os
from break_checker import scan_domain, load_config, validate_domain


class ScanView(APIView):
    """Run a full scan for a domain and return results as JSON."""

    def post(self, request):
        """Handle POST to run a full scan and return results.

        Args:
            request: DRF request with JSON body containing:
                - ``domain`` (str, required): Target domain to scan
                - ``depth`` (int, optional): Crawl depth override

        Returns:
            ``Response`` with a JSON document containing summary stats,
            subdomains, emails, and phones with discovery sources and breach info.
        """
        domain_raw = request.data.get("domain")
        if not domain_raw:
            return Response(
                {"error": "domain parameter required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        valid, domain, msg = validate_domain(domain_raw, check_dns=False)
        if not valid:
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        try:
            cfg = load_config()
            depth = int(request.data.get(
                "depth", os.environ.get("CRAWL_DEPTH", cfg.get("crawl_depth", 3))))
            hibp_key = os.environ.get(
                "HIBP_API_KEY") or cfg.get("hibp_api_key")
            leak_key = os.environ.get(
                "LEAKCHECK_API_KEY") or cfg.get("leakcheck_api_key")
            # Optional save parameters for unified save+log behavior
            save_flag = request.data.get("save", False)
            # Accept strings like "true"/"1" as truthy
            if isinstance(save_flag, str):
                save_flag = save_flag.strip().lower() in {"1", "true", "yes", "y"}
            fmt = request.data.get("fmt", "json")
            output_path = request.data.get("output") or None

            results = async_to_sync(scan_domain)(
                domain,
                depth,
                hibp_key,
                leak_key,
                save=bool(save_flag),
                fmt=fmt,
                output_path=output_path,
            )
        except Exception as e:
            return Response({"error": str(e)}, status=500)

        emails = [
            {
                "address": email,
                "source": results["email_sources"].get(email, ""),
                "breaches": results["breached_emails"].get(email, [])
            }
            for email in results.get("emails", [])
        ]
        emails.sort(key=lambda x: x["address"])

        phones = [
            {
                "number": phone,
                "source": results["phone_sources"].get(phone, ""),
                "breaches": results.get("breached_phones", {}).get(phone, [])
            }
            for phone in results.get("phones", [])
        ]
        phones.sort(key=lambda x: x["number"])

        payload = {
            "domain": domain,
            "scan_start": results.get("scan_start"),
            "scan_end": results.get("scan_end"),
            "scan_duration": results.get("scan_duration"),
            "summary": {
                "num_subdomains": len(results.get("subdomains", [])),
                "num_endpoints": results.get("num_endpoints", 0),
                "num_emails": len(results.get("emails", [])),
                "num_phones": len(results.get("phones", [])),
                "num_breached_emails": len(results.get("breached_emails", [])),
                "num_breached_phones": len(results.get("breached_phones", {})),
                "emails_dropped": results.get("emails_dropped", 0),
                "phones_dropped": results.get("phones_dropped", 0),
            },
            "subdomains": sorted(results.get("subdomains", [])),
            "emails": emails,
            "phones": phones,
        }

        return Response(payload)
