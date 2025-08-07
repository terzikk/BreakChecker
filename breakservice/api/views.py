from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from asgiref.sync import async_to_sync
import os
from break_checker import scan_domain, load_config, validate_domain

import logging


class ScanView(APIView):
    def post(self, request):
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
            logging.info(
                "SCAN: Starting scan for %s ", domain)
            results = async_to_sync(scan_domain)(
                domain, depth, hibp_key, leak_key)

            logging.info(
                "SCAN: Scan completed with %d subdomains, %d emails (%d breached), and %d phones (%d breached).",
                len(results["subdomains"]),
                len(results["emails"]),
                len(results["breached_emails"]),
                len(results["phones"]),
                len(results.get("breached_phones", {})),
            )
        except Exception as e:
            logging.exception("SCAN: Exception in scan_domain")
            return Response({"error": str(e)}, status=500)

        payload = {
            "domain": domain,
            "summary": {
                "num_subdomains": len(results["subdomains"]),
                "num_emails": len(results["emails"]),
                "num_phones": len(results["phones"]),
                "num_breached_emails": len(results["breached_emails"]),
                "num_breached_phones": len(results.get("breached_phones", {})),
            },
            "subdomains": sorted(results["subdomains"]),
            "emails": [
                {
                    "address": email,
                    "source": results["email_sources"].get(email, ""),
                    "breaches": results["breached_emails"].get(email, [])
                }
                for email in sorted(results["emails"])
            ],
            "phones": [
                {
                    "number": phone,
                    "source": results["phone_sources"].get(phone, ""),
                    "breaches": results.get("breached_phones", {}).get(phone, [])
                }
                for phone in sorted(results["phones"])
            ]
        }

        return Response(payload)
