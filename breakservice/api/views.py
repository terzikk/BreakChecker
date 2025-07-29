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
            logging.info(
                "SCAN: Starting scan for %s (depth=%s)", domain, depth)
            results = async_to_sync(scan_domain)(domain, depth, hibp_key)
            logging.info(
                "SCAN: Scan completed for %s with %d breached emails of %d emails and %d phones",
                domain,
                len(results["breached_emails"]),
                len(results["emails"]),
                len(results["phones"]),
            )
        except Exception as e:
            logging.exception("SCAN: Exception in scan_domain")
            return Response({"error": str(e)}, status=500)

        payload = {
            "summary": {
                "num_subdomains":     len(results["subdomains"]),
                "num_emails":         len(results["emails"]),
                "num_phones":         len(results["phones"]),
                "num_breached_emails": len(results["breached_emails"]),
            },
            "subdomains":      sorted(results["subdomains"]),
            "emails":          sorted(results["emails"]),
            "phones":          sorted(results["phones"]),
            "breached_emails": results["breached_emails"],
            "email_sources":   results["email_sources"],
            "phone_sources":   results["phone_sources"],
        }
        return Response(payload)
