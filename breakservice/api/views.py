from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from asgiref.sync import async_to_sync
import os
from breach_checker import scan_domain

import logging


class ScanView(APIView):
    def post(self, request):
        domain = request.data.get("domain")
        if not domain:
            return Response(
                {"error": "domain parameter required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            depth = int(request.data.get(
                "depth", os.environ.get("CRAWL_DEPTH", 3)))
            hibp_key = os.environ.get("HIBP_API_KEY")
            logging.warning(
                "SCAN: Starting scan for %s (depth=%s)", domain, depth)
            results = async_to_sync(scan_domain)(domain, depth, hibp_key)
            logging.warning("SCAN: Scan completed for %s", domain)
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
        }
        return Response(payload)
