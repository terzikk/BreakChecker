"""REST API views for the scanning microservice."""

import os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# Import the high level scanning helper from the script.  This function
# performs subdomain enumeration, crawling and optional breach checks.
from breach_checker import scan_domain


from asgiref.sync import async_to_sync


class ScanView(APIView):
    def post(self, request):
        domain = request.data.get("domain")
        if not domain:
            return Response({"error": "domain parameter required"}, status=status.HTTP_400_BAD_REQUEST)

        depth = int(request.data.get(
            "depth", os.environ.get("CRAWL_DEPTH", 3)))
        hibp_key = os.environ.get("HIBP_API_KEY")

        results = async_to_sync(scan_domain)(domain, depth, hibp_key)

        return Response(
            {
                "subdomains": sorted(results["subdomains"]),
                "emails": sorted(results["emails"]),
                "phones": sorted(results["phones"]),
                "breached_emails": results["breached_emails"],
            }
        )
