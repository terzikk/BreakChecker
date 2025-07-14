"""REST API views for the scanning microservice."""

import os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# Import the high level scanning helper from the script.  This function
# performs subdomain enumeration, crawling and optional breach checks.
from breach_checker import scan_domain


class ScanView(APIView):
    """POST endpoint that triggers a scan for the requested domain."""

    async def post(self, request):
        # ``domain`` is mandatory, while ``depth`` is optional and falls back
        # to either the CRAWL_DEPTH environment variable or the default of 3.
        domain = request.data.get("domain")
        if not domain:
            return Response({"error": "domain parameter required"}, status=status.HTTP_400_BAD_REQUEST)

        depth = int(request.data.get("depth", os.environ.get("CRAWL_DEPTH", 3)))
        hibp_key = os.environ.get("HIBP_API_KEY")

        # Kick off the asynchronous crawler and wait for results.
        results = await scan_domain(domain, depth, hibp_key)
        crawler = results["crawler"]

        # Return a JSON object summarizing what was found.
        return Response(
            {
                "subdomains": sorted(results["subdomains"]),
                "emails": sorted(crawler.emails),
                "phones": sorted(crawler.phones),
                "breached_emails": results["breached_emails"],
            }
        )
