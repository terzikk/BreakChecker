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
                "SCAN: Scan completed with %d endpoints, %d subdomains, %d emails (%d breached, %d dropped), and %d phones (%d breached, %d dropped).",
                results.get("num_endpoints", 0),
                len(results["subdomains"]),
                len(results["emails"]),
                len(results["breached_emails"]),
                results.get("emails_dropped", 0),
                len(results["phones"]),
                len(results.get("breached_phones", {})),
                results.get("phones_dropped", 0),
            )
        except Exception as e:
            logging.exception("SCAN: Exception in scan_domain")
            return Response({"error": str(e)}, status=500)

        metrics = results.get("metrics", {})

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
                "num_endpoints": results.get("num_endpoints", 0),
                "num_subdomains": len(results["subdomains"]),
                "num_emails": len(results["emails"]),
                "num_invalid_emails": results.get("emails_dropped", 0),
                "num_phones": len(results["phones"]),
                "num_invalid_phones": results.get("phones_dropped", 0),
                "num_breached_emails": len(results["breached_emails"]),
                "num_breached_phones": len(results.get("breached_phones", {})),
                "cpu_avg_percent": metrics.get("cpu_avg"),
                "cpu_peak_percent": metrics.get("cpu_peak"),
                "mem_avg_mb": metrics.get("mem_avg_mb"),
                "mem_peak_mb": metrics.get("mem_peak_mb"),
            },
            "subdomains": sorted(results["subdomains"]),
            "emails": emails,
            "phones": phones,
        }

        return Response(payload)
