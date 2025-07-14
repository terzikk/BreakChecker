"""URL configuration for the API application."""

from django.urls import path
from .views import ScanView

urlpatterns = [
    # Expose ``POST /api/scan/`` which runs the crawler and returns JSON results.
    path("scan/", ScanView.as_view(), name="scan"),
]
