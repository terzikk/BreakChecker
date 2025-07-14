"""Project level URL routes."""

from django.urls import path, include

urlpatterns = [
    # Delegate API paths to the API application
    path("api/", include("breakservice.api.urls")),
]
