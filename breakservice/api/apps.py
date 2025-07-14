"""Django application configuration for the API package."""

from django.apps import AppConfig


class ApiConfig(AppConfig):
    """Minimal application configuration used by Django."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "breakservice.api"
