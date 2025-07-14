#!/usr/bin/env python
"""Entry point for Django's command-line utility."""

import os
import sys

if __name__ == "__main__":
    # Configure Django to use the settings from our microservice.
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "breakservice.settings")
    from django.core.management import execute_from_command_line

    # Delegate command line execution to Django.
    execute_from_command_line(sys.argv)
