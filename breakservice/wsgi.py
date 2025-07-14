"""WSGI entrypoint for traditional web servers such as gunicorn."""

import os
from django.core.wsgi import get_wsgi_application

# Configure Django when this module is imported.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "breakservice.settings")

# ``application`` is used by WSGI servers.
application = get_wsgi_application()
