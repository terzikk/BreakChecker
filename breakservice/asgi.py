"""ASGI entrypoint for serving the project with an async server."""

import os
from django.core.asgi import get_asgi_application

# Set up Django to use our settings module when this file is imported.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "breakservice.settings")

# ``application`` is used by ASGI servers such as ``uvicorn``.
application = get_asgi_application()
