"""Minimal Django settings for running the scanning API."""

from pathlib import Path
import os

# Directory that contains this file's parent directory. Used for building
# relative paths.
BASE_DIR = Path(__file__).resolve().parent.parent

# WARNING: Keep the secret key secret in production.
SECRET_KEY = "replace-me"

# Development mode enabled by default
DEBUG = True

# Accept requests from any host
ALLOWED_HOSTS = ["*"]

# Django applications that are active for this project.  REST framework
# provides API support and "breakservice.api" contains our endpoints.
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "breakservice.api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# Root URL configuration module
ROOT_URLCONF = "breakservice.urls"
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# Entry points for WSGI/ASGI servers
WSGI_APPLICATION = "breakservice.wsgi.application"
ASGI_APPLICATION = "breakservice.asgi.application"

# Use a simple SQLite database for demonstration
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True

STATIC_URL = "/static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
