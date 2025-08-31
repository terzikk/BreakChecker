FROM python:3.11-slim

WORKDIR /app

# System dependencies for headless Chromium (Playwright)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget unzip ca-certificates curl gnupg \
    fonts-liberation libnss3 libatk-bridge2.0-0 libgtk-3-0 \
    libxss1 libasound2 libgbm1 libxshmfence1 libxrandr2 \
    libxdamage1 libxcomposite1 libxext6 libxi6 libxcb1 libx11-6 libdrm2 \
 && rm -rf /var/lib/apt/lists/*

# Optional subdomain enumerator (subfinder)
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.8.0/subfinder_2.8.0_linux_amd64.zip \
 && unzip subfinder_2.8.0_linux_amd64.zip \
 && mv subfinder /usr/local/bin/subfinder \
 && chmod +x /usr/local/bin/subfinder \
 && rm subfinder_2.8.0_linux_amd64.zip

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install only Chromium for Playwright (keep image slim)
RUN python -m playwright install chromium

# (Optional) Show base distro for debugging the runtime environment
RUN cat /etc/os-release

# Application code and runtime
COPY . .
EXPOSE 8000
# Use gunicorn to serve the Django app; adjust timeout/log-level as needed
CMD ["gunicorn", "breakservice.wsgi:application", "--bind", "0.0.0.0:8000", "--log-level", "critical", "--timeout", "1000000000"]
