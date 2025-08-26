FROM python:3.11-slim

WORKDIR /app

# Install system deps minimal for Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget unzip ca-certificates curl gnupg \
    fonts-liberation libnss3 libatk-bridge2.0-0 libgtk-3-0 \
    libxss1 libasound2 libgbm1 libxshmfence1 libxrandr2 \
    libxdamage1 libxcomposite1 libxext6 libxi6 libxcb1 libx11-6 libdrm2 \
 && rm -rf /var/lib/apt/lists/*

# Subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.8.0/subfinder_2.8.0_linux_amd64.zip \
 && unzip subfinder_2.8.0_linux_amd64.zip \
 && mv subfinder /usr/local/bin/subfinder \
 && chmod +x /usr/local/bin/subfinder \
 && rm subfinder_2.8.0_linux_amd64.zip

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Chromium only
RUN python -m playwright install chromium

# (Optional) sanity check to keep you honest about the base distro
RUN cat /etc/os-release

# App
COPY . .
EXPOSE 8000
CMD ["gunicorn", "breakservice.wsgi:application", "--bind", "0.0.0.0:8000", "--log-level", "critical", "--timeout", "1000000000"]
