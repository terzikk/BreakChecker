FROM python:3.11-slim

WORKDIR /app

# Install system tools for downloads and zip extraction
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget unzip ca-certificates \
    curl gnupg fonts-liberation libnss3 libatk-bridge2.0-0 libgtk-3-0 \
    libxss1 libasound2 libgbm1 libxshmfence1 libxrandr2 libxdamage1 libxcomposite1 \
    libxext6 libxi6 libxcb1 libx11-6 libdrm2 \
    && rm -rf /var/lib/apt/lists/*

# Install Katana (v1.1.3, Linux amd64)
RUN wget -q https://github.com/projectdiscovery/katana/releases/download/v1.1.3/katana_1.1.3_linux_amd64.zip \
    && unzip katana_1.1.3_linux_amd64.zip \
    && mv katana /usr/local/bin/katana \
    && chmod +x /usr/local/bin/katana \
    && rm katana_1.1.3_linux_amd64.zip

# Install Subfinder (v2.8.0, Linux amd64)
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.8.0/subfinder_2.8.0_linux_amd64.zip \
    && unzip subfinder_2.8.0_linux_amd64.zip \
    && mv subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm subfinder_2.8.0_linux_amd64.zip

# Install Python dependencies first (including playwright)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (after package is installed)
RUN python -m playwright install --with-deps

# Copy application code
COPY . .

EXPOSE 8000

CMD ["gunicorn", "breakservice.wsgi:application", "--bind", "0.0.0.0:8000", "--timeout", "1200"]