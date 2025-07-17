FROM python:3.11-slim

WORKDIR /app

# Install system tools for downloads and zip extraction
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

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

# Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 8000

CMD ["gunicorn", "breakservice.wsgi:application", "--bind", "0.0.0.0:8000", "--timeout", "500"]
