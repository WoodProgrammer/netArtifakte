# pcap-analyzer: FastAPI app + zeek + tshark
#
# Based on the official Zeek image (Debian, multi-arch: amd64 + arm64) so zeek doesn't have to be
# built or installed from a third-party repo. tshark and Python come from Debian packages.
FROM zeek/zeek:lts

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:/usr/local/zeek/bin:$PATH \
    DATA_DIR=/data

# tshark: preseed "no" for the setuid dumpcap question so the install stays non-interactive
# (the app only reads pcap files; it never captures live traffic).
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends tshark python3 python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first for better layer caching.
COPY requirements.txt .
RUN python3 -m venv /opt/venv \
 && pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as an unprivileged user; /data holds the SQLite DB and uploaded pcaps (mounted as a volume).
RUN useradd --create-home --uid 1000 app \
 && mkdir -p /data \
 && chown app:app /data
USER app

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/capabilities', timeout=4)"

# Single process on purpose: the job queue lives in memory in this process.
# Don't add --workers > 1 (jobs could be processed twice / approvals routed to the wrong process).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
