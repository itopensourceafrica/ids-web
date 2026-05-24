# ═══════════════════════════════════════════════════════════════════════════
# IDS Web — Image Docker production
#
# Build :
#   docker build -t ids-web .
#
# Run :
#   docker run -d --name ids-web \
#     --cap-add NET_RAW --cap-add NET_ADMIN \
#     --network host \
#     -e IDS_SECRET_KEY=$(openssl rand -hex 32) \
#     -e IDS_ADMIN_PASSWORD='choose-a-strong-pwd' \
#     -v $(pwd)/instance:/app/instance \
#     -v $(pwd)/events:/app/events \
#     -v $(pwd)/alerts:/app/alerts \
#     -v /var/log:/var/log:ro \
#     ids-web
#
# NOTE : --network host requis pour la capture scapy de l'hôte.
#        Lire /var/log:ro pour parser auth.log.
# ═══════════════════════════════════════════════════════════════════════════

FROM python:3.12-slim

# Métadonnées
LABEL maintainer="IDS Web Team"
LABEL description="IDS Web — Système de détection d'intrusions (HIDS + NIDS)"
LABEL version="1.0"

# Dépendances système : libpcap pour scapy, auditd pour HIDS, reg.exe N/A en Linux
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libpcap-dev \
    tcpdump \
    auditd \
    audispd-plugins \
    procps \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dépendances Python — installées en premier pour cacher cette layer
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code (après les deps pour optimiser le cache)
COPY . /app

# Volumes persistants
VOLUME ["/app/instance", "/app/events", "/app/alerts"]

# Port web
EXPOSE 5000

# Variables par défaut (override via -e au run)
ENV IDS_BIND=0.0.0.0:5000 \
    IDS_LOG_LEVEL=info \
    IDS_ALERT_RETENTION_DAYS=30 \
    IDS_EVENT_RETENTION_DAYS=7 \
    PYTHONUNBUFFERED=1

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/login', timeout=3)" \
      || exit 1

# Lancement via gunicorn (production)
CMD ["gunicorn", "-c", "gunicorn_conf.py", "wsgi:app"]
