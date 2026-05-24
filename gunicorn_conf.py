"""Configuration gunicorn pour le déploiement production de l'IDS.

Usage :
    sudo IDS_SECRET_KEY=$(openssl rand -hex 32) \
         IDS_ADMIN_PASSWORD='votre-mot-de-passe' \
         IDS_HTTPS=1 \
         gunicorn -c gunicorn_conf.py wsgi:app

Note : L'IDS doit tourner en root pour scapy (capture réseau)
       et auditd (lecture audit.log).
"""

import multiprocessing
import os

# ── Réseau ─────────────────────────────────────────────────────────────────
bind     = os.environ.get('IDS_BIND', '0.0.0.0:5000')
backlog  = 2048

# ── Workers ────────────────────────────────────────────────────────────────
# IMPORTANT : workers=1 obligatoire car les démons IDS (Module 1, 2, 4, 5)
# utilisent des threads/queues partagés en mémoire. Plusieurs workers
# créeraient plusieurs instances des démons → doublons d'alertes.
workers       = 1
worker_class  = 'gthread'
threads       = 4
worker_tmp_dir = '/dev/shm'  # plus rapide

# ── Logging ────────────────────────────────────────────────────────────────
accesslog = os.environ.get('IDS_ACCESS_LOG', '-')   # - = stdout
errorlog  = os.environ.get('IDS_ERROR_LOG',  '-')
loglevel  = os.environ.get('IDS_LOG_LEVEL',  'info')

# ── Sécurité ───────────────────────────────────────────────────────────────
limit_request_line       = 4094
limit_request_field_size = 8190
forwarded_allow_ips      = '*'  # derrière reverse proxy

# ── Performance ────────────────────────────────────────────────────────────
keepalive  = 65
timeout    = 120
graceful_timeout = 30

# ── Process naming ─────────────────────────────────────────────────────────
proc_name = 'ids-web'
