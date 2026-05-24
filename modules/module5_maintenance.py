"""
MODULE 5 — Maintenance / Housekeeping (démon)

Responsabilités :
  - Purge des Alerts/Intrusions plus anciennes que ALERT_RETENTION_DAYS
  - Purge des EventEntry plus anciens que EVENT_RETENTION_DAYS
  - Rotation des fichiers events/ et alerts/ (compression gzip après N jours)
  - Suppression des fichiers events/alerts plus anciens que ARCHIVE_RETENTION_DAYS
  - Purge des AuditLog très anciens

Configuration via env vars :
  IDS_ALERT_RETENTION_DAYS   (défaut: 30)
  IDS_EVENT_RETENTION_DAYS   (défaut: 7)
  IDS_ARCHIVE_RETENTION_DAYS (défaut: 90)
  IDS_AUDIT_RETENTION_DAYS   (défaut: 180)
  IDS_MAINTENANCE_INTERVAL   (défaut: 3600 = 1h)
"""

import os
import sys
import gzip
import time
import shutil
import threading
from datetime import datetime, timedelta

BASE_DIR    = os.path.dirname(os.path.dirname(__file__))
EVENTS_DIR  = os.path.join(BASE_DIR, 'events')
ALERTS_DIR  = os.path.join(BASE_DIR, 'alerts')

# Configuration depuis env vars
ALERT_RETENTION_DAYS   = int(os.environ.get('IDS_ALERT_RETENTION_DAYS',   '30'))
EVENT_RETENTION_DAYS   = int(os.environ.get('IDS_EVENT_RETENTION_DAYS',   '7'))
ARCHIVE_RETENTION_DAYS = int(os.environ.get('IDS_ARCHIVE_RETENTION_DAYS', '90'))
AUDIT_RETENTION_DAYS   = int(os.environ.get('IDS_AUDIT_RETENTION_DAYS',   '180'))
COMPRESS_AFTER_DAYS    = int(os.environ.get('IDS_COMPRESS_AFTER_DAYS',    '2'))
MAINTENANCE_INTERVAL   = int(os.environ.get('IDS_MAINTENANCE_INTERVAL',   '3600'))

status = {
    'running':            False,
    'last_run':           None,
    'alerts_purged':      0,
    'intrusions_purged':  0,
    'entries_purged':     0,
    'files_compressed':   0,
    'files_deleted':      0,
    'errors':             [],
}


# ── Purge DB ────────────────────────────────────────────────────────────────

def _purge_db(app):
    """Supprime les Alerts/Intrusions/EventEntry plus anciens que la rétention."""
    with app.app_context():
        from models import db, Alert, Intrusion, EventEntry, AuditLog

        alert_cutoff = datetime.utcnow() - timedelta(days=ALERT_RETENTION_DAYS)
        event_cutoff = datetime.utcnow() - timedelta(days=EVENT_RETENTION_DAYS)
        audit_cutoff = datetime.utcnow() - timedelta(days=AUDIT_RETENTION_DAYS)

        # Alertes anciennes acquittées
        n_alerts = Alert.query.filter(
            Alert.timestamp < alert_cutoff,
            Alert.acknowledged == True
        ).delete(synchronize_session=False)

        # Intrusions anciennes
        n_intr = Intrusion.query.filter(
            Intrusion.detected_at < alert_cutoff
        ).delete(synchronize_session=False)

        # EventEntry (batch analysis) anciens
        n_entries = EventEntry.query.filter(
            EventEntry.timestamp < event_cutoff
        ).delete(synchronize_session=False)

        # Audit log très ancien
        n_audit = AuditLog.query.filter(
            AuditLog.timestamp < audit_cutoff
        ).delete(synchronize_session=False)

        db.session.commit()

        status['alerts_purged']     += n_alerts
        status['intrusions_purged'] += n_intr
        status['entries_purged']    += n_entries

        if n_alerts or n_intr or n_entries or n_audit:
            print(f'[MODULE 5] Purge DB: {n_alerts} alertes, {n_intr} intrusions, '
                  f'{n_entries} entries, {n_audit} audit logs',
                  file=sys.stderr)


# ── Rotation des fichiers ───────────────────────────────────────────────────

def _compress_old_files(directory):
    """Compresse en .gz les fichiers plus anciens que COMPRESS_AFTER_DAYS."""
    if not os.path.isdir(directory):
        return 0

    cutoff = time.time() - (COMPRESS_AFTER_DAYS * 86400)
    n = 0

    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        if name.endswith('.gz'):
            continue  # déjà compressé
        if os.path.getmtime(path) > cutoff:
            continue  # trop récent

        # Ne pas compresser le fichier du jour
        today_name = datetime.utcnow().strftime('%Y-%m-%d')
        if today_name in name:
            continue

        try:
            with open(path, 'rb') as fin, gzip.open(path + '.gz', 'wb') as fout:
                shutil.copyfileobj(fin, fout)
            os.remove(path)
            n += 1
        except Exception as e:
            status['errors'].append(f'Compression {path}: {e}')

    return n


def _delete_archived_files(directory):
    """Supprime les fichiers .gz plus anciens que ARCHIVE_RETENTION_DAYS."""
    if not os.path.isdir(directory):
        return 0

    cutoff = time.time() - (ARCHIVE_RETENTION_DAYS * 86400)
    n = 0

    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                n += 1
        except Exception as e:
            status['errors'].append(f'Suppression {path}: {e}')

    return n


# ── Démon principal ─────────────────────────────────────────────────────────

class MaintenanceDaemon(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True, name='MaintenanceDaemon')
        self.app = app

    def run(self):
        status['running'] = True
        # Première passe après 60s (laisser l'app démarrer)
        time.sleep(60)

        while True:
            try:
                # Purge DB
                _purge_db(self.app)

                # Compression et purge des fichiers
                c1 = _compress_old_files(EVENTS_DIR)
                c2 = _compress_old_files(ALERTS_DIR)
                d1 = _delete_archived_files(EVENTS_DIR)
                d2 = _delete_archived_files(ALERTS_DIR)

                status['files_compressed'] += c1 + c2
                status['files_deleted']    += d1 + d2
                status['last_run']         = datetime.utcnow().strftime('%H:%M:%S')

                if (c1 + c2 + d1 + d2) > 0:
                    print(f'[MODULE 5] Fichiers: compressés={c1 + c2}, supprimés={d1 + d2}',
                          file=sys.stderr)

            except Exception as e:
                status['errors'].append(f'Maintenance: {e}')
                print(f'[MODULE 5] Erreur: {e}', file=sys.stderr)

            time.sleep(MAINTENANCE_INTERVAL)


def start(app):
    """Démarre le démon de maintenance."""
    daemon = MaintenanceDaemon(app)
    daemon.start()
    print(f'[MODULE 5] Maintenance démarrée '
          f'(alerts:{ALERT_RETENTION_DAYS}j, events:{EVENT_RETENTION_DAYS}j, '
          f'archives:{ARCHIVE_RETENTION_DAYS}j)',
          file=sys.stderr)
