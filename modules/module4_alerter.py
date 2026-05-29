"""
MODULE 4 — Générateur d'alertes (démon)

Reçoit les intrusions depuis le Module 2 via une file thread-safe,
génère des alertes détaillées et les distribue vers :
  - La base de données (modèle Alert)
  - Le fichier log alerts/YYYY-MM-DD.log
  - (Optionnel) Email SMTP si configuré dans ids_config.json

Format d'alerte :
  ═══════════════════════════════════════════════════════
  [CRITIQUE] 2026-05-22 10:30:00 UTC
  ───────────────────────────────────────────────────────
  Intrusion détectée
  Utilisateur  : alice
  Ressource    : database
  Tâche        : execute
  Date accès   : 2026-05-22 10:30:00
  Source       : /var/log/auth.log
  ───────────────────────────────────────────────────────
  Violation    : Tâche 'execute' non autorisée sur 'database' pour 'alice'
  Détails      : Aucune règle de la politique ne permet cet accès
  ═══════════════════════════════════════════════════════
"""

import os
import sys
import time
import queue
import threading
import smtplib
from datetime import datetime
from email.mime.text import MIMEText

BASE_DIR   = os.path.dirname(os.path.dirname(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, 'alerts')
CONFIG_FILE = os.path.join(BASE_DIR, 'ids_config.json')

status = {
    'running':        False,
    'alerts_sent':    0,
    'queue_size':     0,
    'last_alert':     None,
    'errors':         [],
}

SEVERITY_LABELS = {
    'critical': 'CRITIQUE',
    'high':     'HAUTE',
    'medium':   'MOYENNE',
    'low':      'FAIBLE',
}


# ── Formatage de l'alerte ────────────────────────────────────────────────────

def _format_alert(data: dict) -> str:
    event     = data.get('event', {})
    violation = data.get('violation', {})
    ts        = data.get('detected_at', datetime.now().isoformat())

    severity_label = SEVERITY_LABELS.get(violation.get('severity', 'high'), 'HAUTE')

    return (
        f"\n{'═'*55}\n"
        f"[{severity_label}] {ts[:19].replace('T', ' ')} UTC\n"
        f"{'─'*55}\n"
        f"INTRUSION DÉTECTÉE\n"
        f"  Utilisateur : {event.get('username', '?')}\n"
        f"  Ressource   : {event.get('resource', '?')}\n"
        f"  Tâche       : {event.get('task', '?')}\n"
        f"  Date accès  : {event.get('execution_date', '?')[:19].replace('T',' ')}\n"
        f"  Source      : {event.get('source', '?')}\n"
        f"{'─'*55}\n"
        f"  Violation   : {violation.get('message', '?')}\n"
        f"  Type        : {violation.get('type', '?')}\n"
        f"  Ligne brute : {event.get('raw', '')[:100]}\n"
        f"{'═'*55}\n"
    )


# ── Écriture dans le fichier log ─────────────────────────────────────────────

_file_lock = threading.Lock()

def _write_alert_log(text: str):
    os.makedirs(ALERTS_DIR, exist_ok=True)
    day_file = os.path.join(ALERTS_DIR, datetime.now().strftime('%Y-%m-%d') + '.log')
    with _file_lock:
        with open(day_file, 'a', encoding='utf-8') as f:
            f.write(text)


# ── Enregistrement en DB ─────────────────────────────────────────────────────

def _save_to_db(data: dict, app):
    with app.app_context():
        from models import db, Alert, Intrusion
        violation = data.get('violation', {})
        event     = data.get('event', {})

        intrusion_id = data.get('intrusion_id')

        alert = Alert(
            message=(
                f"[IDS] {event.get('username','?')} | "
                f"{event.get('task','?')} sur {event.get('resource','?')} | "
                f"{violation.get('message','?')}"
            ),
            severity=violation.get('severity', 'high'),
        )
        db.session.add(alert)
        db.session.commit()


# ── Envoi email (optionnel) ──────────────────────────────────────────────────

def _load_smtp_config() -> dict:
    import json
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
            return cfg.get('smtp', {})
    except Exception:
        return {}


def _send_email(subject: str, body: str, cfg: dict):
    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From']    = cfg['from']
        msg['To']      = cfg['to']

        with smtplib.SMTP(cfg['host'], cfg.get('port', 587), timeout=10) as smtp:
            if cfg.get('tls', True):
                smtp.starttls()
            if cfg.get('user') and cfg.get('password'):
                smtp.login(cfg['user'], cfg['password'])
            smtp.send_message(msg)
    except Exception as e:
        status['errors'].append(f'Email: {e}')


# ── Webhooks Slack / Discord / Teams ────────────────────────────────────────

SEVERITY_COLOR = {
    'critical': '#dc2626',  # rouge
    'high':     '#ea580c',  # orange foncé
    'medium':   '#f59e0b',  # ambre
    'low':      '#22c55e',  # vert
}
SEVERITY_EMOJI = {
    'critical': '🚨',
    'high':     '⚠️',
    'medium':   '🔔',
    'low':      'ℹ️',
}


def _send_slack(url: str, data: dict):
    """Envoie l'alerte vers un webhook Slack (format Block Kit)."""
    import urllib.request, json
    event     = data.get('event', {})
    violation = data.get('violation', {})
    sev       = violation.get('severity', 'high')
    emoji     = SEVERITY_EMOJI.get(sev, '⚠️')

    payload = {
        'attachments': [{
            'color': SEVERITY_COLOR.get(sev, '#666'),
            'fallback': f'{emoji} IDS Alerte {sev.upper()}: {violation.get("message", "")}',
            'blocks': [
                {'type': 'header', 'text': {
                    'type': 'plain_text',
                    'text': f'{emoji} IDS — Alerte {sev.upper()}'
                }},
                {'type': 'section', 'fields': [
                    {'type': 'mrkdwn', 'text': f'*Utilisateur:*\n{event.get("username", "?")}'},
                    {'type': 'mrkdwn', 'text': f'*Tâche:*\n{event.get("task", "?")}'},
                    {'type': 'mrkdwn', 'text': f'*Ressource:*\n{event.get("resource", "?")}'},
                    {'type': 'mrkdwn', 'text': f'*Source:*\n{event.get("source", "?")}'},
                ]},
                {'type': 'section', 'text': {
                    'type': 'mrkdwn',
                    'text': f'*Violation:* {violation.get("message", "?")}'
                }},
                {'type': 'context', 'elements': [{
                    'type': 'mrkdwn',
                    'text': f'_Type: {violation.get("type", "?")} | '
                            f'{data.get("detected_at", "")[:19].replace("T", " ")} UTC_'
                }]},
            ]
        }]
    }

    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=5).close()
    except Exception as e:
        status['errors'].append(f'Slack: {e}')


def _send_discord(url: str, data: dict):
    """Envoie l'alerte vers un webhook Discord."""
    import urllib.request, json
    event     = data.get('event', {})
    violation = data.get('violation', {})
    sev       = violation.get('severity', 'high')
    emoji     = SEVERITY_EMOJI.get(sev, '⚠️')

    # Convertir couleur hex → int pour Discord
    color_hex = SEVERITY_COLOR.get(sev, '#666666').lstrip('#')
    color_int = int(color_hex, 16)

    payload = {
        'username': 'IDS Web',
        'embeds': [{
            'title': f'{emoji} Alerte {sev.upper()}',
            'description': violation.get('message', ''),
            'color': color_int,
            'fields': [
                {'name': 'Utilisateur', 'value': event.get('username', '?'), 'inline': True},
                {'name': 'Tâche',       'value': event.get('task', '?'),     'inline': True},
                {'name': 'Ressource',   'value': event.get('resource', '?'), 'inline': True},
                {'name': 'Source',      'value': event.get('source', '?'),   'inline': False},
                {'name': 'Type',        'value': violation.get('type', '?'), 'inline': True},
            ],
            'footer': {'text': f'IDS Web | {data.get("detected_at", "")[:19].replace("T", " ")} UTC'},
        }]
    }

    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=5).close()
    except Exception as e:
        status['errors'].append(f'Discord: {e}')


def _send_teams(url: str, data: dict):
    """Envoie l'alerte vers un webhook MS Teams (MessageCard)."""
    import urllib.request, json
    event     = data.get('event', {})
    violation = data.get('violation', {})
    sev       = violation.get('severity', 'high')

    payload = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'themeColor': SEVERITY_COLOR.get(sev, '#666666').lstrip('#'),
        'summary': f'IDS Alerte {sev.upper()}',
        'sections': [{
            'activityTitle': f'IDS — Alerte {sev.upper()}',
            'activitySubtitle': violation.get('message', ''),
            'facts': [
                {'name': 'Utilisateur', 'value': event.get('username', '?')},
                {'name': 'Tâche',       'value': event.get('task', '?')},
                {'name': 'Ressource',   'value': event.get('resource', '?')},
                {'name': 'Source',      'value': event.get('source', '?')},
                {'name': 'Type',        'value': violation.get('type', '?')},
            ],
        }]
    }

    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=5).close()
    except Exception as e:
        status['errors'].append(f'Teams: {e}')


# ── Syslog forwarding (SIEM intégration) ────────────────────────────────────

# Mapping IDS severity → syslog severity (RFC 5424)
SYSLOG_SEVERITY = {
    'critical': 2,  # critical
    'high':     3,  # error
    'medium':   4,  # warning
    'low':      6,  # info
}

def _send_syslog(host: str, port: int, data: dict):
    """Envoie l'alerte au format syslog vers un SIEM (Splunk/ELK/Wazuh)."""
    import socket as _socket
    event     = data.get('event', {})
    violation = data.get('violation', {})
    sev_text  = violation.get('severity', 'high')
    sev_num   = SYSLOG_SEVERITY.get(sev_text, 4)

    # Facility = 13 (audit/log), severity = sev_num
    priority = 13 * 8 + sev_num

    # Format RFC 3164 (BSD syslog)
    timestamp = datetime.now().strftime('%b %d %H:%M:%S')
    hostname  = _socket.gethostname()

    msg = (
        f'<{priority}>{timestamp} {hostname} ids-web: '
        f'severity={sev_text} '
        f'user={event.get("username", "?")} '
        f'task={event.get("task", "?")} '
        f'resource={event.get("resource", "?")} '
        f'source={event.get("source", "?")} '
        f'type={violation.get("type", "?")} '
        f'msg="{violation.get("message", "?")[:200]}"'
    )

    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.sendto(msg.encode('utf-8'), (host, port))
        sock.close()
    except Exception as e:
        status['errors'].append(f'Syslog: {e}')


# ── Chargement complet de la config ────────────────────────────────────────

def _load_full_config() -> dict:
    """Charge ids_config.json complet (smtp, webhooks, syslog)."""
    import json
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


# ── Démon principal ──────────────────────────────────────────────────────────

class AlertDaemon(threading.Thread):
    """Consomme la file d'alertes et distribue vers tous les canaux."""

    def __init__(self, app, alert_queue: queue.Queue):
        super().__init__(daemon=True, name='AlertDaemon')
        self.app   = app
        self.queue = alert_queue
        self._config = {}
        self._last_config_load = 0

    def _reload_config_if_needed(self):
        """Recharge la config toutes les 60s."""
        now = time.time()
        if now - self._last_config_load > 60:
            self._config = _load_full_config()
            self._last_config_load = now

    def _enrich_with_threat_intel(self, data):
        """Ajoute AbuseIPDB + GeoIP au message si applicable."""
        try:
            import sys, os
            sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
            from threat_intel import enrich_ip, format_enrichment
        except ImportError:
            return

        event = data.get('event', {})
        violation = data.get('violation', {})

        # Trouver une IP candidate (event username pour NIDS, ou raw)
        ip = event.get('username', '')
        import re as _re
        # Cherche une IP dans raw si username n'est pas une IP
        if not _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            m = _re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', event.get('raw', ''))
            if m:
                ip = m.group(1)
            else:
                return  # pas d'IP à enrichir

        enrichment = enrich_ip(ip)
        if not enrichment:
            return

        # Stocker dans data pour le format/dispatch
        data['enrichment'] = enrichment
        formatted = format_enrichment(enrichment)
        if formatted:
            # Ajouter à la fin du message
            violation['message'] = (violation.get('message', '') + ' | ' + formatted)

        # Si score abuse > 75, bumper la sévérité à critical
        if enrichment.get('abuse_score', 0) >= 75:
            violation['severity'] = 'critical'

    def _dispatch(self, data, alert_text):
        """Envoie l'alerte vers tous les canaux configurés."""
        event     = data.get('event', {})
        violation = data.get('violation', {})
        severity  = violation.get('severity', 'high')

        # Filtre par sévérité minimale (option)
        min_sev = self._config.get('min_severity', 'low')
        sev_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        if sev_order.get(severity, 2) < sev_order.get(min_sev, 0):
            return

        # SMTP
        smtp = self._config.get('smtp', {})
        if smtp.get('host') and smtp.get('to'):
            subject = (
                f"[IDS ALERTE {severity.upper()}] "
                f"{event.get('username', '?')} — "
                f"{event.get('task', '?')} sur {event.get('resource', '?')}"
            )
            _send_email(subject, alert_text, smtp)

        # Slack
        slack_url = self._config.get('slack_webhook', '').strip()
        if slack_url:
            _send_slack(slack_url, data)

        # Discord
        discord_url = self._config.get('discord_webhook', '').strip()
        if discord_url:
            _send_discord(discord_url, data)

        # Teams
        teams_url = self._config.get('teams_webhook', '').strip()
        if teams_url:
            _send_teams(teams_url, data)

        # Syslog
        syslog_cfg = self._config.get('syslog', {})
        if syslog_cfg.get('host'):
            _send_syslog(
                syslog_cfg['host'],
                int(syslog_cfg.get('port', 514)),
                data
            )

    def run(self):
        status['running'] = True
        self._config = _load_full_config()
        self._last_config_load = time.time()
        print('[MODULE 4] Générateur d\'alertes démarré', file=sys.stderr)

        while True:
            status['queue_size'] = self.queue.qsize()
            self._reload_config_if_needed()

            try:
                data = self.queue.get(timeout=2)
            except queue.Empty:
                continue

            try:
                # ── Enrichissement threat intel + GeoIP ──────────
                self._enrich_with_threat_intel(data)

                alert_text = _format_alert(data)

                # Stockage local
                _write_alert_log(alert_text)
                _save_to_db(data, self.app)

                # Dispatch vers tous les canaux configurés
                self._dispatch(data, alert_text)

                status['alerts_sent'] += 1
                status['last_alert']  = (
                    f"{data.get('event',{}).get('username','?')} | "
                    f"{data.get('violation',{}).get('type','?')}"
                )

                print(alert_text, file=sys.stderr)

            except Exception as e:
                status['errors'].append(f'AlertDaemon: {e}')

            self.queue.task_done()


def start(app, alert_queue: queue.Queue):
    """Démarre le générateur d'alertes."""
    os.makedirs(ALERTS_DIR, exist_ok=True)
    AlertDaemon(app, alert_queue).start()
