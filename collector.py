"""Collecteurs de données réels : sniffer réseau + lecteur de logs système."""
import os
import re
import time
import threading
from datetime import datetime

# ─── État partagé (in-memory, lu par la page monitoring) ──────────────────────

sniffer_status = {
    'active': False,
    'packets_captured': 0,
    'started_at': None,
    'interface': 'toutes',
    'error': None,
}

log_watcher_status = {
    'active': False,
    'log_file': None,
    'lines_processed': 0,
    'entries_created': 0,
    'started_at': None,
    'error': None,
}

_LOG_CANDIDATES = [
    '/var/log/auth.log',   # Debian / Ubuntu
    '/var/log/secure',     # RHEL / CentOS / Fedora
    '/var/log/syslog',     # fallback général
]

# ─── Parseur de logs ──────────────────────────────────────────────────────────

def _parse_date(s, year):
    for fmt in ["%Y %b %d %H:%M:%S", "%Y %b  %d %H:%M:%S"]:
        try:
            return datetime.strptime(f"{year} {s.strip()}", fmt)
        except ValueError:
            continue
    return datetime.utcnow()


def _cmd_to_resource(cmd):
    c = cmd.lower()
    if any(x in c for x in ['mysql', 'psql', 'sqlite3', 'mongod', 'redis']):
        return 'database'
    if any(x in c for x in ['nginx', 'apache2', 'httpd']):
        return 'web_server'
    if any(x in c for x in ['sendmail', 'postfix', 'dovecot', 'mail']):
        return 'email_server'
    return 'file_storage'


def parse_log_line(line):
    """Extrait les informations utiles d'une ligne de log système.
    Retourne un dict {username, resource_name, task, execution_date} ou None.
    """
    y = datetime.now().year

    # SSH login réussi
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sshd.*Accepted \w+ for (\S+) from', line)
    if m:
        return {'username': m.group(2), 'resource_name': 'ssh_server',
                'task': 'login', 'execution_date': _parse_date(m.group(1), y)}

    # SSH login échoué
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sshd.*Failed \w+ for (?:invalid user )?(\S+) from', line)
    if m:
        return {'username': m.group(2), 'resource_name': 'ssh_server',
                'task': 'failed_login', 'execution_date': _parse_date(m.group(1), y)}

    # sudo
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sudo.*:\s+(\S+)\s+:.*COMMAND=(.+)', line)
    if m:
        return {'username': m.group(2), 'resource_name': _cmd_to_resource(m.group(3)),
                'task': 'execute', 'execution_date': _parse_date(m.group(1), y)}

    # Échec PAM
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*pam.*authentication failure.*user=(\S+)', line, re.IGNORECASE)
    if m:
        return {'username': m.group(2), 'resource_name': 'system',
                'task': 'failed_login', 'execution_date': _parse_date(m.group(1), y)}

    # su (changement d'utilisateur)
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*\bsu\b.*:\s+\(to (\S+)\) (\S+)', line)
    if m:
        return {'username': m.group(3), 'resource_name': 'system',
                'task': 'admin', 'execution_date': _parse_date(m.group(1), y)}

    # Nouvelle session systemd (login console)
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*systemd-logind.*New session.*user (\S+)', line)
    if m:
        return {'username': m.group(2), 'resource_name': 'system',
                'task': 'login', 'execution_date': _parse_date(m.group(1), y)}

    return None


# ─── Sniffer réseau (scapy) ───────────────────────────────────────────────────

class NetworkSniffer:
    """Capture les paquets IP en temps réel et les analyse contre les règles de sécurité."""

    def __init__(self, app):
        self.app = app

    def start(self):
        try:
            import scapy.all  # noqa
        except ImportError:
            sniffer_status['error'] = "scapy not installed — run: pip install scapy"
            return

        if os.geteuid() != 0:
            sniffer_status['error'] = "Root privileges required — relaunch with: sudo python3 app.py"
            return

        sniffer_status.update({'active': True, 'started_at': datetime.utcnow(), 'error': None})
        threading.Thread(target=self._run, daemon=True).start()
        print("[IDS] Sniffer réseau démarré (scapy)")

    def _run(self):
        from scapy.all import sniff, IP, TCP, UDP, Raw

        def handle(pkt):
            if IP not in pkt:
                return
            sniffer_status['packets_captured'] += 1

            src, dst = pkt[IP].src, pkt[IP].dst
            port, proto, payload = 0, "OTHER", ""

            if TCP in pkt:
                proto, port = "TCP", pkt[TCP].dport
                if Raw in pkt:
                    try:
                        payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')[:500]
                    except Exception:
                        pass
            elif UDP in pkt:
                proto, port = "UDP", pkt[UDP].dport

            if port == 5000 or dst == '127.0.0.1':
                return  # ignorer le trafic interne Flask

            with self.app.app_context():
                from models import db, Event
                from analysis import analyze_network_event
                event = Event(source_ip=src, destination_ip=dst,
                              port=port, protocol=proto,
                              payload=payload, event_type="Capture")
                db.session.add(event)
                db.session.commit()
                analyze_network_event(event)

        try:
            sniff(prn=handle, store=False, filter="ip and not host 127.0.0.1")
        except Exception as e:
            sniffer_status.update({'active': False, 'error': str(e)})
            print(f"[IDS] Sniffer arrêté : {e}")


# ─── Lecteur de logs système ──────────────────────────────────────────────────

class LogWatcher:
    """Surveille /var/log/auth.log (ou équivalent) et crée des EventEntry en temps réel."""

    def __init__(self, app):
        self.app = app
        self._log_file = None
        self._last_pos = 0

    def start(self):
        for path in _LOG_CANDIDATES:
            if os.path.exists(path):
                try:
                    open(path).close()
                    self._log_file = path
                    break
                except PermissionError:
                    continue

        if not self._log_file:
            log_watcher_status['error'] = (
                "No readable log file. "
                "Run: sudo chmod o+r /var/log/auth.log"
            )
            print("[IDS] LogWatcher: no accessible file")
            return

        # Ne traiter que les nouvelles lignes (pas relire l'historique au démarrage)
        self._last_pos = os.path.getsize(self._log_file)
        log_watcher_status.update({
            'active': True, 'log_file': self._log_file,
            'started_at': datetime.utcnow(), 'error': None
        })
        threading.Thread(target=self._watch, daemon=True).start()
        print(f"[IDS] LogWatcher : surveillance de {self._log_file}")

    def _watch(self):
        while True:
            try:
                size = os.path.getsize(self._log_file)
                if size > self._last_pos:
                    with open(self._log_file) as f:
                        f.seek(self._last_pos)
                        lines = f.readlines()
                    self._last_pos = size
                    if lines:
                        self._process(lines)
            except Exception as e:
                log_watcher_status['error'] = str(e)
            time.sleep(3)  # vérification toutes les 3 secondes

    def _process(self, lines):
        with self.app.app_context():
            from models import db, EventFile, EventEntry
            from analysis import analyze_access_entry

            # Fichier du jour (créé automatiquement si absent)
            today = f"Auth_{datetime.utcnow().strftime('%Y-%m-%d')}"
            ef = EventFile.query.filter_by(name=today).first()
            if not ef:
                num = (EventFile.query.count() or 0) + 1
                ef = EventFile(file_number=num, name=today)
                db.session.add(ef)
                db.session.flush()

            added = 0
            for line in lines:
                data = parse_log_line(line.strip())
                if not data:
                    continue
                log_watcher_status['lines_processed'] += 1
                entry = EventEntry(file_id=ef.id, **data)
                db.session.add(entry)
                db.session.flush()
                analyze_access_entry(entry)
                added += 1

            if added:
                db.session.commit()
                log_watcher_status['entries_created'] += added


# ─── Démarrage global ─────────────────────────────────────────────────────────

def start_all(app):
    """Lance tous les collecteurs en arrière-plan (appelé au démarrage de l'app)."""
    NetworkSniffer(app).start()
    LogWatcher(app).start()
