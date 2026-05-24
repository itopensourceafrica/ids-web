"""
MODULE 1 — Collecteur d'événements (démon)

Observe en continu les sources d'événements du système et produit
des fichiers d'événements physiques (JSONL) dans le dossier events/.

Sources supportées :
  Linux  : /var/log/auth.log, /var/log/syslog, /var/log/audit/audit.log
  Windows: Security Event Log (wevtutil), Application, System
  Réseau : capture de paquets IP (scapy, nécessite root/admin)
  Fichiers: surveillance d'intégrité des fichiers critiques (SHA-256)
  Processus: détection de nouveaux processus suspects (psutil)

Format de sortie (JSONL) :
  {"id":"...", "ts":"...", "source":"...", "username":"...",
   "resource":"...", "task":"...", "execution_date":"...", "raw":"..."}
"""

import os
import re
import sys
import json
import uuid
import time
import platform
import hashlib
import threading
import subprocess
from collections import defaultdict
from datetime import datetime

import pwd as _pwd

# ── Statut partagé (lu par l'interface web) ─────────────────────────────────
status = {
    'running':     False,
    'sources':     [],
    'events_today': 0,
    'last_event':  None,
    'errors':      [],
    'started_at':  None,
}

sniffer_status = {
    'active':           False,
    'error':            None,
    'packets_captured': 0,
    'interface':        'all',
    'started_at':       None,
}

logwatcher_status = {
    'active':          False,
    'error':           None,
    'log_file':        None,
    'lines_processed': 0,
    'entries_created': 0,
    'started_at':      None,
}

BASE_DIR   = os.path.dirname(os.path.dirname(__file__))
SYSTEM     = platform.system()  # 'Linux', 'Windows', 'Darwin'

# ── Répertoire de sortie ─────────────────────────────────────────────────────
EVENTS_DIR = os.path.join(BASE_DIR, 'events')

# ── Fichiers Linux surveillés ────────────────────────────────────────────────
LINUX_LOG_CANDIDATES = [
    '/var/log/auth.log',
    '/var/log/secure',
    '/var/log/syslog',
    '/var/log/audit/audit.log',
]

# ── Fichiers critiques pour l'intégrité ─────────────────────────────────────
INTEGRITY_FILES = {
    'Linux': [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/hosts',
        '/etc/crontab',
        '/etc/ssh/sshd_config',
        '/etc/pam.d/common-auth',
        '/etc/pam.d/sudo',
        '/etc/profile',
        '/etc/bash.bashrc',
        '/etc/resolv.conf',
        '/etc/rc.local',
    ],
    'Windows': [
        r'C:\Windows\System32\drivers\etc\hosts',
        r'C:\Windows\System32\drivers\etc\networks',
        r'C:\Windows\System32\drivers\etc\protocol',
        r'C:\Windows\System32\drivers\etc\services',
        r'C:\Windows\System32\config\SAM',
        r'C:\Windows\System32\config\SYSTEM',
        r'C:\Windows\System32\config\SECURITY',
        r'C:\Windows\System32\config\SOFTWARE',
        r'C:\Windows\win.ini',
        r'C:\Windows\System32\GroupPolicy\Machine\Registry.pol',
    ],
    'Darwin': [
        '/etc/passwd',
        '/etc/sudoers',
        '/etc/hosts',
        '/etc/ssh/sshd_config',
    ],
}

INTEGRITY_CONF = os.path.join(BASE_DIR, 'ids_integrity.conf')

def _load_integrity_targets() -> list:
    """Load integrity targets from ids_integrity.conf if present, else use defaults."""
    if os.path.exists(INTEGRITY_CONF):
        targets = []
        with open(INTEGRITY_CONF, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        return targets
    return INTEGRITY_FILES.get(SYSTEM, INTEGRITY_FILES['Linux'])

# ── Ressources détectées automatiquement ─────────────────────────────────────
def _cmd_to_resource(cmd):
    c = cmd.lower()
    if any(x in c for x in ['mysql', 'psql', 'sqlite3', 'mongod', 'redis-cli']):
        return 'database'
    if any(x in c for x in ['nginx', 'apache2', 'httpd', 'flask']):
        return 'web_server'
    if any(x in c for x in ['sendmail', 'postfix', 'dovecot', 'mail']):
        return 'email_server'
    if any(x in c for x in ['useradd', 'usermod', 'passwd', 'chpasswd']):
        return 'user_management'
    if any(x in c for x in ['iptables', 'ufw', 'firewall']):
        return 'firewall'
    return 'system'


# ── Écriture d'un événement dans le fichier JSONL du jour ────────────────────
_write_lock = threading.Lock()

def write_event(username: str, resource: str, task: str,
                execution_date: datetime, source: str, raw: str = ''):
    """Écrit un événement dans events/YYYY-MM-DD.jsonl"""
    event = {
        'id':             str(uuid.uuid4()),
        'ts':             datetime.utcnow().isoformat(),
        'source':         source,
        'username':       username,
        'resource':       resource,
        'task':           task,
        'execution_date': execution_date.isoformat(),
        'raw':            raw[:300],
    }
    day_file = os.path.join(EVENTS_DIR, datetime.utcnow().strftime('%Y-%m-%d') + '.jsonl')
    with _write_lock:
        with open(day_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + '\n')

    status['events_today'] += 1
    status['last_event'] = f"{username} | {task} | {resource}"
    return event


# ════════════════════════════════════════════════════════════════════════════
# COLLECTEUR LINUX — lecture des logs système
# ════════════════════════════════════════════════════════════════════════════

def _parse_date(s: str) -> datetime:
    year = datetime.now().year
    for fmt in ['%Y %b %d %H:%M:%S', '%Y %b  %d %H:%M:%S']:
        try:
            return datetime.strptime(f'{year} {s.strip()}', fmt)
        except ValueError:
            continue
    return datetime.utcnow()


def _parse_auth_line(line: str) -> dict | None:
    """Parse une ligne de auth.log / secure et retourne un dict événement."""
    y = datetime.now().year

    # SSH login réussi
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sshd.*Accepted \w+ for (\S+) from ([\d.]+)', line)
    if m:
        return dict(username=m.group(2), resource='ssh_server', task='login',
                    execution_date=_parse_date(m.group(1)), source='auth.log', raw=line.strip())

    # SSH login échoué
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sshd.*Failed \w+ for (?:invalid user )?(\S+) from ([\d.]+)', line)
    if m:
        return dict(username=m.group(2), resource='ssh_server', task='failed_login',
                    execution_date=_parse_date(m.group(1)), source='auth.log', raw=line.strip())

    # sudo
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sudo.*:\s+(\S+)\s+:.*COMMAND=(.+)', line)
    if m:
        return dict(username=m.group(2), resource=_cmd_to_resource(m.group(3)),
                    task='execute', execution_date=_parse_date(m.group(1)),
                    source='auth.log', raw=line.strip())

    # su
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*su.*:\s+\(to (\S+)\) (\S+)', line)
    if m:
        return dict(username=m.group(3), resource='system', task='admin',
                    execution_date=_parse_date(m.group(1)), source='auth.log', raw=line.strip())

    # Nouveau login PAM
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*pam.*session opened.*for user (\S+)', line, re.IGNORECASE)
    if m:
        return dict(username=m.group(2), resource='system', task='login',
                    execution_date=_parse_date(m.group(1)), source='syslog', raw=line.strip())

    # useradd / usermod
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*useradd.*new user.*name=(\S+)', line)
    if m:
        return dict(username=m.group(2), resource='user_management', task='write',
                    execution_date=_parse_date(m.group(1)), source='auth.log', raw=line.strip())

    return None


def _parse_audit_line(line: str) -> dict | None:
    """Parse une ligne de /var/log/audit/audit.log."""
    if 'type=USER_LOGIN' in line or 'type=USER_AUTH' in line:
        user_m = re.search(r'acct="(\S+)"', line)
        res_m  = re.search(r'res=(\S+)', line)
        ts_m   = re.search(r'msg=audit\((\d+)', line)
        if user_m:
            ts = datetime.fromtimestamp(float(ts_m.group(1))) if ts_m else datetime.utcnow()
            task = 'login' if (res_m and 'success' in res_m.group(1)) else 'failed_login'
            return dict(username=user_m.group(1), resource='system', task=task,
                        execution_date=ts, source='audit.log', raw=line.strip())

    if 'type=EXECVE' in line:
        user_m = re.search(r'uid=(\d+)', line)
        cmd_m  = re.search(r'a0="([^"]+)"', line)
        ts_m   = re.search(r'msg=audit\((\d+)', line)
        if user_m and cmd_m:
            ts = datetime.fromtimestamp(float(ts_m.group(1))) if ts_m else datetime.utcnow()
            try:
                import pwd
                username = pwd.getpwuid(int(user_m.group(1))).pw_name
            except Exception:
                username = f'uid_{user_m.group(1)}'
            return dict(username=username, resource=_cmd_to_resource(cmd_m.group(1)),
                        task='execute', execution_date=ts,
                        source='audit.log', raw=line.strip())
    return None


class LinuxLogCollector(threading.Thread):
    """Surveille les fichiers de log Linux en temps réel (tail -f)."""

    def __init__(self):
        super().__init__(daemon=True, name='LinuxLogCollector')
        self._log_file = None
        self._audit_file = None
        self._log_pos = 0
        self._audit_pos = 0

    def _find_log(self):
        for path in LINUX_LOG_CANDIDATES[:3]:  # auth.log / secure / syslog
            if os.path.exists(path):
                try:
                    open(path).close()
                    return path
                except PermissionError:
                    continue
        return None

    def run(self):
        self._log_file = self._find_log()
        if not self._log_file:
            logwatcher_status['error'] = 'auth.log inaccessible — lancez avec sudo'
            status['errors'].append('auth.log inaccessible — lancez avec sudo')
            return

        logwatcher_status['active']     = True
        logwatcher_status['log_file']   = self._log_file
        logwatcher_status['started_at'] = datetime.utcnow()

        self._log_pos = os.path.getsize(self._log_file)
        if os.path.exists('/var/log/audit/audit.log'):
            try:
                open('/var/log/audit/audit.log').close()
                self._audit_file = '/var/log/audit/audit.log'
                self._audit_pos = os.path.getsize(self._audit_file)
            except PermissionError:
                pass

        sources = [self._log_file]
        if self._audit_file:
            sources.append(self._audit_file)
        status['sources'].extend(sources)

        while True:
            self._poll_log()
            if self._audit_file:
                self._poll_audit()
            time.sleep(2)

    def _poll_log(self):
        try:
            size = os.path.getsize(self._log_file)
            if size > self._log_pos:
                with open(self._log_file, encoding='utf-8', errors='replace') as f:
                    f.seek(self._log_pos)
                    for line in f:
                        logwatcher_status['lines_processed'] += 1
                        ev = _parse_auth_line(line)
                        if ev:
                            write_event(**ev)
                            logwatcher_status['entries_created'] += 1
                self._log_pos = size
        except Exception as e:
            status['errors'].append(f'LinuxLogCollector: {e}')

    def _poll_audit(self):
        try:
            size = os.path.getsize(self._audit_file)
            if size > self._audit_pos:
                with open(self._audit_file, encoding='utf-8', errors='replace') as f:
                    f.seek(self._audit_pos)
                    for line in f:
                        ev = _parse_audit_line(line)
                        if ev:
                            write_event(**ev)
                self._audit_pos = size
        except Exception as e:
            status['errors'].append(f'AuditCollector: {e}')


# ════════════════════════════════════════════════════════════════════════════
# COLLECTEUR WINDOWS — Windows Event Log
# ════════════════════════════════════════════════════════════════════════════

class WindowsLogCollector(threading.Thread):
    """Lit le journal d'événements Windows (Security, System) via wevtutil."""

    # Event IDs importants :
    # 4624 = login réussi, 4625 = login échoué, 4672 = admin privileges
    # 4688 = nouveau processus, 4663 = accès fichier, 4720 = user créé
    # 4732 = ajout groupe, 4728 = ajout groupe admin

    QUERIES = {
        'Security': {
            4624: ('login',        'system'),
            4625: ('failed_login', 'system'),
            4672: ('admin',        'system'),
            4688: ('execute',      'system'),
            4663: ('read',         'file_storage'),
            4720: ('write',        'user_management'),
            4732: ('write',        'user_management'),
        },
        'System': {
            7045: ('execute', 'system'),   # nouveau service installé
        }
    }

    def __init__(self):
        super().__init__(daemon=True, name='WindowsLogCollector')
        self._last_record = {}

    def _get_last_record_id(self, channel):
        try:
            result = subprocess.run(
                ['wevtutil', 'gli', channel],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if 'lastRecordNumber' in line:
                    return int(line.split(':')[1].strip())
        except Exception:
            pass
        return 0

    def _query_events(self, channel, last_id, count=50):
        try:
            xpath = f"*[System/EventRecordID>{last_id}]"
            result = subprocess.run(
                ['wevtutil', 'qe', channel, f'/q:{xpath}',
                 f'/c:{count}', '/rd:true', '/f:xml'],
                capture_output=True, text=True, timeout=15
            )
            return result.stdout
        except Exception:
            return ''

    def _parse_xml_events(self, xml_str, channel):
        import xml.etree.ElementTree as ET
        events = []
        ns = 'http://schemas.microsoft.com/win/2004/08/events/event'

        # wevtutil peut retourner plusieurs événements non encapsulés
        xml_str = f'<root>{xml_str}</root>'
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return events

        for ev in root.findall(f'{{{ns}}}Event'):
            try:
                system = ev.find(f'{{{ns}}}System')
                event_id = int(system.find(f'{{{ns}}}EventID').text)
                record_id = int(system.find(f'{{{ns}}}EventRecordID').text)
                ts_str = system.find(f'{{{ns}}}TimeCreated').attrib.get('SystemTime', '')
                ts = datetime.fromisoformat(ts_str.replace('Z', '')) if ts_str else datetime.utcnow()

                # Extraire le nom d'utilisateur depuis EventData
                username = 'SYSTEM'
                ed = ev.find(f'{{{ns}}}EventData')
                if ed is not None:
                    for data in ed.findall(f'{{{ns}}}Data'):
                        name = data.attrib.get('Name', '')
                        if name in ('SubjectUserName', 'TargetUserName', 'AccountName'):
                            val = data.text or ''
                            if val and val not in ('-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'):
                                username = val
                                break

                if event_id in self.QUERIES.get(channel, {}):
                    task, resource = self.QUERIES[channel][event_id]
                    events.append({
                        'username': username,
                        'resource': resource,
                        'task': task,
                        'execution_date': ts,
                        'source': f'Windows/{channel}',
                        'raw': f'EventID={event_id} RecordID={record_id}',
                        '_record_id': record_id,
                    })
            except Exception:
                continue
        return events

    def run(self):
        for channel in self.QUERIES:
            self._last_record[channel] = self._get_last_record_id(channel)

        status['sources'].append('Windows Event Log (Security, System)')

        while True:
            for channel in self.QUERIES:
                xml_str = self._query_events(channel, self._last_record[channel])
                if xml_str.strip():
                    events = self._parse_xml_events(xml_str, channel)
                    for ev in events:
                        rid = ev.pop('_record_id', 0)
                        write_event(**ev)
                        if rid > self._last_record[channel]:
                            self._last_record[channel] = rid
            time.sleep(5)


# ════════════════════════════════════════════════════════════════════════════
# COLLECTEUR WINDOWS — Sysmon (équivalent auditd)
# ════════════════════════════════════════════════════════════════════════════

class SysmonCollector(threading.Thread):
    """Lit le journal Sysmon — surveillance système avancée sur Windows.

    Sysmon doit être installé séparément:
      Sysmon64.exe -accepteula -i sysmonconfig.xml

    Event IDs surveillés:
      1  = Process Create
      3  = Network Connection
      7  = Image Loaded (DLL injection)
      11 = File Create
      12 = Registry Object Create/Delete
      13 = Registry Value Set
      22 = DNS Query
      25 = Process Tampering
    """

    SYSMON_CHANNEL = 'Microsoft-Windows-Sysmon/Operational'

    EVENT_MAP = {
        1:  ('execute',         'system',          'Process créé'),
        3:  ('network_access',  'network_scanner', 'Connexion réseau'),
        7:  ('execute',         'system',          'DLL chargée'),
        11: ('write',           'file_system',     'Fichier créé'),
        12: ('write',           'registry',        'Clé registre modifiée'),
        13: ('write',           'registry',        'Valeur registre modifiée'),
        22: ('network_access',  'network_scanner', 'Requête DNS'),
        25: ('execute',         'system',          'Process Tampering détecté'),
    }

    # Process suspects souvent utilisés en post-exploitation
    SUSPICIOUS_PROC = {
        'mimikatz.exe', 'psexec.exe', 'psexec64.exe', 'rundll32.exe',
        'mshta.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe',
        'regsvr32.exe', 'cscript.exe', 'wscript.exe',
        'powershell_ise.exe', 'cmd.exe',
    }

    # Clés registre de persistence Windows (HKLM/HKCU)
    PERSISTENCE_KEYS = (
        r'\Run', r'\RunOnce', r'\RunServices', r'\RunOnceEx',
        r'\Explorer\Run', r'\Image File Execution Options',
        r'\Winlogon\Shell', r'\Winlogon\Userinit',
        r'\AppInit_DLLs', r'\Schedule\TaskCache',
    )

    def __init__(self):
        super().__init__(daemon=True, name='SysmonCollector')
        self._last_record = 0

    def _sysmon_available(self):
        """Vérifie si Sysmon est installé en interrogeant le journal."""
        try:
            result = subprocess.run(
                ['wevtutil', 'gl', self.SYSMON_CHANNEL],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _get_last_record_id(self):
        try:
            result = subprocess.run(
                ['wevtutil', 'gli', self.SYSMON_CHANNEL],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if 'lastRecordNumber' in line:
                    return int(line.split(':')[1].strip())
        except Exception:
            pass
        return 0

    def _query_events(self, last_id, count=100):
        try:
            xpath = f"*[System/EventRecordID>{last_id}]"
            result = subprocess.run(
                ['wevtutil', 'qe', self.SYSMON_CHANNEL,
                 f'/q:{xpath}', f'/c:{count}', '/rd:true', '/f:xml'],
                capture_output=True, text=True, timeout=20
            )
            return result.stdout
        except Exception:
            return ''

    def _extract_data(self, ed_node, ns):
        """Extrait les <Data Name="X">val</Data> en dict."""
        out = {}
        if ed_node is None:
            return out
        for d in ed_node.findall(f'{{{ns}}}Data'):
            name = d.attrib.get('Name', '')
            val  = d.text or ''
            if name:
                out[name] = val
        return out

    def _parse_xml_events(self, xml_str):
        import xml.etree.ElementTree as ET
        events = []
        ns = 'http://schemas.microsoft.com/win/2004/08/events/event'
        xml_str = f'<root>{xml_str}</root>'
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return events

        for ev in root.findall(f'{{{ns}}}Event'):
            try:
                system    = ev.find(f'{{{ns}}}System')
                event_id  = int(system.find(f'{{{ns}}}EventID').text)
                record_id = int(system.find(f'{{{ns}}}EventRecordID').text)
                ts_str    = system.find(f'{{{ns}}}TimeCreated').attrib.get('SystemTime', '')
                try:
                    ts = datetime.fromisoformat(ts_str.replace('Z', '')[:26])
                except Exception:
                    ts = datetime.utcnow()

                if event_id not in self.EVENT_MAP:
                    continue

                task, resource, label = self.EVENT_MAP[event_id]
                data = self._extract_data(ev.find(f'{{{ns}}}EventData'), ns)

                # Username (User attribute style: DOMAIN\User)
                user_full = data.get('User', 'SYSTEM')
                username  = user_full.split('\\')[-1] if '\\' in user_full else user_full

                raw_parts = [f'Sysmon Event {event_id}: {label}']

                # ─── Event-specific enrichment ─────────────
                severity = 'medium'

                if event_id == 1:  # Process Create
                    img  = data.get('Image', '')
                    cmd  = data.get('CommandLine', '')
                    parent = data.get('ParentImage', '')
                    proc_name = img.split('\\')[-1].lower()
                    raw_parts.append(f'image={img}')
                    raw_parts.append(f'cmd={cmd[:120]}')
                    raw_parts.append(f'parent={parent}')

                    if proc_name in self.SUSPICIOUS_PROC:
                        severity = 'high'
                        raw_parts.append('[SUSPICIOUS PROCESS]')

                    # Détection LOLBins (Living Off The Land)
                    lol = ['certutil', 'bitsadmin', 'mshta', 'rundll32',
                           'regsvr32', 'wmic', 'powershell -enc',
                           'powershell -encodedcommand', 'invoke-expression']
                    cmd_lc = cmd.lower()
                    if any(l in cmd_lc for l in lol):
                        severity = 'critical'
                        raw_parts.append('[LOLBin/Obfuscation]')

                elif event_id == 3:  # Network Connection
                    dst_ip   = data.get('DestinationIp', '')
                    dst_port = data.get('DestinationPort', '')
                    proto    = data.get('Protocol', '')
                    img      = data.get('Image', '').split('\\')[-1]
                    raw_parts.append(f'{img} → {dst_ip}:{dst_port} ({proto})')

                elif event_id == 7:  # Image Loaded
                    img    = data.get('Image', '').split('\\')[-1]
                    loaded = data.get('ImageLoaded', '').split('\\')[-1]
                    raw_parts.append(f'{img} chargea {loaded}')
                    if not data.get('Signed', '').lower() == 'true':
                        severity = 'high'
                        raw_parts.append('[UNSIGNED DLL]')

                elif event_id == 11:  # File Create
                    target = data.get('TargetFilename', '')
                    img    = data.get('Image', '').split('\\')[-1]
                    raw_parts.append(f'{img} créa {target}')
                    # Détection drop dans dossiers persistence
                    persistence_dirs = ['\\Startup\\', '\\Start Menu\\',
                                        'AppData\\Roaming', 'Temp\\']
                    if any(p in target for p in persistence_dirs) and \
                       target.lower().endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs')):
                        severity = 'high'
                        raw_parts.append('[PERSISTENCE LOCATION]')

                elif event_id in (12, 13):  # Registry
                    target = data.get('TargetObject', '')
                    img    = data.get('Image', '').split('\\')[-1]
                    raw_parts.append(f'{img}: {target}')
                    if any(k in target for k in self.PERSISTENCE_KEYS):
                        severity = 'critical'
                        raw_parts.append('[PERSISTENCE KEY MODIFIED]')

                elif event_id == 22:  # DNS Query
                    qname  = data.get('QueryName', '')
                    img    = data.get('Image', '').split('\\')[-1]
                    raw_parts.append(f'{img} → {qname}')
                    suspect_tlds = ['.onion', '.bit', '.i2p']
                    suspect_kw   = ['ngrok', 'pastebin', 'serveo', 'pagekite',
                                    'requestbin', 'webhook', 'burpcollaborator']
                    if any(qname.endswith(t) for t in suspect_tlds) or \
                       any(k in qname.lower() for k in suspect_kw):
                        severity = 'high'
                        raw_parts.append('[SUSPICIOUS DOMAIN]')

                elif event_id == 25:  # Process Tampering
                    severity = 'critical'

                events.append({
                    'username': username,
                    'resource': resource,
                    'task':     task,
                    'execution_date': ts,
                    'source':   'sysmon',
                    'raw':      ' | '.join(raw_parts),
                    '_severity': severity,
                    '_record_id': record_id,
                })
            except Exception:
                continue
        return events

    def run(self):
        if not self._sysmon_available():
            print('[MODULE 1] Sysmon: non installé — '
                  'téléchargez https://docs.microsoft.com/sysinternals/downloads/sysmon',
                  file=sys.stderr)
            return

        self._last_record = self._get_last_record_id()
        status['sources'].append('Sysmon (Windows)')
        print(f'[MODULE 1] Sysmon: démarré (last record={self._last_record})',
              file=sys.stderr)

        while True:
            try:
                xml_str = self._query_events(self._last_record)
                if xml_str.strip():
                    events = self._parse_xml_events(xml_str)
                    for ev in events:
                        rid = ev.pop('_record_id', 0)
                        if rid > self._last_record:
                            self._last_record = rid
                        write_event(**{k: v for k, v in ev.items()
                                       if not k.startswith('_')})
            except Exception as e:
                status['errors'].append(f'Sysmon: {e}')

            time.sleep(3)


# ════════════════════════════════════════════════════════════════════════════
# NIDS — Moteur de règles réseau
# ════════════════════════════════════════════════════════════════════════════

NIDS_RULES_FILE = os.path.join(BASE_DIR, 'nids_rules.conf')

nids_status = {
    'rules':       0,
    'whitelisted': 0,
    'signatures':  0,
}

# ── Structures de règles chargées ────────────────────────────────────────────
_nids_port_rules: dict  = {}   # port → [{'severity','resource','msg'}]
_nids_payload_rules: list = [] # [{'pattern','severity','resource','msg'}]
_nids_whitelist_ips: set  = set()
_nids_whitelist_nets: list = [] # [(network_int, mask_int)]
_nids_lock = threading.Lock()


def _ip_to_int(ip: str) -> int:
    parts = ip.split('.')
    return sum(int(p) << (24 - 8*i) for i, p in enumerate(parts))


def _load_nids_rules(path: str = NIDS_RULES_FILE):
    """
    Charge nids_rules.conf.
    Recharge à chaud sans redémarrer l'app.
    """
    global _nids_port_rules, _nids_payload_rules, _nids_whitelist_ips, _nids_whitelist_nets

    port_rules:    dict  = defaultdict(list)
    payload_rules: list  = []
    whitelist_ips: set   = set()
    whitelist_nets: list = []

    if not os.path.exists(path):
        _create_default_nids_rules(path)

    with open(path, encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split(';')]
            if len(parts) < 4:
                continue

            action = parts[0].lower()

            if action == 'alert' and len(parts) >= 6:
                # alert;proto;port;payload_pattern;severity;description
                _, proto, port_str, pattern, severity, msg = parts[:6]
                resource = parts[6] if len(parts) > 6 else _port_to_resource(port_str)
                entry = {
                    'proto':    proto.lower(),
                    'severity': severity,
                    'resource': resource,
                    'msg':      msg,
                    'pattern':  pattern if pattern != '-' else '',
                }
                if port_str == 'any':
                    if entry['pattern']:
                        payload_rules.append(entry)
                else:
                    try:
                        port_rules[int(port_str)].append(entry)
                        if entry['pattern']:
                            payload_rules.append({**entry, 'port': int(port_str)})
                    except ValueError:
                        pass

            elif action == 'whitelist' and len(parts) >= 3:
                # whitelist;ip;192.168.1.1;description
                # whitelist;net;192.168.0.0/24;description
                wtype, value = parts[1].lower(), parts[2]
                if wtype == 'ip':
                    whitelist_ips.add(value)
                elif wtype == 'net' and '/' in value:
                    net_ip, prefix = value.split('/')
                    mask = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
                    whitelist_nets.append((_ip_to_int(net_ip) & mask, mask))

    with _nids_lock:
        _nids_port_rules     = dict(port_rules)
        _nids_payload_rules  = payload_rules
        _nids_whitelist_ips  = whitelist_ips
        _nids_whitelist_nets = whitelist_nets

    nids_status['rules']       = sum(len(v) for v in port_rules.values())
    nids_status['whitelisted'] = len(whitelist_ips) + len(whitelist_nets)
    nids_status['signatures']  = len(payload_rules)

    return nids_status['rules']


def _port_to_resource(port_str: str) -> str:
    mapping = {
        '22': 'ssh_server', '23': 'telnet_server', '21': 'ftp_server',
        '3306': 'database', '5432': 'database', '1433': 'database',
        '27017': 'database', '6379': 'database',
        '445': 'file_storage', '139': 'file_storage',
        '3389': 'rdp_server', '25': 'email_server', '587': 'email_server',
    }
    return mapping.get(port_str, 'network_scanner')


def _is_whitelisted(ip: str) -> bool:
    if ip in _nids_whitelist_ips:
        return True
    try:
        ip_int = _ip_to_int(ip)
        for net, mask in _nids_whitelist_nets:
            if (ip_int & mask) == net:
                return True
    except Exception:
        pass
    return False


def _create_default_nids_rules(path: str):
    """Crée nids_rules.conf avec des règles par défaut si absent."""
    content = """\
# ══════════════════════════════════════════════════════════════════════════════
# IDS Web — Règles NIDS (Network Intrusion Detection System)
#
# Format règle  : alert;proto;port;payload_pattern;severity;description;resource
# Format whitelist: whitelist;ip|net;valeur;description
#
# Champs :
#   proto          : tcp | udp | any
#   port           : numéro de port ou 'any'
#   payload_pattern: sous-chaîne à chercher (insensible à la casse), ou '-'
#   severity       : critical | high | medium | low
#   description    : texte libre
#   resource       : (optionnel) nom de ressource IDS
#
# Modifier ce fichier et recharger l'IDS — les règles s'appliquent à chaud.
# ══════════════════════════════════════════════════════════════════════════════

# ── WHITELIST — IPs/réseaux autorisés (jamais alertés) ───────────────────────
whitelist;ip;127.0.0.1;Loopback local
whitelist;net;10.0.0.0/8;Réseau privé classe A
whitelist;net;172.16.0.0/12;Réseau privé classe B
whitelist;net;192.168.0.0/16;Réseau privé classe C

# ── PORTS DANGEREUX — connexions suspectes ────────────────────────────────────
alert;tcp;22;-;medium;Connexion SSH détectée;ssh_server
alert;tcp;23;-;high;Telnet — protocole non chiffré;telnet_server
alert;tcp;21;-;medium;FTP — protocole non chiffré;ftp_server
alert;tcp;3389;-;high;Connexion RDP (Bureau à distance);rdp_server
alert;tcp;5900;-;high;Connexion VNC;rdp_server

# ── BASES DE DONNÉES EXPOSÉES ────────────────────────────────────────────────
alert;tcp;3306;-;high;MySQL exposé sur le réseau;database
alert;tcp;5432;-;high;PostgreSQL exposé sur le réseau;database
alert;tcp;1433;-;high;MSSQL exposé sur le réseau;database
alert;tcp;27017;-;high;MongoDB exposé (sans auth par défaut);database
alert;tcp;6379;-;high;Redis exposé (sans auth par défaut);database
alert;tcp;9200;-;high;Elasticsearch exposé;database
alert;tcp;5984;-;medium;CouchDB exposé;database

# ── PARTAGE DE FICHIERS ───────────────────────────────────────────────────────
alert;tcp;445;-;high;SMB — partage Windows (EternalBlue);file_storage
alert;tcp;139;-;medium;NetBIOS;file_storage
alert;tcp;2049;-;medium;NFS exposé sur le réseau;file_storage

# ── PORTS C2 ET REVERSE SHELLS ───────────────────────────────────────────────
alert;tcp;4444;-;critical;Port Metasploit par défaut;network_scanner
alert;tcp;4445;-;critical;Port reverse shell suspect;network_scanner
alert;tcp;1337;-;critical;Port C2 suspect (leet);network_scanner
alert;tcp;6666;-;critical;Port IRC/C2 suspect;network_scanner
alert;tcp;6667;-;critical;Port IRC/C2 suspect;network_scanner
alert;tcp;9001;-;critical;Port Tor/C2 suspect;network_scanner
alert;tcp;8888;-;medium;Port non standard suspect;network_scanner
alert;tcp;31337;-;critical;Port backdoor classique (élite);network_scanner

# ── EMAIL ─────────────────────────────────────────────────────────────────────
alert;tcp;25;-;medium;Connexion SMTP (relai possible);email_server
alert;tcp;587;-;medium;Connexion SMTP avec auth;email_server

# ── SIGNATURES PAYLOAD — détection par contenu ───────────────────────────────
# SQL Injection
alert;any;any;SELECT * FROM;critical;Injection SQL — SELECT *;database
alert;any;any;UNION SELECT;critical;Injection SQL — UNION SELECT;database
alert;any;any;DROP TABLE;critical;Injection SQL — DROP TABLE;database
alert;any;any;INSERT INTO;high;Injection SQL — INSERT INTO;database
alert;any;any;' OR '1'='1;critical;Injection SQL — bypass auth;database
alert;any;any;1=1--;critical;Injection SQL — toujours vrai;database

# Shells et commandes
alert;any;any;/bin/sh;critical;Tentative injection shell;system
alert;any;any;/bin/bash;critical;Tentative injection bash;system
alert;any;any;cmd.exe;critical;Tentative injection cmd Windows;system
alert;any;any;powershell;high;Commande PowerShell dans payload;system

# Traversée de répertoires
alert;any;any;../../../;high;Path traversal détecté;web_server
alert;any;any;..\\..\\;high;Path traversal Windows détecté;web_server

# XSS
alert;any;any;<script>;high;Tentative XSS — balise script;web_server
alert;any;any;javascript:;high;Tentative XSS — javascript:;web_server
"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


# ── Scan de ports (fenêtre glissante) ────────────────────────────────────────
_port_tracker:    dict = defaultdict(set)
_port_first_seen: dict = {}
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW    = 60


def _check_port_scan(src_ip: str, port: int) -> tuple[bool, int]:
    now   = time.time()
    first = _port_first_seen.get(src_ip, now)
    if now - first > PORT_SCAN_WINDOW:
        _port_tracker[src_ip]    = set()
        _port_first_seen[src_ip] = now
    if src_ip not in _port_first_seen:
        _port_first_seen[src_ip] = now
    _port_tracker[src_ip].add(port)
    n = len(_port_tracker[src_ip])
    triggered = (n == PORT_SCAN_THRESHOLD or
                 (n > PORT_SCAN_THRESHOLD and (n - PORT_SCAN_THRESHOLD) % 10 == 0))
    return triggered, n


# ── Suivi d'état des connexions TCP ─────────────────────────────────────────
class _ConnState:
    __slots__ = ('src','dst','dport','proto','started','packets','alerted')
    def __init__(self, src, dst, dport, proto):
        self.src     = src
        self.dst     = dst
        self.dport   = dport
        self.proto   = proto
        self.started = time.time()
        self.packets = 0
        self.alerted = False

_tcp_sessions: dict  = {}   # (src,dst,dport) → _ConnState
_conn_dedup:   dict  = {}   # (src,dport) → last_alert_ts
CONN_DEDUP_WIN = 60


def _session_key(src, dst, dport):
    return (src, dst, dport)


def _track_session(src, dst, dport, proto, flags=0) -> _ConnState:
    key   = _session_key(src, dst, dport)
    state = _tcp_sessions.get(key)
    if state is None:
        state = _ConnState(src, dst, dport, proto)
        _tcp_sessions[key] = state
    state.packets += 1
    # FIN ou RST → fermeture
    if flags & 0x05:  # FIN=0x01, RST=0x04
        _tcp_sessions.pop(key, None)
    # Nettoyage sessions > 30 min
    if len(_tcp_sessions) > 10000:
        now = time.time()
        dead = [k for k, v in _tcp_sessions.items() if now - v.started > 1800]
        for k in dead:
            del _tcp_sessions[k]
    return state


# ── Extraction SNI depuis TLS ClientHello (sans déchiffrement) ──────────────
def _extract_sni(raw: bytes) -> str:
    """
    Lit le SNI (Server Name Indication) du ClientHello TLS.
    Ce champ est envoyé en clair même dans TLS 1.3.
    Retourne le hostname ou '' si absent/non parsable.
    """
    try:
        if len(raw) < 6 or raw[0] != 0x16:   # type Handshake
            return ''
        if raw[5] != 0x01:                     # ClientHello
            return ''
        pos = 43
        if pos >= len(raw): return ''
        pos += 1 + raw[pos]                    # session ID
        if pos + 2 > len(raw): return ''
        pos += 2 + int.from_bytes(raw[pos:pos+2], 'big')  # cipher suites
        if pos >= len(raw): return ''
        pos += 1 + raw[pos]                    # compression methods
        if pos + 2 > len(raw): return ''
        ext_end = pos + 2 + int.from_bytes(raw[pos:pos+2], 'big')
        pos += 2
        while pos + 4 <= ext_end and pos + 4 <= len(raw):
            etype = int.from_bytes(raw[pos:pos+2], 'big')
            elen  = int.from_bytes(raw[pos+2:pos+4], 'big')
            pos  += 4
            if etype == 0x0000 and pos + 5 <= len(raw):  # SNI
                nlen = int.from_bytes(raw[pos+3:pos+5], 'big')
                return raw[pos+5:pos+5+nlen].decode('ascii', errors='replace')
            pos += elen
    except Exception:
        pass
    return ''


# ── Fingerprint JA3 — TLS ClientHello (identifie client TLS) ───────────────
# JA3 = MD5(version,ciphers,extensions,curves,curve_formats)
# Identifie de manière unique le client TLS (curl vs Firefox vs malware)
def _extract_ja3(raw: bytes) -> str:
    """Calcule la signature JA3 d'un ClientHello TLS."""
    import hashlib as _h
    try:
        if len(raw) < 6 or raw[0] != 0x16 or raw[5] != 0x01:
            return ''
        # TLS version
        version = int.from_bytes(raw[9:11], 'big')
        pos = 11 + 32  # skip 32-byte random
        # Session ID
        sid_len = raw[pos]
        pos += 1 + sid_len
        # Cipher suites
        cs_len = int.from_bytes(raw[pos:pos+2], 'big')
        pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            c = int.from_bytes(raw[pos+i:pos+i+2], 'big')
            # Filtrer GREASE values (RFC 8701)
            if (c & 0x0F0F) != 0x0A0A:
                ciphers.append(c)
        pos += cs_len
        # Compression methods
        cm_len = raw[pos]
        pos += 1 + cm_len
        # Extensions
        ext_len = int.from_bytes(raw[pos:pos+2], 'big')
        pos += 2
        ext_end = pos + ext_len
        extensions, curves, curve_formats = [], [], []
        while pos + 4 <= ext_end and pos + 4 <= len(raw):
            etype = int.from_bytes(raw[pos:pos+2], 'big')
            elen  = int.from_bytes(raw[pos+2:pos+4], 'big')
            pos  += 4
            if (etype & 0x0F0F) != 0x0A0A:
                extensions.append(etype)
            if etype == 10 and pos + 2 <= len(raw):  # supported_groups
                cl = int.from_bytes(raw[pos:pos+2], 'big')
                for i in range(2, cl + 2, 2):
                    c = int.from_bytes(raw[pos+i:pos+i+2], 'big')
                    if (c & 0x0F0F) != 0x0A0A:
                        curves.append(c)
            if etype == 11 and pos + 1 <= len(raw):  # ec_point_formats
                fl = raw[pos]
                for i in range(1, fl + 1):
                    curve_formats.append(raw[pos+i])
            pos += elen
        # Construire la chaîne JA3
        s = (f"{version},"
             f"{'-'.join(str(x) for x in ciphers)},"
             f"{'-'.join(str(x) for x in extensions)},"
             f"{'-'.join(str(x) for x in curves)},"
             f"{'-'.join(str(x) for x in curve_formats)}")
        return _h.md5(s.encode()).hexdigest()
    except Exception:
        return ''


# ── JA3 hashes connus comme malicieux (mini base) ───────────────────────────
KNOWN_BAD_JA3 = {
    '6734f37431670b3ab4292b8f60f29984': 'Trickbot',
    '54328bd36c14bd82ddaa0c04b25ed9ad': 'Emotet',
    'a0e9f5d64349fb13191bc781f81f42e1': 'Cobalt Strike',
    '72a589da586844d7f0818ce684948eea': 'Tor browser',
}


# ── Détection DNS tunneling ─────────────────────────────────────────────────
class DnsTunnelTracker:
    """Détecte le tunneling DNS via:
       - Trop de requêtes vers un domaine (volume)
       - Sous-domaines très longs (encoding base64)
       - Entropie élevée du sous-domaine (données chiffrées)
    """
    def __init__(self):
        self._domain_requests = defaultdict(list)   # domain → [timestamps]
        self._alerted = {}                          # domain → last_alert_ts

    @staticmethod
    def _shannon_entropy(s):
        """Entropie de Shannon (0=déterministe, ~5=aléatoire)."""
        from math import log2
        if not s:
            return 0
        prob = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * log2(p) for p in prob.values())

    def check(self, qname):
        """Retourne (suspect, raison) si la requête DNS est suspecte."""
        if not qname or '.' not in qname:
            return False, ''

        # Extraire le domaine racine (last 2 labels)
        parts = qname.rstrip('.').split('.')
        if len(parts) < 2:
            return False, ''
        root = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

        now = time.time()
        self._domain_requests[root] = [
            t for t in self._domain_requests[root] if now - t < 60
        ]
        self._domain_requests[root].append(now)

        # 1. Volume : > 50 requêtes en 60s vers le même domaine
        if len(self._domain_requests[root]) > 50:
            if now - self._alerted.get(root, 0) > 300:
                self._alerted[root] = now
                return True, f'volume anormal ({len(self._domain_requests[root])} req/60s)'

        # 2. Longueur : sous-domaine > 50 chars
        if subdomain and len(subdomain) > 50:
            if now - self._alerted.get(f'len:{root}', 0) > 300:
                self._alerted[f'len:{root}'] = now
                return True, f'sous-domaine très long ({len(subdomain)} chars)'

        # 3. Entropie : sous-domaine très aléatoire (>4.0)
        if subdomain and len(subdomain) > 15:
            ent = self._shannon_entropy(subdomain.replace('.', ''))
            if ent > 4.0:
                if now - self._alerted.get(f'ent:{root}', 0) > 300:
                    self._alerted[f'ent:{root}'] = now
                    return True, f'entropie haute ({ent:.2f}) — possible exfiltration'

        return False, ''

_dns_tracker = DnsTunnelTracker()


# ── Moteur de règles : applique les règles NIDS à un paquet ─────────────────
def _apply_rules(src: str, dst: str, port: int, proto: str,
                 payload_bytes: bytes, flags: int = 0):
    """
    Applique les règles NIDS chargées.
    Génère des événements IDS si une règle correspond.
    """
    if _is_whitelisted(src):
        return

    now = time.time()
    session = _track_session(src, dst, port, proto, flags)

    # ── 1. Scan de ports ────────────────────────────────────────────────
    scan_hit, n_ports = _check_port_scan(src, port)
    if scan_hit:
        write_event(
            username=src, resource='network_scanner', task='port_scan',
            execution_date=datetime.utcnow(), source='network/port_scan',
            raw=f'SCAN DE PORTS: {src} → {n_ports} ports en {PORT_SCAN_WINDOW}s'
        )

    # ── 2. SNI TLS (domaine chiffré visible en clair) ────────────────────
    sni = ''
    if port == 443 and payload_bytes:
        sni = _extract_sni(payload_bytes)
        if sni:
            # Domaines suspects (C2, exfiltration, tor)
            _suspicious_tlds = ('.onion', '.bit', '.i2p')
            _suspicious_kw   = ['pastebin', 'ngrok', 'serveo', 'pagekite',
                                 'requestbin', 'webhook', 'burpcollaborator']
            if any(sni.endswith(t) for t in _suspicious_tlds) or \
               any(k in sni for k in _suspicious_kw):
                write_event(
                    username=src, resource='network_scanner', task='connect',
                    execution_date=datetime.utcnow(), source='network/tls_sni',
                    raw=f'TLS SNI SUSPECT: {src} → {sni}'
                )

    # ── 3. Règles par port ───────────────────────────────────────────────
    with _nids_lock:
        port_matches = list(_nids_port_rules.get(port, []))

    for rule in port_matches:
        if rule['proto'] not in ('any', proto.lower()):
            continue
        # Déduplication par (src, port)
        key = (src, port)
        if now - _conn_dedup.get(key, 0) < CONN_DEDUP_WIN:
            continue
        _conn_dedup[key] = now

        extra = f' [SNI: {sni}]' if sni else ''
        write_event(
            username=src,
            resource=rule['resource'],
            task='connect',
            execution_date=datetime.utcnow(),
            source=f'network/{proto}',
            raw=f"{rule['msg']}: {src}:{port} → {dst}{extra}"
        )

    # ── 4. Signatures payload ─────────────────────────────────────────────
    if not payload_bytes:
        return
    try:
        payload_str = payload_bytes.decode('utf-8', errors='replace').lower()
    except Exception:
        return

    with _nids_lock:
        sig_rules = list(_nids_payload_rules)

    for rule in sig_rules:
        pat = rule['pattern'].lower()
        if not pat or pat not in payload_str:
            continue
        # Vérifier port si la règle est liée à un port
        if 'port' in rule and rule['port'] != port:
            continue
        key = (src, pat[:20])
        if now - _conn_dedup.get(key, 0) < CONN_DEDUP_WIN:
            continue
        _conn_dedup[key] = now
        write_event(
            username=src,
            resource=rule['resource'],
            task='execute',
            execution_date=datetime.utcnow(),
            source='network/signature',
            raw=f"{rule['msg']}: {src} → {dst}:{port} | payload: {payload_str[:120]}"
        )


# ── Thread de capture ────────────────────────────────────────────────────────
class NetworkCapture(threading.Thread):
    """Capture les paquets IP et applique le moteur de règles NIDS.

    Lance un thread sniff par interface (y compris lo) pour capturer
    TOUT le trafic, qu'il soit local (loopback) ou externe.
    Applique aussi les règles NIDS personnalisées depuis la DB.
    """

    def __init__(self, app=None):
        super().__init__(daemon=True, name='NetworkCapture')
        self._count = 0
        self._rules_mtime = 0
        self._pkt_count = 0
        self._lock = threading.Lock()
        self._app = app
        self._db_rules = []        # Règles NIDS compilées depuis la DB
        self._db_dedup = {}        # (rule_id, src_ip) → last_alert_ts
        self._db_last_reload = 0

    # ── Compilation et matching des règles DB ──────────────────────────────
    def _compile_db_rule(self, r):
        """Compile une NidsRule pour un matching rapide."""
        try:
            src_net = self._parse_cidr(r.src_ip)
            dst_net = self._parse_cidr(r.dst_ip)
            src_pr  = self._parse_port_range(r.src_port)
            dst_pr  = self._parse_port_range(r.dst_port)
            flags   = set(f.strip().lower() for f in (r.tcp_flags or '').split('|') if f.strip())
            return {
                'id': r.id, 'name': r.name,
                'version': r.version, 'protocol': r.protocol.lower(),
                'src_net': src_net, 'dst_net': dst_net,
                'src_port_range': src_pr, 'dst_port_range': dst_pr,
                'tcp_flags': flags,
                'action': r.action.lower(), 'severity': r.severity,
            }
        except Exception as e:
            print(f'[MODULE 1] NIDS: règle #{r.id} ignorée ({e})', file=sys.stderr)
            return None

    @staticmethod
    def _parse_cidr(s):
        """Parse une IP/CIDR. Retourne (network_int, mask_int) ou None pour any."""
        s = (s or '').strip()
        if not s or s in ('any', '0.0.0.0/0', '*'):
            return None
        try:
            if '/' in s:
                ip, bits = s.split('/')
                bits = int(bits)
            else:
                ip, bits = s, 32
            ip_int = _ip_to_int(ip)
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            return (ip_int & mask, mask)
        except Exception:
            return None

    @staticmethod
    def _parse_port_range(s):
        """Parse un port range. Retourne (lo, hi) ou None pour any."""
        s = (s or '').strip()
        if not s or s.lower() == 'any' or s == '*':
            return None
        try:
            if '-' in s:
                a, b = s.split('-')
                return (int(a), int(b))
            p = int(s)
            return (p, p)
        except Exception:
            return None

    def _load_db_rules(self):
        """Recharge les règles depuis la DB."""
        if not self._app:
            return
        try:
            with self._app.app_context():
                from models import NidsRule
                rules = NidsRule.query.filter_by(active=True).all()
                compiled = []
                for r in rules:
                    c = self._compile_db_rule(r)
                    if c:
                        compiled.append(c)
                self._db_rules = compiled
                self._db_last_reload = time.time()
                print(f'[MODULE 1] NIDS DB: {len(compiled)} règle(s) DB chargée(s)',
                      file=sys.stderr)
        except Exception as e:
            print(f'[MODULE 1] NIDS DB ERROR: {e}', file=sys.stderr)

    def _match_db_rule(self, rule, src, dst, sport, dport, proto, flags_int):
        """Test si un paquet match une règle DB compilée."""
        # Version (TODO: ipv6)
        if rule['version'] not in ('any', 'ipv4'):
            return False
        # Protocol
        if rule['protocol'] not in ('any', proto.lower()):
            return False
        # IPs
        if rule['src_net']:
            try:
                src_int = _ip_to_int(src)
                if (src_int & rule['src_net'][1]) != rule['src_net'][0]:
                    return False
            except Exception:
                return False
        if rule['dst_net']:
            try:
                dst_int = _ip_to_int(dst)
                if (dst_int & rule['dst_net'][1]) != rule['dst_net'][0]:
                    return False
            except Exception:
                return False
        # Ports
        if rule['src_port_range']:
            lo, hi = rule['src_port_range']
            if not (lo <= sport <= hi):
                return False
        if rule['dst_port_range']:
            lo, hi = rule['dst_port_range']
            if not (lo <= dport <= hi):
                return False
        # TCP flags (si spécifiés)
        if rule['tcp_flags'] and proto.lower() == 'tcp':
            # Mapping flag name → bit
            flag_bits = {'fin': 0x01, 'syn': 0x02, 'rst': 0x04, 'psh': 0x08,
                         'ack': 0x10, 'urg': 0x20}
            wanted_bits = 0
            for f in rule['tcp_flags']:
                wanted_bits |= flag_bits.get(f, 0)
            if wanted_bits and (flags_int & wanted_bits) == 0:
                return False
        return True

    def _handle(self, pkt):
        """Callback partagé entre tous les threads sniff. Supporte IPv4 et IPv6."""
        try:
            from scapy.all import IP, IPv6, TCP, UDP, Raw, DNS
        except ImportError:
            return

        with self._lock:
            self._pkt_count += 1

        # Debug : afficher les 10 premiers paquets reçus
        if self._pkt_count <= 10:
            try:
                print(f'[MODULE 1] NIDS RAW pkt#{self._pkt_count}: {pkt.summary()[:100]}',
                      file=sys.stderr)
            except:
                pass

        # Support IPv4 et IPv6
        ip_version = 4
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            ip_version = 6
        else:
            return

        # Filtrer le trafic purement loopback
        if (src == '127.0.0.1' and dst == '127.0.0.1') or \
           (src == '::1' and dst == '::1'):
            return

        with self._lock:
            self._count += 1
            sniffer_status['packets_captured'] = self._count

        if self._count <= 20:
            print(f'[MODULE 1] NIDS DEBUG pkt#{self._count}: {src} → {dst}',
                  file=sys.stderr)

        # Hot reload des règles fichier toutes les 500 paquets
        if self._count % 500 == 0:
            try:
                mt = os.path.getmtime(NIDS_RULES_FILE)
                if mt != self._rules_mtime:
                    self._rules_mtime = mt
                    _load_nids_rules()
                    print(f'[MODULE 1] NIDS: règles fichier rechargées', file=sys.stderr)
            except Exception:
                pass

        # Hot reload des règles DB toutes les 30 secondes
        if time.time() - self._db_last_reload > 30:
            self._load_db_rules()

        sport = 0
        dport = 0
        proto = 'OTHER'
        flags = 0
        raw_payload = b''

        if TCP in pkt:
            proto = 'TCP'
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = int(pkt[TCP].flags)
            if Raw in pkt:
                raw_payload = bytes(pkt[Raw].load)
        elif UDP in pkt:
            proto = 'UDP'
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if Raw in pkt:
                raw_payload = bytes(pkt[Raw].load)

        # Ignorer les ports Flask
        if dport in (5000, 5001) or sport in (5000, 5001):
            return

        # ── JA3 fingerprinting (TLS ClientHello) ──────────────────
        if proto == 'TCP' and dport == 443 and raw_payload:
            ja3 = _extract_ja3(raw_payload)
            if ja3 and ja3 in KNOWN_BAD_JA3:
                malware_name = KNOWN_BAD_JA3[ja3]
                key = ('ja3', src, ja3)
                if time.time() - self._db_dedup.get(key, 0) > 300:
                    self._db_dedup[key] = time.time()
                    write_event(
                        username=src, resource='network_scanner',
                        task='network_access',
                        execution_date=datetime.utcnow(),
                        source='nids/ja3',
                        raw=f'[JA3 MATCH] Fingerprint {malware_name} détecté: '
                            f'src={src} dst={dst} ja3={ja3}'
                    )

        # ── DNS tunneling (port 53) ───────────────────────────────
        if dport == 53 and proto == 'UDP' and DNS in pkt:
            try:
                qd = pkt[DNS].qd
                if qd and qd.qname:
                    qname = qd.qname.decode('ascii', errors='replace').rstrip('.')
                    suspect, reason = _dns_tracker.check(qname)
                    if suspect:
                        write_event(
                            username=src, resource='network_scanner',
                            task='network_access',
                            execution_date=datetime.utcnow(),
                            source='nids/dns_tunnel',
                            raw=f'[DNS TUNNEL] {src} → {qname[:80]} ({reason})'
                        )
            except Exception:
                pass

        # Règles NIDS depuis la DB (custom)
        self._apply_db_rules(src, dst, sport, dport, proto, flags)

        # Règles NIDS fichier (par défaut)
        _apply_rules(src, dst, dport, proto, raw_payload, flags)

    def _apply_db_rules(self, src, dst, sport, dport, proto, flags):
        """Applique les règles NIDS personnalisées depuis la DB."""
        now = time.time()
        for rule in self._db_rules:
            if not self._match_db_rule(rule, src, dst, sport, dport, proto, flags):
                continue

            # Action 'accept' = whitelist, ne génère pas d'alerte
            if rule['action'] == 'accept':
                return  # Skip toute autre règle pour ce paquet

            # Déduplication par (rule_id, src) — 60s
            dedup_key = (rule['id'], src)
            if now - self._db_dedup.get(dedup_key, 0) < 60:
                continue
            self._db_dedup[dedup_key] = now

            # Action 'deny' ou 'alert' = générer un event
            severity = 'critical' if rule['action'] == 'deny' else rule['severity']
            action_label = 'BLOQUÉ' if rule['action'] == 'deny' else 'ALERTE'
            raw_msg = (f"{action_label} (règle #{rule['id']} '{rule['name']}'): "
                       f"{src}:{sport} → {dst}:{dport} ({proto})")
            write_event(
                username=src,
                resource='network_scanner',
                task='network_access',
                execution_date=datetime.utcnow(),
                source=f'nids/rule_{rule["id"]}',
                raw=raw_msg
            )
            with self._lock:
                sniffer_status['alerts'] = sniffer_status.get('alerts', 0) + 1

    def _sniff_iface(self, iface):
        """Lance sniff() sur une interface spécifique (thread dédié).
        Auto-restart si l'interface tombe (network down), avec backoff."""
        from scapy.all import sniff
        retry_delay = 5
        max_delay = 60

        while True:
            try:
                print(f'[MODULE 1] NIDS: sniff démarré sur {iface}', file=sys.stderr)
                sniff(iface=iface, prn=self._handle, store=False)
                # Si sniff retourne (interface fermée), on retry
                print(f'[MODULE 1] NIDS: sniff sur {iface} arrêté, retry dans {retry_delay}s',
                      file=sys.stderr)
            except Exception as e:
                msg = str(e)
                # Network down = interface inactive, skip silencieusement
                if 'Network is down' in msg or 'No such device' in msg:
                    print(f'[MODULE 1] NIDS: {iface} inactive, ignorée', file=sys.stderr)
                    return
                print(f'[MODULE 1] NIDS ERROR sur {iface}: {e}', file=sys.stderr)
                status['errors'].append(f'NetworkCapture({iface}): {e}')

            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_delay)

    def _is_admin_windows(self):
        """Vérifie si on a les droits Admin Windows."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _check_npcap_installed(self):
        """Vérifie si npcap est installé sur Windows."""
        try:
            paths = [
                r'C:\Windows\System32\Npcap',
                r'C:\Windows\SysWOW64\Npcap',
            ]
            return any(os.path.isdir(p) for p in paths)
        except Exception:
            return False

    def run(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
        except ImportError:
            sniffer_status['error'] = 'scapy non installé (pip install scapy)'
            status['errors'].append('NetworkCapture: pip install scapy')
            return

        # ── Vérification des droits selon OS ─────────────────────────
        if SYSTEM == 'Windows':
            if not self._is_admin_windows():
                sniffer_status['error'] = 'Droits Administrateur requis (clic droit → Exécuter en tant qu\'admin)'
                status['errors'].append('NetworkCapture: droits Admin requis')
                return
            if not self._check_npcap_installed():
                sniffer_status['error'] = 'npcap non installé — téléchargez https://npcap.com/'
                status['errors'].append('NetworkCapture: npcap requis sur Windows')
                print('[MODULE 1] NIDS: npcap manquant — capture désactivée', file=sys.stderr)
                return
        elif os.geteuid() != 0:
            sniffer_status['error'] = 'Droits root requis (lancez avec sudo)'
            status['errors'].append('NetworkCapture: droits root requis (sudo)')
            return

        # Charger les règles fichier
        n = _load_nids_rules()
        print(f'[MODULE 1] NIDS: {n} règles chargées depuis {NIDS_RULES_FILE}',
              file=sys.stderr)
        self._rules_mtime = os.path.getmtime(NIDS_RULES_FILE)

        # Charger les règles DB
        self._load_db_rules()

        # Lister TOUTES les interfaces (y compris lo)
        try:
            all_ifaces = get_if_list()
        except Exception as e:
            sniffer_status['error'] = f'get_if_list: {e}'
            return

        if not all_ifaces:
            sniffer_status['error'] = 'Aucune interface disponible'
            print(f'[MODULE 1] NIDS: aucune interface', file=sys.stderr)
            return

        # Filtrer les interfaces non pertinentes sur Windows
        if SYSTEM == 'Windows':
            # Exclure certaines interfaces Windows verbeuses
            all_ifaces = [i for i in all_ifaces
                          if 'isatap' not in i.lower()
                          and 'teredo' not in i.lower()]

        sniffer_status['interface'] = ','.join(all_ifaces)
        sniffer_status['active']     = True
        sniffer_status['error']      = None
        sniffer_status['started_at'] = datetime.utcnow()
        status['sources'].append('Réseau NIDS (scapy)')

        print(f'[MODULE 1] NIDS: interfaces détectées = {all_ifaces}', file=sys.stderr)

        # Lancer un thread sniff par interface
        threads = []
        for iface in all_ifaces:
            t = threading.Thread(target=self._sniff_iface, args=(iface,),
                                 daemon=True, name=f'sniff-{iface}')
            t.start()
            threads.append(t)
            print(f'[MODULE 1] NIDS: thread démarré pour {iface}', file=sys.stderr)

        # Attendre indéfiniment (les threads sont daemon)
        for t in threads:
            t.join()


# ════════════════════════════════════════════════════════════════════════════
# INTÉGRITÉ FICHIERS — hash SHA-256
# ════════════════════════════════════════════════════════════════════════════

class FileIntegrityMonitor(threading.Thread):
    """Surveille l'intégrité des fichiers critiques (SHA-256)."""

    def __init__(self):
        super().__init__(daemon=True, name='FileIntegrityMonitor')
        self._baseline = {}

    def _hash(self, path):
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def run(self):
        targets = _load_integrity_targets()
        existing = [p for p in targets if os.path.exists(p)]

        if not existing:
            return

        # Établir la baseline
        for path in existing:
            h = self._hash(path)
            if h:
                self._baseline[path] = h

        status['sources'].append(f'Intégrité fichiers ({len(existing)} fichiers)')

        while True:
            time.sleep(30)  # vérifier toutes les 30s
            for path in existing:
                current = self._hash(path)
                if current and current != self._baseline.get(path):
                    self._baseline[path] = current
                    write_event(
                        username='SYSTEM',
                        resource='file_storage',
                        task='write',
                        execution_date=datetime.utcnow(),
                        source='file_integrity',
                        raw=f'MODIFICATION: {path} (SHA256 changé)'
                    )


# ════════════════════════════════════════════════════════════════════════════
# SURVEILLANCE DES PROCESSUS — psutil
# ════════════════════════════════════════════════════════════════════════════

class ProcessMonitor(threading.Thread):
    """Détecte les nouveaux processus suspects via psutil."""

    SUSPICIOUS = [
        # ═══ MULTI-PLATEFORME ═══
        # Scanners réseau
        'nmap', 'masscan', 'zmap', 'unicornscan', 'hping3', 'angry ip',
        # Sniffers / MitM
        'tcpdump', 'wireshark', 'tshark', 'ettercap', 'dsniff', 'arpspoof',
        'bettercap', 'mitmproxy', 'responder',
        # Outils de connexion / reverse shells
        'nc', 'ncat', 'netcat', 'socat', 'chisel', 'ligolo', 'rpivot',
        # Exploitation / frameworks
        'msfconsole', 'msfvenom', 'metasploit', 'meterpreter',
        'empire', 'covenant', 'sliver', 'havoc', 'cobalt',
        # Webapps
        'sqlmap', 'nikto', 'burpsuite', 'zaproxy', 'dirb', 'gobuster',
        'dirbuster', 'ffuf', 'wfuzz', 'feroxbuster', 'nuclei',
        # Mots de passe / cracking
        'hydra', 'medusa', 'john', 'hashcat', 'ophcrack', 'fcrackzip',
        'cewl', 'crunch',
        # Crypto mining
        'xmrig', 'minerd', 'cpuminer', 'ccminer', 'ethminer', 'nbminer',
        # Tunneling / persistance
        'proxychains', 'revsocks', 'iodine', 'dns2tcp', 'ptunnel',

        # ═══ LINUX ═══
        'linpeas', 'linenum', 'pspy', 'gtfobins',
        'linux-exploit-suggester',
        # Commandes shell suspectes
        'bash -i', 'sh -i', 'python -c', 'python3 -c', 'perl -e',
        'ruby -e', 'php -r', 'curl | bash', 'wget | bash',

        # ═══ WINDOWS — Credential dumping & persistence ═══
        'mimikatz', 'mimikatz.exe', 'procdump', 'procdump.exe',
        'procdump64.exe', 'wce', 'wce.exe', 'fgdump', 'pwdump',
        'rubeus', 'rubeus.exe', 'kekeo', 'kekeo.exe',
        'gsecdump', 'creddump', 'lazagne', 'lazagne.exe',

        # ═══ WINDOWS — AD reconnaissance ═══
        'bloodhound', 'sharphound', 'sharphound.exe', 'powerview',
        'azurehound', 'pingcastle', 'adfind', 'adexplorer',

        # ═══ WINDOWS — Lateral movement ═══
        'psexec', 'psexec.exe', 'psexec64.exe', 'paexec',
        'wmiexec', 'wmiexec.py', 'smbexec', 'atexec',
        'impacket', 'crackmapexec', 'crackmapexec.exe',
        'evil-winrm', 'evilwinrm',

        # ═══ WINDOWS — LOLBins (Living Off The Land) ═══
        'certutil.exe', 'bitsadmin.exe', 'mshta.exe',
        'rundll32.exe', 'regsvr32.exe', 'installutil.exe',
        'msbuild.exe', 'csc.exe',

        # ═══ WINDOWS — Exploitation frameworks ═══
        'cobaltstrike', 'beacon.exe', 'cobalt strike',
        'sliver-client', 'sliver-server', 'havoc client',
        'brute ratel', 'nighthawk',

        # ═══ WINDOWS — Privilege escalation ═══
        'winpeas', 'winpeas.exe', 'winpeasx64.exe',
        'windows-exploit-suggester', 'wesng', 'sherlock', 'watson.exe',
        'juicypotato', 'juicypotato.exe', 'roguepotato', 'printspoofer',

        # ═══ WINDOWS — Commandes suspectes (cmdline) ═══
        'powershell -enc', 'powershell -encodedcommand',
        'powershell -nop', 'powershell -noprofile',
        'powershell -windowstyle hidden', 'powershell.exe -e',
        'iex(new-object', 'invoke-webrequest', 'invoke-expression',
        'downloadstring', 'downloadfile', 'iex (',
        'reg add hklm', 'reg add hkcu',
        'schtasks /create', 'at /create',
        'wmic process call create', 'wmic /node:',
        'net user /add', 'net localgroup administrators',
        'vssadmin delete shadows', 'wbadmin delete catalog',
        'bcdedit /set', 'fsutil usn deletejournal',
        'cipher /w:', 'wevtutil cl ',
    ]

    def __init__(self):
        super().__init__(daemon=True, name='ProcessMonitor')
        self._known_pids = set()

    def run(self):
        try:
            import psutil
        except ImportError:
            status['errors'].append('ProcessMonitor: pip install psutil')
            return

        import psutil
        self._known_pids = {p.pid for p in psutil.process_iter()}
        status['sources'].append('Processus (psutil)')

        while True:
            time.sleep(5)
            try:
                current_pids = set()
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                    try:
                        pid  = proc.info['pid']
                        name = (proc.info['name'] or '').lower()
                        user = proc.info['username'] or 'SYSTEM'
                        cmd  = ' '.join(proc.info['cmdline'] or []).lower()
                        current_pids.add(pid)

                        if pid not in self._known_pids:
                            # New process — word-boundary matching to avoid false positives
                            name_words = set(re.split(r'[\s/\-._]', name))
                            cmd_lower  = cmd
                            is_suspicious = False
                            for s in self.SUSPICIOUS:
                                if ' ' in s:
                                    if s in cmd_lower:
                                        is_suspicious = True
                                        break
                                else:
                                    if s in name_words or name == s:
                                        is_suspicious = True
                                        break
                            if is_suspicious:
                                write_event(
                                    username=user,
                                    resource='system',
                                    task='execute',
                                    execution_date=datetime.utcnow(),
                                    source='process_monitor',
                                    raw=f'PROCESSUS SUSPECT: {name} (pid={pid}) cmd={cmd[:100]}'
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                self._known_pids = current_pids
            except Exception as e:
                status['errors'].append(f'ProcessMonitor: {e}')


# ════════════════════════════════════════════════════════════════════════════
# AUDITD — collecteur /var/log/audit/audit.log
# ════════════════════════════════════════════════════════════════════════════

AUDIT_LOG = '/var/log/audit/audit.log'

auditd_status = {
    'active':          False,
    'error':           None,
    'events_parsed':   0,
    'started_at':      None,
    'rules_loaded':    0,
}

# Règles auditctl à appliquer au démarrage
_AUDIT_RULES = [
    # Commandes sudo uniquement (pas toutes les execve root — trop verbeux)
    '-a always,exit -F arch=b64 -S execve -F euid=0 -F key=ids_root_exec -F exe=/usr/bin/sudo',
    # Fichiers critiques — écriture seulement (pas lecture, trop verbeux)
    '-w /etc/passwd          -p wa -k ids_passwd',
    '-w /etc/shadow          -p wa -k ids_shadow',
    '-w /etc/sudoers         -p wa -k ids_sudoers',
    '-w /etc/ssh/sshd_config -p wa -k ids_sshd',
    '-w /etc/crontab         -p wa -k ids_cron',
    '-w /etc/hosts           -p wa -k ids_hosts',
    # Gestion d'utilisateurs
    '-w /usr/sbin/useradd    -p x  -k ids_useradd',
    '-w /usr/sbin/userdel    -p x  -k ids_userdel',
    '-w /usr/bin/passwd      -p x  -k ids_passwd_chg',
    # NOTE: la règle ids_connect est intentionnellement absente —
    # elle capture connect() de Flask lui-même → flood inutile.
    # La surveillance réseau est faite par scapy (NetworkCapture).
]


def _setup_audit_rules():
    """Installe les règles auditctl pour la détection IDS."""
    loaded = 0
    for rule in _AUDIT_RULES:
        ret = os.system(f'auditctl {rule} 2>/dev/null')
        if ret == 0:
            loaded += 1
    auditd_status['rules_loaded'] = loaded
    return loaded


def _resolve_uid(uid_str: str) -> str:
    """Convertit un UID numérique en nom d'utilisateur."""
    try:
        uid = int(uid_str)
        if uid in (4294967295, -1):
            return ''
        return _pwd.getpwuid(uid).pw_name
    except (ValueError, KeyError):
        return uid_str


def _parse_audit_fields(line: str) -> dict:
    """Parse une ligne audit en dict key=value."""
    fields = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\'[^\']*\')|(\S+))', line):
        key = m.group(1)
        val = m.group(2) or m.group(3) or m.group(4) or ''
        fields[key] = val.strip("'")
    return fields


def _decode_hex(s: str) -> str:
    """Décode une chaîne hexadécimale auditd (ex: cmd=2F62696E2F7368)."""
    try:
        if s and all(c in '0123456789ABCDEFabcdef' for c in s) and len(s) % 2 == 0:
            return bytes.fromhex(s).decode('utf-8', errors='replace')
    except Exception:
        pass
    return s


# ════════════════════════════════════════════════════════════════════════════
# LINUX — Détection de persistence (cron, systemd, profile.d, etc.)
# ════════════════════════════════════════════════════════════════════════════

class LinuxPersistenceMonitor(threading.Thread):
    """Surveille les emplacements de persistence Linux.

    Détecte les modifications de :
      - /etc/cron.d/, /etc/cron.hourly/, /etc/cron.daily/, /etc/cron.weekly/
      - /var/spool/cron/crontabs/
      - /etc/systemd/system/ et /lib/systemd/system/ (.service files)
      - /etc/profile.d/
      - /etc/rc.local
      - ~/.bashrc, ~/.bash_profile (root)
      - /etc/init.d/
    """

    PERSISTENCE_PATHS = [
        '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily',
        '/etc/cron.weekly', '/etc/cron.monthly',
        '/var/spool/cron', '/var/spool/cron/crontabs',
        '/etc/systemd/system', '/lib/systemd/system',
        '/etc/profile.d', '/etc/init.d',
        '/root/.ssh',
    ]

    POLL_INTERVAL = 120  # secondes

    def __init__(self):
        super().__init__(daemon=True, name='LinuxPersistenceMonitor')
        self._baseline = {}  # path → {file: mtime}

    def _scan_dir(self, directory):
        """Retourne {filename: mtime} pour les fichiers d'un dossier."""
        out = {}
        if not os.path.isdir(directory):
            return out
        try:
            for name in os.listdir(directory):
                full = os.path.join(directory, name)
                if os.path.isfile(full):
                    try:
                        out[name] = os.path.getmtime(full)
                    except Exception:
                        pass
        except (PermissionError, OSError):
            pass
        return out

    def _build_baseline(self):
        for path in self.PERSISTENCE_PATHS:
            self._baseline[path] = self._scan_dir(path)

    def _check_changes(self):
        for path in self.PERSISTENCE_PATHS:
            current = self._scan_dir(path)
            baseline = self._baseline.get(path, {})

            # Nouveaux fichiers
            for name in current:
                if name not in baseline:
                    full = os.path.join(path, name)
                    write_event(
                        username='SYSTEM',
                        resource='file_system',
                        task='write',
                        execution_date=datetime.utcnow(),
                        source='linux/persistence',
                        raw=f'[PERSISTENCE] Nouveau fichier dans {path}: {name}'
                    )

            # Fichiers modifiés
            for name in current:
                if name in baseline and current[name] != baseline[name]:
                    full = os.path.join(path, name)
                    write_event(
                        username='SYSTEM',
                        resource='file_system',
                        task='write',
                        execution_date=datetime.utcnow(),
                        source='linux/persistence',
                        raw=f'[MODIFICATION] Fichier modifié dans {path}: {name}'
                    )

            # Fichiers supprimés
            for name in baseline:
                if name not in current:
                    write_event(
                        username='SYSTEM',
                        resource='file_system',
                        task='delete',
                        execution_date=datetime.utcnow(),
                        source='linux/persistence',
                        raw=f'[SUPPRESSION] Fichier supprimé dans {path}: {name}'
                    )

            self._baseline[path] = current

    def run(self):
        if SYSTEM == 'Windows':
            return
        try:
            self._build_baseline()
            n = sum(len(v) for v in self._baseline.values())
            print(f'[MODULE 1] Persistence: baseline construite ({n} fichiers)',
                  file=sys.stderr)
            status['sources'].append('Linux Persistence (cron/systemd/init)')
        except Exception as e:
            status['errors'].append(f'PersistenceMonitor init: {e}')
            return

        while True:
            try:
                time.sleep(self.POLL_INTERVAL)
                self._check_changes()
            except Exception as e:
                status['errors'].append(f'PersistenceMonitor: {e}')


# ════════════════════════════════════════════════════════════════════════════
# LINUX — Détection d'élévation de privilèges (SUID binaries)
# ════════════════════════════════════════════════════════════════════════════

class SUIDMonitor(threading.Thread):
    """Détecte l'apparition de nouveaux binaires SUID/SGID.

    Un binaire SUID s'exécute avec les privilèges de son propriétaire.
    Un nouveau SUID dans /tmp, /home ou /var → souvent backdoor pour escalade.
    """

    SCAN_PATHS = ['/usr/bin', '/usr/sbin', '/bin', '/sbin',
                  '/usr/local/bin', '/usr/local/sbin',
                  '/tmp', '/var/tmp', '/dev/shm', '/home']

    POLL_INTERVAL = 600  # 10 minutes

    # SUID Linux légitimes connus (whitelist)
    KNOWN_SUID = {
        'su', 'sudo', 'passwd', 'mount', 'umount', 'chsh', 'chfn',
        'gpasswd', 'newgrp', 'ping', 'ping6', 'pkexec', 'crontab',
        'fusermount', 'sudoedit', 'expiry', 'unix_chkpwd',
        'mount.cifs', 'mount.nfs', 'ntfs-3g', 'ssh-keysign',
        'dbus-daemon-launch-helper', 'polkit-agent-helper-1',
        'snap-confine', 'pam_extrausers_chkpwd', 'bwrap',
    }

    def __init__(self):
        super().__init__(daemon=True, name='SUIDMonitor')
        self._known = set()

    def _find_suid(self):
        """Trouve tous les fichiers SUID via os.walk + os.stat."""
        import stat as _stat
        suid_files = set()
        for path in self.SCAN_PATHS:
            if not os.path.isdir(path):
                continue
            try:
                for root, dirs, files in os.walk(path, followlinks=False):
                    # Limiter la profondeur dans /home et /tmp
                    if path in ('/home', '/tmp', '/var/tmp', '/dev/shm'):
                        depth = root[len(path):].count(os.sep)
                        if depth > 4:
                            dirs[:] = []
                            continue
                    for f in files:
                        full = os.path.join(root, f)
                        try:
                            st = os.lstat(full)
                            if st.st_mode & (_stat.S_ISUID | _stat.S_ISGID):
                                suid_files.add(full)
                        except (OSError, PermissionError):
                            pass
            except (PermissionError, OSError):
                continue
        return suid_files

    def run(self):
        if SYSTEM == 'Windows':
            return

        # Baseline initial
        try:
            self._known = self._find_suid()
            print(f'[MODULE 1] SUID: baseline construite ({len(self._known)} binaires)',
                  file=sys.stderr)
            status['sources'].append(f'SUID/SGID monitor ({len(self._known)} binaires)')
        except Exception as e:
            status['errors'].append(f'SUIDMonitor init: {e}')
            return

        while True:
            try:
                time.sleep(self.POLL_INTERVAL)
                current = self._find_suid()

                # Nouveaux SUID
                new_suid = current - self._known
                for path in new_suid:
                    filename = os.path.basename(path)
                    severity_marker = ''
                    # SUID dans emplacements suspects
                    if any(path.startswith(p) for p in ('/tmp', '/home', '/var/tmp', '/dev/shm')):
                        severity_marker = ' [CRITIQUE — emplacement suspect]'
                    elif filename not in self.KNOWN_SUID:
                        severity_marker = ' [SUID non standard]'

                    write_event(
                        username='SYSTEM',
                        resource='file_system',
                        task='write',
                        execution_date=datetime.utcnow(),
                        source='linux/suid',
                        raw=f'[NEW SUID] {path}{severity_marker}'
                    )

                # SUID supprimés
                removed = self._known - current
                for path in removed:
                    write_event(
                        username='SYSTEM',
                        resource='file_system',
                        task='delete',
                        execution_date=datetime.utcnow(),
                        source='linux/suid',
                        raw=f'[SUID REMOVED] {path}'
                    )

                self._known = current
            except Exception as e:
                status['errors'].append(f'SUIDMonitor: {e}')


# ════════════════════════════════════════════════════════════════════════════
# WINDOWS — Surveillance du Registre (clés de persistence)
# ════════════════════════════════════════════════════════════════════════════

class WindowsRegistryMonitor(threading.Thread):
    """Surveille les clés de persistence Windows toutes les 60 secondes.

    Détecte ajouts/modifications dans :
      - HKLM/HKCU \\Software\\Microsoft\\Windows\\CurrentVersion\\Run
      - HKLM/HKCU \\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
      - HKLM \\System\\CurrentControlSet\\Services (nouveaux services)
      - HKLM \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
      - HKLM \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options
    """

    PERSISTENCE_KEYS = [
        # (hive, key, description)
        ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Run', 'autorun-machine'),
        ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Run', 'autorun-user'),
        ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'runonce-machine'),
        ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'runonce-user'),
        ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders', 'shell-folders'),
        ('HKLM', r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'winlogon'),
        ('HKLM', r'Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'ifeo'),
        ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'policy-run'),
        ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'policy-run-user'),
    ]

    POLL_INTERVAL = 60  # secondes

    def __init__(self):
        super().__init__(daemon=True, name='WindowsRegistryMonitor')
        self._baseline = {}   # (hive, key) → {value_name: value_data}

    def _read_key(self, hive_name, key_path):
        """Lit toutes les valeurs d'une clé via reg.exe."""
        hive_map = {'HKLM': 'HKEY_LOCAL_MACHINE', 'HKCU': 'HKEY_CURRENT_USER'}
        full = f'{hive_map.get(hive_name, hive_name)}\\{key_path}'
        try:
            result = subprocess.run(
                ['reg', 'query', full],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return {}
            values = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                # Format: "    NomValeur    REG_SZ    Donnée"
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[1].startswith('REG_'):
                    values[parts[0]] = parts[2]
            return values
        except Exception:
            return {}

    def _build_baseline(self):
        """Construit la baseline initiale."""
        for hive, key, _ in self.PERSISTENCE_KEYS:
            self._baseline[(hive, key)] = self._read_key(hive, key)

    def _check_diff(self):
        """Compare l'état actuel à la baseline."""
        for hive, key, label in self.PERSISTENCE_KEYS:
            current = self._read_key(hive, key)
            baseline = self._baseline.get((hive, key), {})

            # Nouvelles valeurs
            for name, val in current.items():
                if name not in baseline:
                    write_event(
                        username='SYSTEM',
                        resource='registry',
                        task='write',
                        execution_date=datetime.utcnow(),
                        source='windows/registry',
                        raw=f'[PERSISTENCE] Nouvelle valeur dans {hive}\\{key} ({label}): '
                            f'{name} = {val[:120]}'
                    )
                elif baseline[name] != val:
                    write_event(
                        username='SYSTEM',
                        resource='registry',
                        task='write',
                        execution_date=datetime.utcnow(),
                        source='windows/registry',
                        raw=f'[MODIFICATION] Valeur changée {hive}\\{key} ({label}): '
                            f'{name} = {val[:120]} (était {baseline[name][:60]})'
                    )

            # Valeurs supprimées
            for name in baseline:
                if name not in current:
                    write_event(
                        username='SYSTEM',
                        resource='registry',
                        task='delete',
                        execution_date=datetime.utcnow(),
                        source='windows/registry',
                        raw=f'[SUPPRESSION] Valeur supprimée {hive}\\{key} ({label}): {name}'
                    )

            self._baseline[(hive, key)] = current

    def run(self):
        if SYSTEM != 'Windows':
            return
        try:
            self._build_baseline()
            n = sum(len(v) for v in self._baseline.values())
            print(f'[MODULE 1] Registry: baseline construite ({n} valeurs surveillées)',
                  file=sys.stderr)
            status['sources'].append('Windows Registry (persistence)')
        except Exception as e:
            status['errors'].append(f'RegistryMonitor init: {e}')
            return

        while True:
            try:
                time.sleep(self.POLL_INTERVAL)
                self._check_diff()
            except Exception as e:
                status['errors'].append(f'RegistryMonitor: {e}')


# ════════════════════════════════════════════════════════════════════════════
# WINDOWS — Surveillance des Services
# ════════════════════════════════════════════════════════════════════════════

class WindowsServiceMonitor(threading.Thread):
    """Surveille les services Windows : détecte nouveaux services et changements.

    Utilise `sc query` pour lister tous les services et détecte :
      - Nouveau service installé (potentielle persistence)
      - Service AUTO_START non-Microsoft suspect
      - Service avec binPath suspect (rundll32, powershell, etc.)
    """

    POLL_INTERVAL = 60  # secondes

    # Patterns suspects dans binPath
    SUSPICIOUS_BIN_PATTERNS = [
        'powershell', 'cmd.exe /c', 'rundll32', 'mshta',
        'wscript', 'cscript', 'regsvr32', 'certutil',
        'bitsadmin', '\\users\\', '\\temp\\', '\\appdata\\',
    ]

    def __init__(self):
        super().__init__(daemon=True, name='WindowsServiceMonitor')
        self._known = set()        # noms de services connus
        self._configs = {}         # name → {start_type, bin_path}

    def _list_services(self):
        """Liste tous les services via sc query state=all."""
        try:
            result = subprocess.run(
                ['sc', 'query', 'state=', 'all'],
                capture_output=True, text=True, timeout=15
            )
            services = []
            current = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    if current:
                        services.append(current)
                    current = {'name': line.split(':', 1)[1].strip()}
                elif line.startswith('DISPLAY_NAME:'):
                    current['display'] = line.split(':', 1)[1].strip()
            if current:
                services.append(current)
            return services
        except Exception:
            return []

    def _get_service_config(self, name):
        """Récupère config d'un service via sc qc <name>."""
        try:
            result = subprocess.run(
                ['sc', 'qc', name],
                capture_output=True, text=True, timeout=10
            )
            cfg = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if ':' in line:
                    k, v = line.split(':', 1)
                    cfg[k.strip()] = v.strip()
            return {
                'start_type': cfg.get('START_TYPE', ''),
                'bin_path':   cfg.get('BINARY_PATH_NAME', ''),
                'display':    cfg.get('DISPLAY_NAME', ''),
            }
        except Exception:
            return {}

    def _is_suspicious(self, cfg):
        """Détermine si un service est suspect."""
        bin_path = cfg.get('bin_path', '').lower()
        for pattern in self.SUSPICIOUS_BIN_PATTERNS:
            if pattern in bin_path:
                return True, f'binPath contient "{pattern}"'
        return False, ''

    def run(self):
        if SYSTEM != 'Windows':
            return

        # Baseline initial
        try:
            for svc in self._list_services():
                self._known.add(svc['name'])
            print(f'[MODULE 1] Services: baseline construite ({len(self._known)} services)',
                  file=sys.stderr)
            status['sources'].append('Windows Services (persistence)')
        except Exception as e:
            status['errors'].append(f'ServiceMonitor init: {e}')
            return

        while True:
            try:
                time.sleep(self.POLL_INTERVAL)
                current_services = self._list_services()
                current_names = {s['name'] for s in current_services}

                # Nouveaux services
                new_names = current_names - self._known
                for name in new_names:
                    cfg = self._get_service_config(name)
                    suspicious, reason = self._is_suspicious(cfg)
                    severity = 'critical' if suspicious else 'medium'
                    raw = (f'Nouveau service "{name}" ({cfg.get("display", "")}): '
                           f'start={cfg.get("start_type", "?")} '
                           f'bin={cfg.get("bin_path", "?")[:120]}')
                    if suspicious:
                        raw += f' [SUSPECT: {reason}]'
                    write_event(
                        username='SYSTEM',
                        resource='system',
                        task='admin',
                        execution_date=datetime.utcnow(),
                        source='windows/service',
                        raw=raw,
                    )

                # Services supprimés (intéressant pour audit)
                removed = self._known - current_names
                for name in removed:
                    write_event(
                        username='SYSTEM',
                        resource='system',
                        task='delete',
                        execution_date=datetime.utcnow(),
                        source='windows/service',
                        raw=f'Service supprimé : {name}',
                    )

                self._known = current_names
            except Exception as e:
                status['errors'].append(f'ServiceMonitor: {e}')


class AuditdCollector(threading.Thread):
    """
    Lit /var/log/audit/audit.log en temps réel.
    Convertit les enregistrements audit en événements IDS (JSONL).

    Types traités :
      USER_CMD       → commande sudo (exécution privilégiée)
      USER_AUTH      → authentification (succès / échec)
      USER_LOGIN     → ouverture de session
      USER_LOGOUT    → fermeture de session
      ADD_USER       → création d'utilisateur
      DEL_USER       → suppression d'utilisateur
      USER_CHAUTHTOK → changement de mot de passe
      SYSCALL(execve)→ commande exécutée en root
      PATH(ids_*)    → accès à fichier critique surveillé
      SYSCALL(connect) → connexion réseau initiée
    """

    def __init__(self):
        super().__init__(daemon=True, name='AuditdCollector')
        self._pos = 0

    def run(self):
        if not os.path.exists(AUDIT_LOG):
            auditd_status['error'] = 'audit.log absent — installez auditd'
            status['errors'].append('AuditdCollector: audit.log absent')
            return

        try:
            open(AUDIT_LOG).close()
        except PermissionError:
            auditd_status['error'] = 'Permission refusée — lancez avec sudo'
            status['errors'].append('AuditdCollector: permission refusée sur audit.log')
            return

        # Charger les règles
        n = _setup_audit_rules()
        print(f'[MODULE 1] auditd: {n}/{len(_AUDIT_RULES)} règles chargées', file=sys.stderr)

        # Commencer à la fin du fichier (ne pas rejouer l'historique)
        self._pos = os.path.getsize(AUDIT_LOG)
        auditd_status['active']     = True
        auditd_status['started_at'] = datetime.utcnow()
        status['sources'].append(f'auditd ({AUDIT_LOG})')

        while True:
            self._poll()
            time.sleep(1)

    def _poll(self):
        try:
            size = os.path.getsize(AUDIT_LOG)
            if size <= self._pos:
                return
            with open(AUDIT_LOG, encoding='utf-8', errors='replace') as f:
                f.seek(self._pos)
                for line in f:
                    self._process(line.strip())
            self._pos = size
        except Exception as e:
            status['errors'].append(f'AuditdCollector: {e}')

    def _process(self, line: str):
        if not line:
            return

        # Extraire type et timestamp
        m = re.match(r'type=(\w+)\s+msg=audit\((\d+\.\d+):\d+\):(.*)', line)
        if not m:
            return

        record_type = m.group(1)
        ts_str      = m.group(2)
        body        = m.group(3)

        try:
            exec_date = datetime.utcfromtimestamp(float(ts_str))
        except Exception:
            exec_date = datetime.utcnow()

        fields = _parse_audit_fields(body)
        auditd_status['events_parsed'] += 1

        # Résoudre le nom d'utilisateur
        username = ''
        for key in ('auid', 'uid'):
            raw = fields.get(key, '')
            resolved = _resolve_uid(raw)
            if resolved and resolved not in ('unset', '4294967295', '-1'):
                username = resolved
                break
        if not username:
            username = fields.get('acct', fields.get('id', 'unknown')).strip('"')

        # ── Dispatch par type ────────────────────────────────────────────
        if record_type == 'USER_CMD':
            cmd = _decode_hex(fields.get('cmd', ''))
            write_event(username=username, resource='system', task='execute',
                        execution_date=exec_date, source='auditd/sudo',
                        raw=f'SUDO: {username} → {cmd[:200]}')

        elif record_type == 'USER_AUTH':
            res  = fields.get('res', 'failed')
            task = 'login' if res == 'success' else 'failed_login'
            svc  = fields.get('exe', '').replace('"', '')
            write_event(username=username, resource='ssh_server', task=task,
                        execution_date=exec_date, source='auditd/auth',
                        raw=f'AUTH {res.upper()}: {username} via {svc}')

        elif record_type == 'USER_LOGIN':
            write_event(username=username, resource='ssh_server', task='login',
                        execution_date=exec_date, source='auditd/login',
                        raw=f'LOGIN: {username}')

        elif record_type == 'USER_LOGOUT':
            write_event(username=username, resource='ssh_server', task='login',
                        execution_date=exec_date, source='auditd/logout',
                        raw=f'LOGOUT: {username}')

        elif record_type in ('ADD_USER', 'ADD_GROUP'):
            target = fields.get('id', fields.get('acct', '?')).strip('"')
            write_event(username=username, resource='user_management', task='admin',
                        execution_date=exec_date, source='auditd/user_mgmt',
                        raw=f'{record_type}: {username} a créé "{target}"')

        elif record_type in ('DEL_USER', 'DEL_GROUP'):
            target = fields.get('id', fields.get('acct', '?')).strip('"')
            write_event(username=username, resource='user_management', task='delete',
                        execution_date=exec_date, source='auditd/user_mgmt',
                        raw=f'{record_type}: {username} a supprimé "{target}"')

        elif record_type == 'USER_CHAUTHTOK':
            target = fields.get('id', username).strip('"')
            write_event(username=username, resource='user_management', task='write',
                        execution_date=exec_date, source='auditd/passwd',
                        raw=f'PASSWD CHANGE: {username} → {target}')

        elif record_type == 'SYSCALL':
            key     = fields.get('key', '').strip('"')
            exe     = fields.get('exe', '').strip('"')
            success = fields.get('success', 'yes')

            if key == 'ids_root_exec' and success == 'yes':
                comm = fields.get('comm', '').strip('"')
                # Whitelist des processus système légitimes à ignorer
                _ROOT_WHITELIST = {
                    'auditd', 'audisp', 'audispd', 'kauditd',
                    'python3', 'python3.12', 'python', 'flask',
                    'sudo', 'su',
                    'runc', 'docker', 'docker-init', 'containerd',
                    'systemd', 'systemd-journal', 'systemd-udevd',
                    'ldconfig', 'ldconfig.real', 'dash', 'sh', 'bash',
                    'apt', 'apt-get', 'dpkg', 'snap',
                    'uname', 'id', 'whoami', 'ls', 'cat',
                    'cron', 'crond', 'atd', 'anacron',
                    'sshd', 'login', 'getty', 'agetty',
                    'polkit', 'polkitd', 'dbus-daemon',
                }
                if comm not in _ROOT_WHITELIST:
                    write_event(username=username, resource='system', task='execute',
                                execution_date=exec_date, source='auditd/execve',
                                raw=f'ROOT EXEC: {comm} ({exe})')

        elif record_type == 'PATH':
            key = fields.get('key', '').strip('"')
            name = fields.get('name', '').strip('"')
            nametype = fields.get('nametype', '')
            if key.startswith('ids_') and nametype in ('NORMAL', 'CREATE', 'DELETE'):
                write_event(username=username, resource='file_storage', task='write',
                            execution_date=exec_date, source='auditd/file',
                            raw=f'FICHIER CRITIQUE: {name} (key={key})')


# ════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE — démarre tous les collecteurs
# ════════════════════════════════════════════════════════════════════════════

def start(app=None):
    """Démarre tous les collecteurs comme démons en arrière-plan.

    Linux : LinuxLogCollector + AuditdCollector + FileIntegrity + Process + Network
    Windows : WindowsLog + Sysmon + Registry + Service + FileIntegrity + Process + Network
    """
    os.makedirs(EVENTS_DIR, exist_ok=True)

    status['running']    = True
    status['started_at'] = datetime.utcnow().isoformat()
    status['sources']    = []
    status['errors']     = []

    # ── Collecteurs spécifiques par OS ─────────────────────────
    if SYSTEM == 'Windows':
        WindowsLogCollector().start()
        SysmonCollector().start()           # Équivalent auditd
        WindowsRegistryMonitor().start()    # Persistence registre
        WindowsServiceMonitor().start()     # Persistence services
    else:
        LinuxLogCollector().start()
        AuditdCollector().start()
        LinuxPersistenceMonitor().start()   # cron/systemd/init.d
        SUIDMonitor().start()               # Escalade de privilèges

    # ── Collecteurs multi-OS ───────────────────────────────────
    NetworkCapture(app).start()
    FileIntegrityMonitor().start()
    ProcessMonitor().start()

    print(f'[MODULE 1] Collecteur démarré (OS={SYSTEM})', file=sys.stderr)
