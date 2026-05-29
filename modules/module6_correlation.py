"""
MODULE 6 — Corrélation kill chain (démon)

Détecte des séquences d'attaque (kill chain) en analysant les patterns
temporels d'événements depuis une même IP/utilisateur.

Stages typiques d'une attaque (Lockheed Martin Cyber Kill Chain) :
  1. Reconnaissance     → port_scan, dns_tunnel
  2. Weaponization      → (côté attaquant, non détectable)
  3. Delivery           → connexion C2, payload détecté
  4. Exploitation       → brute_force, signature payload
  5. Installation       → SUID drop, persistence (registry, cron)
  6. Command & Control  → JA3 match, SNI suspect
  7. Actions on objective → exfiltration (DNS tunnel, large outbound)

Ce module identifie 3 patterns simplifiés :
  - SCAN_THEN_BREACH    : port_scan suivi de brute_force (même src)
  - BREACH_THEN_EXEC    : brute_force suivi de execute (même user/IP)
  - PERSIST_AFTER_EXEC  : execute suivi de modification persistence
"""

import os
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta

# Configuration
KILL_CHAIN_WINDOW = int(os.environ.get('IDS_KILLCHAIN_WINDOW', '1800'))  # 30 min
SCAN_INTERVAL     = int(os.environ.get('IDS_CORRELATION_INTERVAL', '60'))  # 1 min

status = {
    'running':            False,
    'patterns_detected':  0,
    'last_scan':          None,
    'errors':             [],
}

# Patterns détectés (pour éviter doublons sur fenêtre courte)
_recent_patterns = {}  # (pattern_name, actor) → last_ts


def _format_chain(pattern, actor, events):
    """Formate une chaîne d'attaque détectée."""
    lines = [
        f'═══ KILL CHAIN DÉTECTÉE : {pattern} ═══',
        f'Acteur : {actor}',
        f'Étapes :',
    ]
    for ev in events:
        ts = ev.get('detected_at') or ev.get('execution_date')
        ts_str = ts.strftime('%H:%M:%S') if hasattr(ts, 'strftime') else str(ts)
        lines.append(f"  [{ts_str}] {ev.get('type', '?')}: {ev.get('msg', '')[:80]}")
    return '\n'.join(lines)


class CorrelationDaemon(threading.Thread):
    """Démon de corrélation — scanne les intrusions toutes les minutes."""

    def __init__(self, app, alert_queue):
        super().__init__(daemon=True, name='CorrelationDaemon')
        self.app = app
        self.alert_queue = alert_queue

    def _detect_scan_then_breach(self, intrusions):
        """Pattern 1 : port_scan puis brute_force depuis la même IP en < 30 min."""
        # Grouper par IP source (extraite du raw ou du username)
        scans_by_ip = defaultdict(list)
        bf_by_ip    = defaultdict(list)

        for intr in intrusions:
            entry = intr.entry
            if not entry:
                continue
            actor = entry.username or ''
            vtype = (intr.violation_type or '').lower()

            if 'port_scan' in vtype or 'scan de ports' in vtype:
                scans_by_ip[actor].append(intr)
            elif 'brute' in vtype or 'failed_login' in vtype.lower():
                bf_by_ip[actor].append(intr)

        # Pour chaque IP avec scan ET brute force
        detected = []
        for ip in scans_by_ip:
            if ip in bf_by_ip:
                scans = sorted(scans_by_ip[ip], key=lambda x: x.detected_at)
                bfs   = sorted(bf_by_ip[ip],   key=lambda x: x.detected_at)
                # Scan avant brute force
                if scans[0].detected_at < bfs[0].detected_at:
                    delta = (bfs[0].detected_at - scans[0].detected_at).total_seconds()
                    if delta < KILL_CHAIN_WINDOW:
                        detected.append({
                            'pattern': 'SCAN_THEN_BREACH',
                            'actor': ip,
                            'events': [
                                {'type': 'port_scan',   'msg': scans[0].violation_type,
                                 'detected_at': scans[0].detected_at},
                                {'type': 'brute_force', 'msg': bfs[0].violation_type,
                                 'detected_at': bfs[0].detected_at},
                            ],
                            'severity': 'critical',
                        })
        return detected

    def _detect_breach_then_exec(self, intrusions):
        """Pattern 2 : brute_force puis execute par le même user en < 30 min."""
        bf_by_user   = defaultdict(list)
        exec_by_user = defaultdict(list)

        for intr in intrusions:
            entry = intr.entry
            if not entry:
                continue
            user  = entry.username or ''
            task  = (entry.task or '').lower()
            vtype = (intr.violation_type or '').lower()

            if 'brute' in vtype or task == 'failed_login':
                bf_by_user[user].append(intr)
            elif task == 'execute':
                exec_by_user[user].append(intr)

        detected = []
        for user in bf_by_user:
            if user in exec_by_user:
                bfs   = sorted(bf_by_user[user],   key=lambda x: x.detected_at)
                execs = sorted(exec_by_user[user], key=lambda x: x.detected_at)
                if bfs[0].detected_at < execs[0].detected_at:
                    delta = (execs[0].detected_at - bfs[0].detected_at).total_seconds()
                    if delta < KILL_CHAIN_WINDOW:
                        detected.append({
                            'pattern': 'BREACH_THEN_EXEC',
                            'actor': user,
                            'events': [
                                {'type': 'brute_force', 'msg': bfs[0].violation_type,
                                 'detected_at': bfs[0].detected_at},
                                {'type': 'execute',     'msg': execs[0].violation_type,
                                 'detected_at': execs[0].detected_at},
                            ],
                            'severity': 'critical',
                        })
        return detected

    def _detect_persist_after_exec(self, intrusions):
        """Pattern 3 : execute puis write sur fichier de persistence."""
        exec_by_user      = defaultdict(list)
        persist_by_user   = defaultdict(list)

        for intr in intrusions:
            entry = intr.entry
            if not entry:
                continue
            user = entry.username or ''
            task = (entry.task or '').lower()
            src  = (intr.violation_type or '').lower()
            # Le tag "PERSISTENCE" est ajouté par LinuxPersistenceMonitor / Sysmon
            if task == 'execute':
                exec_by_user[user].append(intr)
            elif 'persistence' in src or 'persistance' in src \
                 or 'ifeo' in src or 'autorun' in src \
                 or 'cron' in src or 'systemd' in src:
                persist_by_user[user].append(intr)

        detected = []
        for user in exec_by_user:
            if user in persist_by_user:
                execs    = sorted(exec_by_user[user],    key=lambda x: x.detected_at)
                persists = sorted(persist_by_user[user], key=lambda x: x.detected_at)
                if execs[0].detected_at < persists[0].detected_at:
                    delta = (persists[0].detected_at - execs[0].detected_at).total_seconds()
                    if delta < KILL_CHAIN_WINDOW:
                        detected.append({
                            'pattern': 'PERSIST_AFTER_EXEC',
                            'actor': user,
                            'events': [
                                {'type': 'execute',     'msg': execs[0].violation_type,
                                 'detected_at': execs[0].detected_at},
                                {'type': 'persistence', 'msg': persists[0].violation_type,
                                 'detected_at': persists[0].detected_at},
                            ],
                            'severity': 'critical',
                        })
        return detected

    def _scan(self):
        """Scan toutes les intrusions récentes pour patterns."""
        with self.app.app_context():
            from models import Intrusion
            cutoff = datetime.now() - timedelta(seconds=KILL_CHAIN_WINDOW)
            intrusions = Intrusion.query.filter(
                Intrusion.detected_at >= cutoff
            ).all()

            if not intrusions:
                return []

            patterns = []
            patterns += self._detect_scan_then_breach(intrusions)
            patterns += self._detect_breach_then_exec(intrusions)
            patterns += self._detect_persist_after_exec(intrusions)
            return patterns

    def run(self):
        status['running'] = True
        print(f'[MODULE 6] Corrélation kill chain démarrée '
              f'(fenêtre {KILL_CHAIN_WINDOW}s)', file=sys.stderr)

        while True:
            try:
                time.sleep(SCAN_INTERVAL)
                detected = self._scan()
                status['last_scan'] = datetime.now().strftime('%H:%M:%S')

                for pattern in detected:
                    # Déduplication : ne pas re-alerter sur le même pattern/acteur en < 30 min
                    key = (pattern['pattern'], pattern['actor'])
                    now = time.time()
                    if now - _recent_patterns.get(key, 0) < KILL_CHAIN_WINDOW:
                        continue
                    _recent_patterns[key] = now

                    # Envoyer dans la queue d'alertes (Module 4 va dispatcher)
                    chain_msg = _format_chain(pattern['pattern'],
                                              pattern['actor'],
                                              pattern['events'])
                    print(chain_msg, file=sys.stderr)

                    self.alert_queue.put({
                        'event': {
                            'username': pattern['actor'],
                            'resource': 'system',
                            'task':     'kill_chain',
                            'source':   'correlation',
                            'execution_date': datetime.now().isoformat(),
                            'raw':      chain_msg[:500],
                        },
                        'violation': {
                            'type':     f'kill_chain_{pattern["pattern"]}',
                            'message':  f'[CORRELATION] {pattern["pattern"]}: '
                                        f'{pattern["actor"]} — '
                                        f'{len(pattern["events"])} stages détectées',
                            'severity': pattern['severity'],
                        },
                        'detected_at': datetime.now().isoformat(),
                    })
                    status['patterns_detected'] += 1

            except Exception as e:
                status['errors'].append(f'CorrelationDaemon: {e}')
                print(f'[MODULE 6] Erreur: {e}', file=sys.stderr)


def start(app, alert_queue):
    CorrelationDaemon(app, alert_queue).start()
