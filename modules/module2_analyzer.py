"""
MODULE 2 — Analyseur d'événements (démon)

Surveille en continu le dossier events/ pour de nouveaux événements.
Pour chaque événement, compare aux règles de la politique de sécurité.
Si au moins une règle est violée → crée une Intrusion + notifie le Module 4.

Règle de détection :
  Un événement constitue une intrusion si AUCUNE règle de la politique
  n'autorise l'accès (user, resource, task, date/heure). Défaut : tout refuser.

Types de violations :
  1. Utilisateur inconnu de la politique
  2. Tâche/ressource non autorisée pour cet utilisateur
  3. Date/heure d'exécution hors de la plage autorisée
  4. Brute force — seuil de tentatives échouées dépassé
"""

import os
import sys
import json
import time
import threading
from collections import defaultdict
from datetime import datetime

BASE_DIR   = os.path.dirname(os.path.dirname(__file__))
EVENTS_DIR = os.path.join(BASE_DIR, 'events')
CURSOR_FILE = os.path.join(BASE_DIR, '.events_cursor.json')

status = {
    'running':    False,
    'analyzed':   0,
    'intrusions': 0,
    'last_check': None,
    'errors':     [],
}

# Queue partagée avec le Module 4
_alert_queue = None

# ── Détection Brute Force (fenêtre glissante) ────────────────────────────────
_bf_tracker: dict = defaultdict(list)   # username → [timestamps des failed_login]
BRUTE_FORCE_THRESHOLD = 5               # tentatives avant alerte
BRUTE_FORCE_WINDOW    = 60              # secondes

def _detect_brute_force(username: str) -> tuple[bool, int]:
    """
    Retourne (True, count) si le seuil brute force est atteint.
    Utilise une fenêtre glissante de BRUTE_FORCE_WINDOW secondes.
    """
    now = time.time()
    _bf_tracker[username] = [t for t in _bf_tracker[username]
                              if now - t < BRUTE_FORCE_WINDOW]
    _bf_tracker[username].append(now)
    count = len(_bf_tracker[username])
    # Déclencher au seuil, puis tous les 5 supplémentaires
    triggered = (count == BRUTE_FORCE_THRESHOLD or
                 (count > BRUTE_FORCE_THRESHOLD and (count - BRUTE_FORCE_THRESHOLD) % 5 == 0))
    return triggered, count


def _load_cursor() -> dict:
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_cursor(cursor: dict):
    with open(CURSOR_FILE, 'w') as f:
        json.dump(cursor, f)


def _load_policy(app):
    """Charge la politique depuis la DB (AccessPolicy)."""
    with app.app_context():
        from models import AccessPolicy
        policies = AccessPolicy.query.filter_by(active=True).all()
        return [
            {
                'username':   p.user.username,
                'resource':   p.resource.name,
                'task':       p.task,
                'policy_type': p.policy_type,  # 'allow' ou 'deny'
                'start_date': p.start_date,
                'end_date':   p.end_date,
            }
            for p in policies
        ]


def _check_event(event: dict, policies: list) -> dict | None:
    """
    Vérifie si un événement viole la politique avec système allow/deny cumulatif.
    Logique : deny-by-default, accumulation de droits via rules allow/deny.
    Retourne un dict de violation ou None si l'accès est autorisé.
    """
    username = event.get('username', '')
    resource = event.get('resource', '')
    task     = event.get('task', '')

    try:
        exec_date = datetime.fromisoformat(event.get('execution_date', ''))
    except Exception:
        exec_date = datetime.utcnow()

    # Exclure les comptes système sans contrôle d'accès
    system_accounts = {'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE',
                       'daemon', 'nobody', 'www-data', '_apt', 'gdm'}
    if username in system_accounts:
        return None

    # Les événements réseau ont une IP comme username (source network/*)
    # Ils bypassent la politique utilisateur et sont toujours des alertes
    source = event.get('source', '')
    if source.startswith('network/') and source != 'network/port_scan':
        import re as _re
        if _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', username):
            # Ignorer les vieux événements réseau (backlog JSONL) — max 10 min
            age = (datetime.utcnow() - exec_date).total_seconds()
            if age > 600:
                return None
            return {
                'type':    'network_intrusion',
                'message': f"Connexion entrante suspecte depuis {username} sur {resource} ({task})",
                'severity': 'high',
            }

    # Trouver toutes les règles concernant cet utilisateur
    user_rules = [p for p in policies if p['username'] == username]

    if not user_rules:
        return {
            'type':    'user_unknown',
            'message': f"Utilisateur '{username}' absent de la politique de sécurité",
            'severity': 'critical',
        }

    # ═══ Logique allow/deny cumulative ═══
    # Commencer avec aucune tâche autorisée (deny-by-default)
    allowed_tasks = set()

    # Appliquer les rules allow/deny pour (user, resource)
    applicable_rules = [p for p in user_rules if p['resource'] == resource]

    for rule in applicable_rules:
        # Vérifier si la règle s'applique à cette date/heure
        if not (rule['start_date'] <= exec_date <= rule['end_date']):
            continue  # Règle hors plage temporelle

        rule_task = rule['task']
        if rule['policy_type'] == 'allow':
            allowed_tasks.add(rule_task)
        elif rule['policy_type'] == 'deny':
            allowed_tasks.discard(rule_task)

    # Vérifier si la tâche demandée est autorisée
    if task not in allowed_tasks:
        return {
            'type':    'unauthorized_access',
            'message': (f"Utilisateur '{username}' n'a pas le droit d'effectuer "
                        f"'{task}' sur '{resource}'"),
            'severity': 'critical',
        }

    return None  # Accès autorisé


def _process_file(filepath: str, cursor: dict, policies: list, app) -> int:
    """
    Lit les nouvelles lignes d'un fichier JSONL depuis la position du curseur.
    Retourne le nombre de nouvelles intrusions détectées.
    """
    fname = os.path.basename(filepath)
    pos   = cursor.get(fname, 0)
    intrusions = 0

    try:
        size = os.path.getsize(filepath)
        if size <= pos:
            return 0

        with open(filepath, encoding='utf-8', errors='replace') as f:
            f.seek(pos)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                status['analyzed'] += 1

                # 1. Vérification politique normale
                violation = _check_event(event, policies)
                if violation:
                    _record_intrusion(event, violation, app)
                    intrusions += 1
                    status['intrusions'] += 1

                # 2. Détection brute force (indépendante du check politique)
                if event.get('task') == 'failed_login':
                    triggered, count = _detect_brute_force(event.get('username', ''))
                    if triggered:
                        bf_violation = {
                            'type':    'brute_force',
                            'message': (f"Brute force détecté : {count} tentatives échouées "
                                        f"en {BRUTE_FORCE_WINDOW}s pour "
                                        f"'{event.get('username','')}'"),
                            'severity': 'critical',
                        }
                        _record_intrusion(event, bf_violation, app)
                        intrusions += 1
                        status['intrusions'] += 1

        cursor[fname] = size

    except Exception as e:
        status['errors'].append(f'Analyzer [{fname}]: {e}')

    return intrusions


def _record_intrusion(event: dict, violation: dict, app):
    """Crée une Intrusion en DB et notifie le Module 4."""
    with app.app_context():
        from models import db, EventFile, EventEntry, Intrusion

        # Récupérer ou créer le fichier d'événements du jour
        today = f"Live_{datetime.utcnow().strftime('%Y-%m-%d')}"
        ef = EventFile.query.filter_by(name=today).first()
        if not ef:
            num = (EventFile.query.count() or 0) + 1
            ef  = EventFile(file_number=num, name=today)
            db.session.add(ef)
            db.session.flush()

        # Créer l'entrée d'événement
        try:
            exec_date = datetime.fromisoformat(event.get('execution_date', ''))
        except Exception:
            exec_date = datetime.utcnow()

        entry = EventEntry(
            file_id=ef.id,
            username=event.get('username', 'unknown'),
            resource_name=event.get('resource', 'unknown'),
            task=event.get('task', 'unknown'),
            execution_date=exec_date,
        )
        db.session.add(entry)
        db.session.flush()

        # Créer l'intrusion
        intrusion = Intrusion(
            entry_id=entry.id,
            violation_type=violation['message'],
        )
        db.session.add(intrusion)
        db.session.commit()

        # Notifier le Module 4
        if _alert_queue is not None:
            _alert_queue.put({
                'intrusion_id':  intrusion.id,
                'event':         event,
                'violation':     violation,
                'detected_at':   datetime.utcnow().isoformat(),
            })


class EventAnalyzer(threading.Thread):
    """Démon qui surveille events/ et analyse chaque nouveau fichier."""

    def __init__(self, app, alert_queue):
        super().__init__(daemon=True, name='EventAnalyzer')
        self.app   = app
        global _alert_queue
        _alert_queue = alert_queue

    def run(self):
        cursor   = _load_cursor()
        last_policy_reload = 0
        policies = []

        status['running'] = True
        print('[MODULE 2] Analyseur démarré', file=sys.stderr)

        while True:
            # Recharger la politique toutes les 30 secondes
            if time.time() - last_policy_reload > 30:
                try:
                    policies = _load_policy(self.app)
                    last_policy_reload = time.time()
                except Exception as e:
                    status['errors'].append(f'Policy reload: {e}')

            # Scanner les fichiers JSONL du jour
            if os.path.isdir(EVENTS_DIR):
                for fname in sorted(os.listdir(EVENTS_DIR)):
                    if fname.endswith('.jsonl'):
                        fpath = os.path.join(EVENTS_DIR, fname)
                        _process_file(fpath, cursor, policies, self.app)

            _save_cursor(cursor)
            status['last_check'] = datetime.utcnow().strftime('%H:%M:%S')
            time.sleep(3)


def start(app, alert_queue):
    """Démarre l'analyseur d'événements."""
    os.makedirs(EVENTS_DIR, exist_ok=True)
    EventAnalyzer(app, alert_queue).start()
