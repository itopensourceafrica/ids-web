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

# ── Détection comportementale par patterns (policy_type='detect') ────────────
# Tracker : (pattern_name, username) → [timestamps des événements matchants]
_pattern_tracker: dict = defaultdict(list)
# Cooldown : (pattern_name, username) → dernier ts d'alerte (pour éviter spam)
_pattern_cooldown: dict = {}
PATTERN_COOLDOWN_SEC = 30                # min entre 2 alertes du même pattern/user


def _check_patterns(event: dict, detect_rules: list) -> list:
    """
    Compare un événement aux règles policy_type='detect' (patterns comportementaux).
    Retourne la liste des violations déclenchées (généralement 0 ou 1).

    Exemple de règle detect : (resource=ssh_server, task=failed_login,
                               threshold=5, window_sec=5)
        → 5 failed_login sur ssh_server en 5s = alerte 'BRUTE_FORCE_SSH'
    """
    username = event.get('username', '')
    resource = event.get('resource', '')
    task     = event.get('task', '')
    now      = time.time()

    violations = []
    for rule in detect_rules:
        # Wildcards '*' acceptés sur resource et task
        if rule['resource'] != '*' and rule['resource'] != resource:
            continue
        if rule['task'] != '*' and rule['task'] != task:
            continue
        # Username : '*' = tout user, sinon match exact
        if rule['username'] != '*' and rule['username'] != username:
            continue

        # Trackeur séparé par (pattern, user) — chaque user a son compteur
        key = (rule['pattern_name'], username)
        # Nettoyer la fenêtre glissante
        _pattern_tracker[key] = [t for t in _pattern_tracker[key]
                                  if now - t < rule['window_sec']]
        _pattern_tracker[key].append(now)
        count = len(_pattern_tracker[key])

        if count >= rule['threshold']:
            # Cooldown : ne pas spammer la même alerte
            last_alert = _pattern_cooldown.get(key, 0)
            if now - last_alert < PATTERN_COOLDOWN_SEC:
                continue
            _pattern_cooldown[key] = now
            # Reset le compteur pour repartir d'une fenêtre propre
            _pattern_tracker[key] = []

            violations.append({
                'type':    rule['pattern_name'],
                'message': (f"[{rule['pattern_name']}] {rule['description']} "
                            f"— user '{username}', {count} événements en "
                            f"{rule['window_sec']}s"),
                'severity': rule['severity'] or 'high',
            })
    return violations


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
    """Charge la politique depuis la DB (AccessPolicy).
    Retourne (allow_deny_rules, detect_rules) — séparation pour clarté."""
    with app.app_context():
        from models import AccessPolicy
        policies = AccessPolicy.query.filter_by(active=True).all()
        allow_deny = []
        detect     = []
        for p in policies:
            if p.policy_type == 'detect':
                if not p.threshold or not p.window_sec:
                    continue  # Règle detect invalide (manque seuil)
                detect.append({
                    'pattern_name': p.pattern_name or f'PATTERN_{p.id}',
                    'username':     p.user.username,    # ex: '*' (user virtuel)
                    'resource':     p.resource.name,
                    'task':         p.task,
                    'threshold':    p.threshold,
                    'window_sec':   p.window_sec,
                    'severity':     p.severity or 'high',
                    'description':  f"Pattern détecté",
                })
            else:
                allow_deny.append({
                    'username':    p.user.username,
                    'resource':    p.resource.name,
                    'task':        p.task,
                    'policy_type': p.policy_type,
                    'start_date':  p.start_date,
                    'end_date':    p.end_date,
                })
        return allow_deny, detect


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
        exec_date = datetime.now()

    # Exclure les comptes système sans contrôle d'accès
    system_accounts = {'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE',
                       'daemon', 'nobody', 'www-data', '_apt', 'gdm'}
    if username in system_accounts:
        return None

    # Une tentative de connexion échouée (failed_login) isolée n'est PAS une
    # intrusion : c'est la RÉPÉTITION qui l'est. On laisse donc ces événements
    # uniquement aux patterns 'detect' (BRUTE_FORCE_*) — pas d'alerte par
    # événement, ce qui évite le bruit et produit une alerte propre et nommée.
    if task == 'failed_login':
        return None

    # Les événements réseau ont une IP comme username (source network/*)
    # Ils bypassent la politique utilisateur et sont toujours des alertes
    source = event.get('source', '')
    if source.startswith('network/') and source != 'network/port_scan':
        import re as _re
        if _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', username):
            # Ignorer les vieux événements réseau (backlog JSONL) — max 10 min
            age = (datetime.now() - exec_date).total_seconds()
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


def _process_file(filepath: str, cursor: dict, policies: list,
                  detect_rules: list, app) -> int:
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

                # 1. Vérification politique allow/deny
                violation = _check_event(event, policies)
                if violation:
                    _record_intrusion(event, violation, app)
                    intrusions += 1
                    status['intrusions'] += 1

                # 2. Détection comportementale via patterns 'detect' (configurables en DB)
                for pat_violation in _check_patterns(event, detect_rules):
                    _record_intrusion(event, pat_violation, app)
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
        today = f"Live_{datetime.now().strftime('%Y-%m-%d')}"
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
            exec_date = datetime.now()

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
                'detected_at':   datetime.now().isoformat(),
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
        policies      = []
        detect_rules  = []

        status['running'] = True
        print('[MODULE 2] Analyseur démarré', file=sys.stderr)

        while True:
            # Recharger la politique toutes les 30 secondes
            if time.time() - last_policy_reload > 30:
                try:
                    policies, detect_rules = _load_policy(self.app)
                    last_policy_reload = time.time()
                    if detect_rules:
                        print(f'[MODULE 2] {len(detect_rules)} patterns detect chargés',
                              file=sys.stderr)
                except Exception as e:
                    status['errors'].append(f'Policy reload: {e}')

            # Scanner les fichiers JSONL du jour
            if os.path.isdir(EVENTS_DIR):
                for fname in sorted(os.listdir(EVENTS_DIR)):
                    if fname.endswith('.jsonl'):
                        fpath = os.path.join(EVENTS_DIR, fname)
                        _process_file(fpath, cursor, policies, detect_rules, self.app)

            _save_cursor(cursor)
            status['last_check'] = datetime.now().strftime('%H:%M:%S')
            time.sleep(3)


def start(app, alert_queue):
    """Démarre l'analyseur d'événements."""
    os.makedirs(EVENTS_DIR, exist_ok=True)
    EventAnalyzer(app, alert_queue).start()
