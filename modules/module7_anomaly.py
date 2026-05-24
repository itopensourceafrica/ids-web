"""
MODULE 7 — Détection d'anomalies par baseline statistique

Construit pour chaque utilisateur surveillé un profil de comportement normal :
  - Distribution des heures d'activité (24 buckets)
  - Ressources accédées habituellement (set)
  - Tâches habituellement effectuées (set)
  - Taux moyen de failed_login

Compare l'activité récente à la baseline. Si une activité dévie fortement
(Z-score > seuil), génère une alerte d'anomalie.

Pas de ML lourd : statistiques Bayesiennes simples (suffisant pour MVP).
La baseline est mise à jour en glissant (decay exponentiel).
"""

import os
import sys
import math
import time
import threading
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# Configuration
BASELINE_WINDOW_DAYS = int(os.environ.get('IDS_BASELINE_DAYS', '7'))
ANALYSIS_INTERVAL    = int(os.environ.get('IDS_ANOMALY_INTERVAL', '300'))  # 5 min
ZSCORE_THRESHOLD     = float(os.environ.get('IDS_ANOMALY_ZSCORE', '3.0'))
MIN_BASELINE_SAMPLES = int(os.environ.get('IDS_ANOMALY_MIN_SAMPLES', '50'))

status = {
    'running':           False,
    'baselines_built':   0,
    'anomalies_found':   0,
    'last_run':          None,
    'errors':            [],
}


class UserBaseline:
    """Baseline statistique pour un utilisateur."""
    __slots__ = ('username', 'hour_counts', 'resources', 'tasks',
                 'total_events', 'failed_login_count')

    def __init__(self, username):
        self.username = username
        self.hour_counts = [0] * 24
        self.resources = Counter()
        self.tasks = Counter()
        self.total_events = 0
        self.failed_login_count = 0

    def add(self, hour, resource, task):
        self.hour_counts[hour] += 1
        self.resources[resource] += 1
        self.tasks[task] += 1
        self.total_events += 1
        if task == 'failed_login':
            self.failed_login_count += 1

    def hour_anomaly_score(self, hour):
        """Z-score de l'heure courante vs la distribution baseline."""
        if self.total_events < MIN_BASELINE_SAMPLES:
            return 0.0
        mean = self.total_events / 24
        if mean == 0:
            return 0.0
        std = statistics.stdev(self.hour_counts) if any(self.hour_counts) else 1.0
        if std == 0:
            return 0.0
        observed = self.hour_counts[hour]
        # Activité à une heure jamais vue → score élevé
        if observed == 0:
            return -(mean / std) if std > 0 else 0.0
        return (observed - mean) / std

    def is_unusual_resource(self, resource):
        """True si la ressource n'a jamais (ou très rarement) été accédée."""
        if self.total_events < MIN_BASELINE_SAMPLES:
            return False
        count = self.resources.get(resource, 0)
        return count == 0 or (count / self.total_events) < 0.01

    def is_unusual_task(self, task):
        """True si la tâche est très rare pour cet utilisateur."""
        if self.total_events < MIN_BASELINE_SAMPLES:
            return False
        count = self.tasks.get(task, 0)
        return count == 0 or (count / self.total_events) < 0.01


class AnomalyDetector(threading.Thread):
    def __init__(self, app, alert_queue):
        super().__init__(daemon=True, name='AnomalyDetector')
        self.app = app
        self.alert_queue = alert_queue
        self._baselines = {}     # username → UserBaseline
        self._recent_alerts = {} # (username, type) → last_ts

    def _build_baselines(self):
        """Construit les baselines à partir des EventEntry de la fenêtre."""
        with self.app.app_context():
            from models import EventEntry
            cutoff = datetime.utcnow() - timedelta(days=BASELINE_WINDOW_DAYS)
            entries = EventEntry.query.filter(
                EventEntry.timestamp >= cutoff
            ).all()

            new_baselines = {}
            for e in entries:
                if not e.username or e.username == 'SYSTEM':
                    continue
                if e.username not in new_baselines:
                    new_baselines[e.username] = UserBaseline(e.username)
                hour = e.execution_date.hour if e.execution_date else 12
                new_baselines[e.username].add(hour, e.resource_name, e.task)

            self._baselines = new_baselines
            status['baselines_built'] = len(new_baselines)

    def _check_recent_anomalies(self):
        """Analyse l'activité récente (dernière heure) vs baselines."""
        with self.app.app_context():
            from models import EventEntry
            cutoff = datetime.utcnow() - timedelta(hours=1)
            recent = EventEntry.query.filter(
                EventEntry.timestamp >= cutoff
            ).all()

            anomalies = []
            for e in recent:
                if not e.username or e.username == 'SYSTEM':
                    continue
                baseline = self._baselines.get(e.username)
                if not baseline:
                    continue

                anomaly_reasons = []
                hour = e.execution_date.hour if e.execution_date else 12

                # 1. Activité à une heure très inhabituelle
                z = baseline.hour_anomaly_score(hour)
                if abs(z) > ZSCORE_THRESHOLD:
                    anomaly_reasons.append(f'heure inhabituelle (z-score={z:.2f}, h={hour})')

                # 2. Ressource jamais/rarement accédée
                if baseline.is_unusual_resource(e.resource_name):
                    anomaly_reasons.append(f'ressource inhabituelle ({e.resource_name})')

                # 3. Tâche inhabituelle
                if baseline.is_unusual_task(e.task):
                    anomaly_reasons.append(f'tâche inhabituelle ({e.task})')

                if anomaly_reasons:
                    # Déduplication : 1 alerte par user / type / heure
                    key = (e.username, e.task, hour)
                    now = time.time()
                    if now - self._recent_alerts.get(key, 0) < 3600:
                        continue
                    self._recent_alerts[key] = now

                    anomalies.append({
                        'username': e.username,
                        'resource': e.resource_name,
                        'task':     e.task,
                        'reasons':  anomaly_reasons,
                        'execution_date': e.execution_date,
                    })
            return anomalies

    def run(self):
        status['running'] = True
        # Attendre 2 min avant la première analyse (laisser les modules démarrer)
        time.sleep(120)

        print('[MODULE 7] Détecteur d\'anomalies démarré', file=sys.stderr)

        while True:
            try:
                # Reconstruire baselines toutes les 5 analyses
                if (status['baselines_built'] == 0
                    or int(time.time()) % (ANALYSIS_INTERVAL * 5) < ANALYSIS_INTERVAL):
                    self._build_baselines()

                # Analyser l'activité récente
                anomalies = self._check_recent_anomalies()
                status['last_run'] = datetime.utcnow().strftime('%H:%M:%S')

                for a in anomalies:
                    msg = (f'[ANOMALY] {a["username"]} — '
                           f'{a["task"]} sur {a["resource"]} : '
                           + ' ; '.join(a['reasons']))
                    print(msg, file=sys.stderr)

                    self.alert_queue.put({
                        'event': {
                            'username': a['username'],
                            'resource': a['resource'],
                            'task':     a['task'],
                            'source':   'anomaly_detection',
                            'execution_date': (a['execution_date'].isoformat()
                                               if a['execution_date'] else
                                               datetime.utcnow().isoformat()),
                            'raw':      msg[:500],
                        },
                        'violation': {
                            'type':     'behavior_anomaly',
                            'message':  msg,
                            'severity': 'medium',  # anomalie n'est pas forcément attaque
                        },
                        'detected_at': datetime.utcnow().isoformat(),
                    })
                    status['anomalies_found'] += 1

                time.sleep(ANALYSIS_INTERVAL)
            except Exception as e:
                status['errors'].append(f'AnomalyDetector: {e}')
                print(f'[MODULE 7] Erreur: {e}', file=sys.stderr)
                time.sleep(60)


def start(app, alert_queue):
    AnomalyDetector(app, alert_queue).start()
