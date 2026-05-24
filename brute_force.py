"""Détection et blocage de brute force sur le login — persistant en DB.

Fonctionnement :
  - Chaque tentative de login (échec ou succès) est enregistrée dans `LoginAttempt`
  - Une IP est bloquée si elle a > LOCKOUT_THRESHOLD échecs en LOCKOUT_WINDOW secondes
  - Le blocage est persistant : il survit au redémarrage de l'app
  - Les tentatives anciennes sont purgées automatiquement
"""

import os
from datetime import datetime, timedelta
from models import db, LoginAttempt

# Configuration via env vars
LOCKOUT_THRESHOLD = int(os.environ.get('IDS_LOCKOUT_THRESHOLD', '5'))
LOCKOUT_WINDOW    = int(os.environ.get('IDS_LOCKOUT_WINDOW',    '300'))   # 5 minutes
LOCKOUT_DURATION  = int(os.environ.get('IDS_LOCKOUT_DURATION',  '900'))   # 15 minutes


def record_attempt(ip: str, username: str, success: bool, user_agent: str = ''):
    """Enregistre une tentative de login."""
    db.session.add(LoginAttempt(
        ip_address=ip[:45] if ip else '',
        username=(username or '')[:80],
        success=success,
        user_agent=(user_agent or '')[:200],
    ))
    db.session.commit()


def is_blocked(ip: str) -> tuple[bool, int]:
    """Vérifie si une IP est bloquée pour brute force.

    Retourne (blocked, seconds_remaining).
    """
    if not ip:
        return False, 0

    now = datetime.utcnow()

    # Fenêtre de détection : compter les échecs récents
    window_start = now - timedelta(seconds=LOCKOUT_WINDOW)
    failures = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,
        LoginAttempt.timestamp >= window_start,
    ).count()

    if failures < LOCKOUT_THRESHOLD:
        return False, 0

    # Trouver la tentative la plus récente
    last = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,
    ).order_by(LoginAttempt.timestamp.desc()).first()

    if not last:
        return False, 0

    # Bloqué tant qu'il s'est passé moins de LOCKOUT_DURATION depuis la dernière
    elapsed = (now - last.timestamp).total_seconds()
    if elapsed < LOCKOUT_DURATION:
        return True, int(LOCKOUT_DURATION - elapsed)

    return False, 0


def reset_attempts(ip: str):
    """Supprime les tentatives échouées d'une IP (après login réussi)."""
    if not ip:
        return
    LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,
    ).delete(synchronize_session=False)
    db.session.commit()


def purge_old_attempts(days: int = 30):
    """Purge les tentatives plus anciennes que N jours (appelé par Module 5)."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    n = LoginAttempt.query.filter(LoginAttempt.timestamp < cutoff).delete(
        synchronize_session=False
    )
    db.session.commit()
    return n
