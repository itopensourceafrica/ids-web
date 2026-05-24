"""
Authentification web pour l'IDS — sessions + CSRF + audit.

Utilise Werkzeug pour le hash des mots de passe (déjà disponible avec Flask).
Pas de Flask-Login : décorateur maison + session Flask suffisent.
"""

import os
import secrets
from functools import wraps
from datetime import datetime
from flask import session, request, redirect, url_for, flash, abort, g


# ── Décorateurs ────────────────────────────────────────────────────────────

def login_required(view):
    """Bloque l'accès si l'utilisateur n'est pas connecté."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    """Bloque l'accès si l'utilisateur n'est pas admin."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            flash("Action réservée aux administrateurs.", 'danger')
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def editor_required(view):
    """Bloque l'accès si l'utilisateur ne peut pas modifier (viewer-only)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        if session.get('role') not in ('admin', 'analyst'):
            flash("Action réservée aux admins et analystes.", 'danger')
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ── CSRF protection ────────────────────────────────────────────────────────

def generate_csrf_token():
    """Génère ou récupère le token CSRF de la session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']


def validate_csrf(token):
    """Valide le token CSRF (constant-time comparison)."""
    expected = session.get('_csrf_token', '')
    if not expected or not token:
        return False
    return secrets.compare_digest(expected, token)


def csrf_protect(view):
    """Décorateur : vérifie le token CSRF sur les POST."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
            if not validate_csrf(token):
                abort(403)
        return view(*args, **kwargs)
    return wrapped


# ── Audit log ──────────────────────────────────────────────────────────────

def log_action(action: str, target: str = '', details: str = ''):
    """Enregistre une action dans l'audit log."""
    from models import db, AuditLog

    user_id  = session.get('user_id')
    username = session.get('username', 'anonymous')
    ip       = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua       = request.headers.get('User-Agent', '')[:200]

    db.session.add(AuditLog(
        user_id=user_id, username=username, action=action,
        target=target, ip_address=ip, user_agent=ua, details=details,
    ))
    db.session.commit()


# ── Helpers de session ─────────────────────────────────────────────────────

def login_user(user):
    """Établit la session pour un utilisateur."""
    session.clear()
    session['user_id']  = user.id
    session['username'] = user.username
    session['role']     = user.role
    session.permanent   = True


def logout_user():
    """Termine la session."""
    session.clear()


def current_user():
    """Retourne le WebUser courant ou None."""
    from models import WebUser
    uid = session.get('user_id')
    if uid:
        return WebUser.query.get(uid)
    return None


# ── Initialisation : admin par défaut ───────────────────────────────────────

def ensure_default_admin(app):
    """Crée un compte admin par défaut au premier démarrage."""
    from models import db, WebUser

    with app.app_context():
        if WebUser.query.count() == 0:
            default_password = os.environ.get('IDS_ADMIN_PASSWORD') or 'admin'
            admin = WebUser(username='admin', role='admin', active=True)
            admin.set_password(default_password)
            db.session.add(admin)
            db.session.commit()

            print(f'\n{"="*60}', flush=True)
            print(f'[IDS] Admin par défaut créé', flush=True)
            print(f'      Username : admin', flush=True)
            if default_password == 'admin':
                print(f'      Password : admin  ⚠️  CHANGEZ-LE IMMÉDIATEMENT', flush=True)
                print(f'      (ou définissez IDS_ADMIN_PASSWORD dans l\'environnement)',
                      flush=True)
            else:
                print(f'      Password : (depuis IDS_ADMIN_PASSWORD)', flush=True)
            print(f'{"="*60}\n', flush=True)
