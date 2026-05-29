"""
IDS Web Platform — Orchestrateur principal

Démarre les 4 modules démons au lancement puis expose l'interface web.
"""

import os
import sys
import json
import queue
import secrets
import time as time_module
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, Response, stream_with_context, session, abort)
from models import (db, Alert, Resource, IDSUser, AccessPolicy,
                    EventFile, EventEntry, Intrusion, NidsRule,
                    WebUser, AuditLog, LoginAttempt)
from auth import (login_required, admin_required, editor_required,
                  csrf_protect, generate_csrf_token, validate_csrf,
                  login_user, logout_user, current_user, log_action,
                  ensure_default_admin)
from brute_force import (record_attempt, is_blocked, reset_attempts,
                         LOCKOUT_THRESHOLD, LOCKOUT_DURATION)

app = Flask(__name__)

# ── Configuration sécurité (SECRET_KEY via env var) ──────────────
# Génère un secret aléatoire si non défini (logout tous les utilisateurs au restart)
app.config['SECRET_KEY'] = os.environ.get('IDS_SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI']        = 'sqlite:///ids.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY']        = True
app.config['SESSION_COOKIE_SAMESITE']        = 'Lax'
app.config['SESSION_COOKIE_SECURE']          = os.environ.get('IDS_HTTPS') == '1'
app.config['PERMANENT_SESSION_LIFETIME']     = timedelta(hours=8)

db.init_app(app)

# ── CSRF token disponible dans tous les templates ────────────────
@app.context_processor
def inject_csrf():
    return {'csrf_token': generate_csrf_token, 'current_user': current_user}

# ── Validation CSRF automatique sur tous les POST ────────────────
@app.before_request
def csrf_validate_all():
    # Exempter login (token donné dans la page)
    if request.method == 'POST' and request.endpoint not in (None, 'login'):
        token = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
        if not validate_csrf(token):
            abort(403, 'CSRF token invalide ou manquant')

# ── Auth requise sur toute l'app sauf /login, /favicon, /health, /metrics ─
@app.before_request
def require_login_globally():
    public = {'login', 'static', 'health', 'metrics', None}
    if request.endpoint in public:
        return
    if request.path == '/favicon.ico':
        return
    if 'user_id' not in session:
        return redirect(url_for('login', next=request.path))

# File partagée entre Module 2 et Module 4
_alert_queue: queue.Queue = queue.Queue()

BASE_DIR   = os.path.dirname(__file__)
EVENTS_DIR = os.path.join(BASE_DIR, 'events')
ALERTS_DIR = os.path.join(BASE_DIR, 'alerts')


# ══════════════════════════════════════════════════════════════════
# DÉMARRAGE DES 4 MODULES
# ══════════════════════════════════════════════════════════════════

def _start_modules():
    from modules import module1_collector as m1
    from modules import module2_analyzer  as m2
    from modules import module3_policy    as m3
    from modules import module4_alerter   as m4
    from modules import module5_maintenance as m5
    from modules import module6_correlation as m6
    from modules import module7_anomaly as m7

    m3.start(app)                      # Politique d'abord
    time_module.sleep(1)               # Laisser la politique se charger
    m1.start(app)                      # Collecteur d'événements
    m2.start(app, _alert_queue)        # Analyseur
    m4.start(app, _alert_queue)        # Générateur d'alertes (canaux)
    m5.start(app)                      # Maintenance / housekeeping
    m6.start(app, _alert_queue)        # Corrélation kill chain
    m7.start(app, _alert_queue)        # Détection d'anomalies

    print('[IDS] Les 7 modules sont démarrés.', file=sys.stderr)


# ══════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════

@app.route('/favicon.ico')
def favicon():
    return Response(status=204)


# ══════════════════════════════════════════════════════════════════
# HEALTHCHECK & MÉTRIQUES (public, sans auth)
# ══════════════════════════════════════════════════════════════════

@app.route('/health')
def health():
    """Healthcheck détaillé — usable par k8s/load balancer/monitoring."""
    from modules import module1_collector as m1
    from modules import module2_analyzer  as m2
    from modules import module3_policy    as m3
    from modules import module4_alerter   as m4
    from modules import module5_maintenance as m5
    from modules import module6_correlation as m6
    from modules import module7_anomaly   as m7

    try:
        # Test DB
        Alert.query.count()
        db_ok = True
    except Exception:
        db_ok = False

    all_modules = {
        'collector':    m1.status.get('running', False),
        'analyzer':     m2.status.get('running', False),
        'policy':       m3.status.get('running', False),
        'alerter':      m4.status.get('running', False),
        'maintenance':  m5.status.get('running', False),
        'correlation':  m6.status.get('running', False),
        'anomaly':      m7.status.get('running', False),
    }

    healthy = db_ok and all(all_modules.values())

    payload = {
        'status': 'healthy' if healthy else 'degraded',
        'database': db_ok,
        'modules': all_modules,
        'sniffer': {
            'active': m1.sniffer_status.get('active', False),
            'packets_captured': m1.sniffer_status.get('packets_captured', 0),
        },
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    }
    return Response(json.dumps(payload), status=200 if healthy else 503,
                    mimetype='application/json')


@app.route('/metrics')
def metrics():
    """Métriques Prometheus (text format).

    Sécurité : protégé par IP whitelist via env var IDS_METRICS_ALLOW
    (par défaut : localhost uniquement).
    """
    allowed = os.environ.get('IDS_METRICS_ALLOW', '127.0.0.1,::1').split(',')
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
    if client_ip.strip() not in [a.strip() for a in allowed]:
        return Response('Forbidden', status=403)

    from modules import module1_collector as m1
    from modules import module2_analyzer  as m2
    from modules import module4_alerter   as m4
    from modules import module5_maintenance as m5

    # Compteurs DB
    try:
        total_alerts = Alert.query.count()
        unack_alerts = Alert.query.filter_by(acknowledged=False).count()
        total_intrusions = Intrusion.query.count()
        critical_unack = Alert.query.filter_by(
            severity='critical', acknowledged=False).count()
        high_unack = Alert.query.filter_by(
            severity='high', acknowledged=False).count()
    except Exception:
        total_alerts = unack_alerts = total_intrusions = critical_unack = high_unack = 0

    lines = [
        '# HELP ids_alerts_total Total number of alerts',
        '# TYPE ids_alerts_total counter',
        f'ids_alerts_total {total_alerts}',
        '',
        '# HELP ids_alerts_unacknowledged Unacknowledged alerts by severity',
        '# TYPE ids_alerts_unacknowledged gauge',
        f'ids_alerts_unacknowledged{{severity="critical"}} {critical_unack}',
        f'ids_alerts_unacknowledged{{severity="high"}} {high_unack}',
        f'ids_alerts_unacknowledged{{severity="all"}} {unack_alerts}',
        '',
        '# HELP ids_intrusions_total Total intrusions detected',
        '# TYPE ids_intrusions_total counter',
        f'ids_intrusions_total {total_intrusions}',
        '',
        '# HELP ids_nids_packets_captured Packets captured by NIDS',
        '# TYPE ids_nids_packets_captured counter',
        f'ids_nids_packets_captured {m1.sniffer_status.get("packets_captured", 0)}',
        '',
        '# HELP ids_nids_active NIDS sniffer state (1=running)',
        '# TYPE ids_nids_active gauge',
        f'ids_nids_active {1 if m1.sniffer_status.get("active") else 0}',
        '',
        '# HELP ids_module_running State of each daemon (1=running)',
        '# TYPE ids_module_running gauge',
        f'ids_module_running{{module="collector"}} {1 if m1.status.get("running") else 0}',
        f'ids_module_running{{module="analyzer"}} {1 if m2.status.get("running") else 0}',
        f'ids_module_running{{module="alerter"}} {1 if m4.status.get("running") else 0}',
        f'ids_module_running{{module="maintenance"}} {1 if m5.status.get("running") else 0}',
        '',
        '# HELP ids_analyzer_processed Events processed by analyzer',
        '# TYPE ids_analyzer_processed counter',
        f'ids_analyzer_processed {m2.status.get("analyzed", 0)}',
        '',
        '# HELP ids_alerter_sent Alerts dispatched by alerter',
        '# TYPE ids_alerter_sent counter',
        f'ids_alerter_sent {m4.status.get("alerts_sent", 0)}',
        '',
        '# HELP ids_maintenance_purged Items purged by maintenance',
        '# TYPE ids_maintenance_purged counter',
        f'ids_maintenance_purged{{type="alerts"}} {m5.status.get("alerts_purged", 0)}',
        f'ids_maintenance_purged{{type="intrusions"}} {m5.status.get("intrusions_purged", 0)}',
        f'ids_maintenance_purged{{type="entries"}} {m5.status.get("entries_purged", 0)}',
    ]
    return Response('\n'.join(lines) + '\n', mimetype='text/plain; version=0.0.4')


# ══════════════════════════════════════════════════════════════════
# AUTHENTIFICATION
# ══════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
    ua = request.headers.get('User-Agent', '')

    if request.method == 'POST':
        # Validation CSRF manuelle (la global before_request exempte /login)
        token = request.form.get('_csrf_token')
        if not validate_csrf(token):
            flash('Token CSRF invalide. Rechargez la page.', 'danger')
            return redirect(url_for('login'))

        # Vérification brute force (persistant en DB)
        blocked, remaining = is_blocked(ip)
        if blocked:
            mins = remaining // 60
            flash(f'Trop de tentatives échouées. Réessayez dans {mins} min.', 'danger')
            return redirect(url_for('login'))

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '').strip()

        user = WebUser.query.filter_by(username=username, active=True).first()

        # Authentification : password OK ?
        if user and user.check_password(password):
            # Si 2FA activé, vérifier le code TOTP
            if user.totp_enabled:
                import pyotp
                if not user.totp_secret:
                    flash('Erreur 2FA : secret manquant. Contactez un admin.', 'danger')
                    return redirect(url_for('login'))
                totp = pyotp.TOTP(user.totp_secret)
                if not totp_code:
                    # Re-afficher le login avec un champ TOTP
                    return render_template('login.html',
                        require_totp=True, username=username)
                if not totp.verify(totp_code, valid_window=1):
                    record_attempt(ip, username, success=False, user_agent=ua)
                    flash('Code 2FA invalide.', 'danger')
                    return render_template('login.html',
                        require_totp=True, username=username)

            # Succès
            login_user(user)
            user.last_login = datetime.utcnow()
            record_attempt(ip, username, success=True, user_agent=ua)
            reset_attempts(ip)
            db.session.commit()
            log_action('login', target=username)

            next_url = request.form.get('next') or url_for('index')
            if not next_url.startswith('/'):
                next_url = url_for('index')
            return redirect(next_url)
        else:
            record_attempt(ip, username, success=False, user_agent=ua)
            flash('Identifiants invalides.', 'danger')
            return redirect(url_for('login'))

    # GET
    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action('logout', target=session.get('username', ''))
    logout_user()
    flash('Déconnexion réussie.', 'info')
    return redirect(url_for('login'))


# ── 2FA TOTP (intégré dans /account/password) ─────────────────────

@app.route('/account/2fa/setup', methods=['POST'])
@login_required
def account_2fa_setup():
    """Génère un nouveau secret TOTP + QR code pour l'activation.
    Affiche le formulaire de confirmation sur la page sécurité."""
    import pyotp, qrcode, io, base64
    user = current_user()

    # Générer un nouveau secret (en attente de validation)
    secret = pyotp.random_base32()
    session['_pending_totp_secret'] = secret

    # URI standard otpauth:// pour Google Authenticator/Authy
    totp_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.username,
        issuer_name='IDS Web'
    )

    # Générer le QR code en base64
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('ascii')

    return render_template('change_password.html',
        user=user, setup_mode=True,
        secret=secret, qr_b64=qr_b64, totp_uri=totp_uri)


@app.route('/account/2fa/confirm', methods=['POST'])
@login_required
def account_2fa_confirm():
    """Active le 2FA après vérification du code."""
    import pyotp
    user = current_user()
    code = request.form.get('totp_code', '').strip()
    pending_secret = session.get('_pending_totp_secret')

    if not pending_secret:
        flash('Session expirée. Recommencez l\'activation.', 'danger')
        return redirect(url_for('change_password'))

    totp = pyotp.TOTP(pending_secret)
    if not totp.verify(code, valid_window=1):
        flash('Code invalide. Vérifiez l\'heure de votre téléphone.', 'danger')
        return redirect(url_for('change_password'))

    user.totp_secret = pending_secret
    user.totp_enabled = True
    db.session.commit()
    session.pop('_pending_totp_secret', None)
    log_action('2fa_enable', target=user.username)
    flash('2FA activé avec succès !', 'success')
    return redirect(url_for('change_password'))


@app.route('/account/2fa/disable', methods=['POST'])
@login_required
def account_2fa_disable():
    """Désactive le 2FA (requiert mot de passe pour confirmer)."""
    user = current_user()
    password = request.form.get('password', '')

    if not user.check_password(password):
        flash('Mot de passe incorrect.', 'danger')
        return redirect(url_for('change_password'))

    user.totp_secret = None
    user.totp_enabled = False
    db.session.commit()
    log_action('2fa_disable', target=user.username)
    flash('2FA désactivé.', 'info')
    return redirect(url_for('change_password'))


# Redirection compat : /account/2fa → /account/password
@app.route('/account/2fa')
@login_required
def account_2fa_redirect():
    return redirect(url_for('change_password'))


@app.route('/account/password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = current_user()
    if request.method == 'POST':
        current_pwd = request.form.get('current_password', '')
        new_pwd = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if not user.check_password(current_pwd):
            flash('Mot de passe actuel incorrect.', 'danger')
            return redirect(url_for('change_password'))
        if len(new_pwd) < 8:
            flash('Le nouveau mot de passe doit avoir au moins 8 caractères.', 'danger')
            return redirect(url_for('change_password'))
        if new_pwd != confirm:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return redirect(url_for('change_password'))

        user.set_password(new_pwd)
        db.session.commit()
        log_action('password_change', target=user.username)
        flash('Mot de passe modifié avec succès.', 'success')
        return redirect(url_for('index'))

    return render_template('change_password.html', user=user)


# ══════════════════════════════════════════════════════════════════
# GESTION DES UTILISATEURS WEB (admin only)
# ══════════════════════════════════════════════════════════════════

@app.route('/admin/users')
@admin_required
def admin_users():
    return render_template('admin_users.html',
        users=WebUser.query.order_by(WebUser.username).all(),
        recent_audit=AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(30).all(),
    )

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    username = request.form['username'].strip()
    password = request.form['password']
    role     = request.form.get('role', 'viewer')

    if WebUser.query.filter_by(username=username).first():
        flash(f"L'utilisateur '{username}' existe déjà.", 'warning')
        return redirect(url_for('admin_users'))
    if len(password) < 8:
        flash('Mot de passe trop court (8 caractères minimum).', 'danger')
        return redirect(url_for('admin_users'))
    if role not in ('admin', 'analyst', 'viewer'):
        flash('Rôle invalide.', 'danger')
        return redirect(url_for('admin_users'))

    u = WebUser(username=username, role=role, active=True)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    log_action('user_create', target=username, details=f'role={role}')
    flash(f"Utilisateur '{username}' créé.", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle/<int:user_id>')
@admin_required
def admin_toggle_user(user_id):
    u = WebUser.query.get_or_404(user_id)
    if u.id == session.get('user_id'):
        flash('Vous ne pouvez pas désactiver votre propre compte.', 'danger')
        return redirect(url_for('admin_users'))
    u.active = not u.active
    db.session.commit()
    log_action('user_toggle', target=u.username, details=f'active={u.active}')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>')
@admin_required
def admin_delete_user(user_id):
    u = WebUser.query.get_or_404(user_id)
    if u.id == session.get('user_id'):
        flash('Vous ne pouvez pas supprimer votre propre compte.', 'danger')
        return redirect(url_for('admin_users'))
    name = u.username
    db.session.delete(u)
    db.session.commit()
    log_action('user_delete', target=name)
    flash(f"Utilisateur '{name}' supprimé.", 'info')
    return redirect(url_for('admin_users'))


# ══════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html',
        recent_intrusions=Intrusion.query.order_by(Intrusion.detected_at.desc()).limit(15).all(),
        alerts=Alert.query.order_by(Alert.timestamp.desc()).limit(10).all(),
        total_alerts=Alert.query.count(),
        critical=Alert.query.filter_by(severity='critical').count(),
        high=Alert.query.filter_by(severity='high').count(),
        total_intrusions=Intrusion.query.count(),
        total_files=EventFile.query.count(),
    )


def _alerts_query(args):
    """Construit la query Alert avec filtres optionnels."""
    q = Alert.query

    # Filtre sévérité
    sev = args.get('severity')
    if sev in ('critical', 'high', 'medium', 'low'):
        q = q.filter(Alert.severity == sev)

    # Filtre statut
    status_f = args.get('status')
    if status_f == 'unack':
        q = q.filter(Alert.acknowledged == False)
    elif status_f == 'ack':
        q = q.filter(Alert.acknowledged == True)

    # Filtre recherche texte
    search = args.get('q', '').strip()
    if search:
        q = q.filter(Alert.message.ilike(f'%{search}%'))

    # Filtre date
    days = args.get('days')
    if days:
        try:
            cutoff = datetime.utcnow() - timedelta(days=int(days))
            q = q.filter(Alert.timestamp >= cutoff)
        except ValueError:
            pass

    return q.order_by(Alert.timestamp.desc())


@app.route('/alerts')
def alerts():
    page = max(1, int(request.args.get('page', 1) or 1))
    per_page = min(200, int(request.args.get('per_page', 50) or 50))

    q = _alerts_query(request.args)
    total = q.count()
    items = q.limit(per_page).offset((page - 1) * per_page).all()
    pages = (total + per_page - 1) // per_page

    return render_template('alerts.html',
        alerts=items,
        page=page, per_page=per_page, pages=pages, total=total,
        filter_sev=request.args.get('severity', ''),
        filter_status=request.args.get('status', ''),
        filter_days=request.args.get('days', ''),
        filter_q=request.args.get('q', ''),
    )


@app.route('/alerts/export.csv')
def alerts_export_csv():
    """Export CSV des alertes filtrées (max 10000 lignes)."""
    import csv
    import io
    q = _alerts_query(request.args)
    rows = q.limit(10000).all()

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(['id', 'timestamp', 'severity', 'acknowledged', 'message'])
    for a in rows:
        writer.writerow([
            a.id,
            a.timestamp.strftime('%Y-%m-%d %H:%M:%S') if a.timestamp else '',
            a.severity or '',
            '1' if a.acknowledged else '0',
            (a.message or '').replace('\n', ' ').replace('\r', ''),
        ])

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=alerts_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
        }
    )


@app.route('/ack_alert/<int:alert_id>')
@editor_required
def ack_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.acknowledged = True
    db.session.commit()
    return redirect(url_for('alerts', **{k: v for k, v in request.args.items()}))

@app.route('/ack_all_alerts')
@editor_required
def ack_all_alerts():
    Alert.query.filter_by(acknowledged=False).update({'acknowledged': True})
    db.session.commit()
    flash('Toutes les alertes acquittées.', 'success')
    return redirect(url_for('alerts'))


# ══════════════════════════════════════════════════════════════════
# MODULE 3 — Politique de sécurité (routes web)
# ══════════════════════════════════════════════════════════════════

@app.route('/ids/policy')
def ids_policy():
    from modules import module3_policy as m3
    rule_type = request.args.get('type', 'hids')  # hids | detect | nids
    all_policies = AccessPolicy.query.all()
    # Séparer allow/deny (HIDS classique) des patterns 'detect'
    hids_policies   = [p for p in all_policies if p.policy_type in ('allow', 'deny')]
    detect_patterns = [p for p in all_policies if p.policy_type == 'detect']
    return render_template('ids_policy.html',
        rule_type=rule_type,
        policies=hids_policies,
        detect_patterns=detect_patterns,
        nids_rules=NidsRule.query.order_by(NidsRule.id).all(),
        users=IDSUser.query.all(),
        resources=Resource.query.all(),
        policy_status=m3.status,
        policy_file=m3.POLICY_FILE,
    )

# ── Règles NIDS ────────────────────────────────────────────────────────────
@app.route('/ids/policy/nids/add', methods=['POST'])
@editor_required
def ids_add_nids_rule():
    from validators import validate_nids_rule_form

    valid, errors = validate_nids_rule_form(request.form)
    if not valid:
        for err in errors:
            flash(err, 'danger')
        return redirect(url_for('ids_policy', type='nids'))

    db.session.add(NidsRule(
        name      = request.form['name'].strip(),
        version   = request.form.get('version', 'ipv4'),
        protocol  = request.form.get('protocol', 'tcp'),
        src_ip    = request.form.get('src_ip', '0.0.0.0/0').strip() or '0.0.0.0/0',
        dst_ip    = request.form.get('dst_ip', '0.0.0.0/0').strip() or '0.0.0.0/0',
        src_port  = request.form.get('src_port', 'any').strip() or 'any',
        dst_port  = request.form.get('dst_port', 'any').strip() or 'any',
        tcp_flags = request.form.get('tcp_flags', '').strip(),
        action    = request.form.get('action', 'alert'),
        severity  = request.form.get('severity', 'medium'),
        active    = True,
    ))
    db.session.commit()
    log_action('nids_rule_create', target=request.form['name'].strip())
    flash('Règle NIDS ajoutée.', 'success')
    return redirect(url_for('ids_policy', type='nids'))

@app.route('/ids/policy/nids/toggle/<int:rule_id>')
@editor_required
def ids_toggle_nids_rule(rule_id):
    r = NidsRule.query.get_or_404(rule_id)
    r.active = not r.active
    db.session.commit()
    return redirect(url_for('ids_policy', type='nids'))

@app.route('/ids/policy/nids/delete/<int:rule_id>')
@editor_required
def ids_delete_nids_rule(rule_id):
    db.session.delete(NidsRule.query.get_or_404(rule_id))
    db.session.commit()
    flash('Règle NIDS supprimée.', 'info')
    return redirect(url_for('ids_policy', type='nids'))

@app.route('/ids/policy/add', methods=['POST'])
@editor_required
def ids_add_policy():
    s_date = request.form['start_date']
    s_time = request.form.get('start_time', '00:00') or '00:00'
    e_date = request.form['end_date']
    e_time = request.form.get('end_time', '00:00') or '00:00'
    db.session.add(AccessPolicy(
        user_id=int(request.form['user_id']),
        resource_id=int(request.form['resource_id']),
        task=request.form['task'],
        policy_type=request.form.get('policy_type', 'allow'),
        start_date=datetime.strptime(f'{s_date}T{s_time}', '%Y-%m-%dT%H:%M'),
        end_date=datetime.strptime(f'{e_date}T{e_time}', '%Y-%m-%dT%H:%M'),
    ))
    db.session.commit()
    flash("Règle d'accès ajoutée.", 'success')
    return redirect(url_for('ids_policy'))

@app.route('/ids/policy/toggle/<int:policy_id>')
@editor_required
def ids_toggle_policy(policy_id):
    p = AccessPolicy.query.get_or_404(policy_id)
    p.active = not p.active
    db.session.commit()
    next_type = 'detect' if p.policy_type == 'detect' else 'hids'
    return redirect(url_for('ids_policy', type=next_type))


# ── Patterns de détection comportementale (policy_type='detect') ───────────
@app.route('/ids/policy/detect/add', methods=['POST'])
@editor_required
def ids_add_detect_pattern():
    """Crée un pattern de détection comportementale.
    Ex: 5 failed_login sur ssh_server en 5s → alerte BRUTE_FORCE_SSH."""
    # Récupérer ou créer l'utilisateur virtuel '*'
    any_user = IDSUser.query.filter_by(username='*').first()
    if not any_user:
        any_user = IDSUser(username='*', role='system')
        db.session.add(any_user)
        db.session.commit()

    try:
        threshold  = int(request.form.get('threshold', 5))
        window_sec = int(request.form.get('window_sec', 5))
    except ValueError:
        flash('Seuil et fenêtre doivent être des entiers.', 'danger')
        return redirect(url_for('ids_policy', type='detect'))

    pattern_name = request.form.get('pattern_name', '').strip().upper()
    if not pattern_name:
        flash('Le nom du pattern est requis.', 'danger')
        return redirect(url_for('ids_policy', type='detect'))

    db.session.add(AccessPolicy(
        user_id      = any_user.id,
        resource_id  = int(request.form['resource_id']),
        task         = request.form['task'],
        policy_type  = 'detect',
        start_date   = datetime(2026, 1, 1),
        end_date     = datetime(2099, 12, 31),
        active       = True,
        threshold    = threshold,
        window_sec   = window_sec,
        severity     = request.form.get('severity', 'high'),
        pattern_name = pattern_name,
    ))
    db.session.commit()
    flash(f"Pattern de détection '{pattern_name}' ajouté.", 'success')
    return redirect(url_for('ids_policy', type='detect'))

@app.route('/ids/policy/delete/<int:policy_id>')
@editor_required
def ids_delete_policy(policy_id):
    db.session.delete(AccessPolicy.query.get_or_404(policy_id))
    db.session.commit()
    flash('Règle supprimée.', 'info')
    return redirect(url_for('ids_policy'))

@app.route('/ids/policy/import', methods=['POST'])
@editor_required
def ids_import_policy():
    """Importe policy.conf → DB."""
    from modules import module3_policy as m3
    replace = request.form.get('replace', '1') == '1'
    result  = m3.import_from_file(app, replace=replace)
    if result['errors']:
        flash(f"Import: {result['created']} règles, erreurs: {'; '.join(result['errors'][:3])}", 'danger')
    else:
        flash(f"Import réussi: {result['created']} règles chargées.", 'success')
    return redirect(url_for('ids_policy'))

@app.route('/ids/policy/export')
@editor_required
def ids_export_policy():
    """Exporte DB → policy.conf."""
    from modules import module3_policy as m3
    n = m3.export_to_file(app)
    flash(f"{n} règles exportées vers {m3.POLICY_FILE}", 'success')
    return redirect(url_for('ids_policy'))

@app.route('/ids/policy/download')
def ids_download_policy():
    """Télécharge policy.conf."""
    from modules import module3_policy as m3
    m3.export_to_file(app)
    with open(m3.POLICY_FILE, encoding='utf-8') as f:
        content = f.read()
    return Response(content, mimetype='text/plain',
                    headers={'Content-Disposition': 'attachment; filename=policy.conf'})

@app.route('/ids/policy/upload', methods=['POST'])
@editor_required
def ids_upload_policy():
    """Upload un fichier policy.conf depuis le navigateur."""
    from modules import module3_policy as m3
    if 'file' not in request.files:
        flash('Aucun fichier.', 'danger')
        return redirect(url_for('ids_policy'))
    f = request.files['file']
    tmp = m3.POLICY_FILE + '.tmp'
    f.save(tmp)
    errors = m3.validate_file(tmp)
    if errors:
        os.remove(tmp)
        flash(f'Fichier invalide: {errors[0]}', 'danger')
        return redirect(url_for('ids_policy'))
    os.replace(tmp, m3.POLICY_FILE)
    result = m3.import_from_file(app, replace=True)
    flash(f"{result['created']} règles importées depuis le fichier uploadé.", 'success')
    return redirect(url_for('ids_policy'))


# ══════════════════════════════════════════════════════════════════
# UTILISATEURS / RESSOURCES
# ══════════════════════════════════════════════════════════════════

@app.route('/ids/users')
def ids_users():
    return render_template('ids_users.html', users=IDSUser.query.all())

@app.route('/ids/users/add', methods=['POST'])
@editor_required
def ids_add_user():
    username = request.form['username'].strip()
    if IDSUser.query.filter_by(username=username).first():
        flash(f"L'utilisateur '{username}' existe déjà.", 'warning')
        return redirect(url_for('ids_users'))
    db.session.add(IDSUser(username=username, role=request.form.get('role', 'user')))
    db.session.commit()
    flash(f"Utilisateur '{username}' ajouté.", 'success')
    return redirect(url_for('ids_users'))

@app.route('/ids/users/delete/<int:user_id>')
@editor_required
def ids_delete_user(user_id):
    user = IDSUser.query.get_or_404(user_id)
    AccessPolicy.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('Utilisateur supprimé.', 'info')
    return redirect(url_for('ids_users'))

@app.route('/ids/resources')
def ids_resources():
    return render_template('ids_resources.html', resources=Resource.query.all())

@app.route('/ids/resources/add', methods=['POST'])
@editor_required
def ids_add_resource():
    name = request.form['name'].strip()
    if Resource.query.filter_by(name=name).first():
        flash(f"La ressource '{name}' existe déjà.", 'warning')
        return redirect(url_for('ids_resources'))
    db.session.add(Resource(name=name, description=request.form.get('description')))
    db.session.commit()
    flash('Ressource ajoutée.', 'success')
    return redirect(url_for('ids_resources'))

@app.route('/ids/resources/delete/<int:resource_id>')
@editor_required
def ids_delete_resource(resource_id):
    res = Resource.query.get_or_404(resource_id)
    AccessPolicy.query.filter_by(resource_id=res.id).delete()
    db.session.delete(res)
    db.session.commit()
    flash('Ressource supprimée.', 'info')
    return redirect(url_for('ids_resources'))


# ══════════════════════════════════════════════════════════════════
# MODULE 2 — Analyse batch manuelle
# ══════════════════════════════════════════════════════════════════

@app.route('/ids')
def ids_dashboard():
    from modules import module1_collector as m1
    from modules import module2_analyzer  as m2
    from modules import module3_policy    as m3
    from modules import module4_alerter   as m4
    stats = {
        'users':      IDSUser.query.count(),
        'resources':  Resource.query.count(),
        'policies':   AccessPolicy.query.filter_by(active=True).count(),
        'files':      EventFile.query.count(),
        'entries':    EventEntry.query.count(),
        'intrusions': Intrusion.query.count(),
    }
    return render_template('ids_dashboard.html',
        stats=stats, m1=m1.status, m2=m2.status,
        m3=m3.status, m4=m4.status)

@app.route('/ids/run', methods=['POST'])
@editor_required
def ids_run():
    from modules import module3_policy as m3
    from modules.module2_analyzer import _check_event

    try:
        N = max(1, int(request.form.get('N', 100)))
        P = max(1, int(request.form.get('P', 5)))
        M = max(1, int(request.form.get('M', 1000)))
        K = max(1, int(request.form.get('K', 100)))
    except ValueError:
        flash('Paramètres invalides.', 'danger')
        return redirect(url_for('ids_dashboard'))

    policies = m3._load_policy_direct(app)[:K]
    if not policies:
        flash('Aucune politique active. Importez policy.conf ou ajoutez des règles.', 'warning')
        return redirect(url_for('ids_policy'))

    files = EventFile.query.order_by(EventFile.file_number.desc()).limit(P).all()
    if not files:
        flash("Aucun fichier d'événements. Créez des fichiers d'abord.", 'warning')
        return redirect(url_for('ids_files'))

    intrusions_found = 0
    entries_checked  = 0
    table_size       = Intrusion.query.count()

    for f in files:
        entries = EventEntry.query.filter_by(file_id=f.id).limit(N).all()
        for entry in entries:
            entries_checked += 1
            if table_size >= M:
                db.session.commit()
                flash(f'Limite M={M} atteinte — {intrusions_found} nouvelle(s) intrusion(s) sur {entries_checked} entrées.', 'warning')
                return redirect(url_for('ids_intrusions'))

            prev = Intrusion.query.filter_by(entry_id=entry.id).first()
            if prev:
                db.session.delete(prev)
                db.session.flush()

            event_dict = {
                'username':       entry.username,
                'resource':       entry.resource_name,
                'task':           entry.task,
                'execution_date': entry.execution_date.isoformat(),
                'source':         f'batch/{f.name}',
                'raw':            f'Analyse batch: {f.name}',
            }
            violation = _check_event(event_dict, policies)
            if violation:
                intr = Intrusion(entry_id=entry.id, violation_type=violation['message'])
                db.session.add(intr)
                db.session.flush()
                db.session.add(Alert(
                    message=(f"[IDS] {entry.username} | {entry.task} sur "
                             f"{entry.resource_name} | {violation['message']}"),
                    severity=violation['severity'],
                ))
                intrusions_found += 1
                table_size += 1
        f.analyzed = True

    db.session.commit()
    msg = (f'Analyse terminée : {intrusions_found} intrusion(s) détectée(s) '
           f'sur {entries_checked} entrées ({len(files)} fichier(s))')
    flash(msg, 'danger' if intrusions_found > 0 else 'success')
    return redirect(url_for('ids_intrusions'))

@app.route('/ids/files')
def ids_files():
    return render_template('ids_files.html',
        files=EventFile.query.order_by(EventFile.file_number).all())

@app.route('/ids/files/create', methods=['POST'])
@editor_required
def ids_create_file():
    next_num = (EventFile.query.count() or 0) + 1
    db.session.add(EventFile(file_number=next_num,
        name=request.form.get('name') or f'Fichier_{next_num:03d}'))
    db.session.commit()
    flash(f'Fichier #{next_num} créé.', 'success')
    return redirect(url_for('ids_files'))

@app.route('/ids/files/delete/<int:file_id>')
@editor_required
def ids_delete_file(file_id):
    EventEntry.query.filter_by(file_id=file_id).delete()
    db.session.delete(EventFile.query.get_or_404(file_id))
    db.session.commit()
    flash('Fichier supprimé.', 'info')
    return redirect(url_for('ids_files'))

@app.route('/ids/files/<int:file_id>')
def ids_file_detail(file_id):
    f = EventFile.query.get_or_404(file_id)
    return render_template('ids_file_detail.html',
        file=f,
        entries=EventEntry.query.filter_by(file_id=file_id).all(),
        users=IDSUser.query.all(),
        resources=Resource.query.all())

@app.route('/ids/files/<int:file_id>/add_entry', methods=['POST'])
@editor_required
def ids_add_entry(file_id):
    from modules.module2_analyzer import _check_event, _record_intrusion
    from modules import module3_policy as m3

    entry = EventEntry(
        file_id=file_id,
        username=request.form['username'],
        resource_name=request.form['resource_name'],
        task=request.form['task'],
        execution_date=datetime.strptime(request.form['execution_date'], '%Y-%m-%dT%H:%M'),
    )
    db.session.add(entry)
    db.session.flush()

    # Analyser immédiatement
    policies = m3._load_policy_direct(app)  # Charge depuis DB
    event_dict = {
        'username':       entry.username,
        'resource':       entry.resource_name,
        'task':           entry.task,
        'execution_date': entry.execution_date.isoformat(),
        'source':         'manual',
        'raw':            'Saisie manuelle',
    }
    violation = _check_event(event_dict, policies)
    if violation:
        intrusion = Intrusion(entry_id=entry.id, violation_type=violation['message'])
        db.session.add(intrusion)
        db.session.flush()
        db.session.add(Alert(
            message=f"[IDS] {entry.username} | {entry.task} sur {entry.resource_name} | {violation['message']}",
            severity=violation['severity']
        ))
    db.session.commit()
    flash('Entrée ajoutée et analysée.', 'success')
    return redirect(url_for('ids_file_detail', file_id=file_id))



# ══════════════════════════════════════════════════════════════════
# NIDS — Configuration
# ══════════════════════════════════════════════════════════════════

@app.route('/ids/nids')
def ids_nids():
    from modules import module1_collector as m1
    from scapy.all import get_if_list

    ifaces = get_if_list()
    all_ifaces = [{'name': i, 'active': i not in ('lo', 'lo0')} for i in ifaces]
    available = [i for i in ifaces if i not in ('lo', 'lo0')]
    selected = m1.sniffer_status.get('interface', 'any')

    # Compter les règles NIDS
    with open(os.path.join(BASE_DIR, 'nids_rules.conf')) as f:
        rules_count = len([l for l in f if l.strip() and not l.startswith('#')])

    return render_template('ids_nids_settings.html',
        available_interfaces=available,
        selected_interface=selected,
        all_interfaces=all_ifaces,
        status=m1.sniffer_status,
        nids_rules_count=rules_count)

@app.route('/ids/nids/set_interface', methods=['POST'])
@editor_required
def ids_nids_set_interface():
    interface = request.form.get('interface', 'any')
    from modules import module1_collector as m1
    m1.sniffer_status['interface'] = interface
    flash(f"Interface NIDS changée : {interface}", 'success')
    return redirect(url_for('ids_nids'))

# ══════════════════════════════════════════════════════════════════
# INTRUSIONS
# ══════════════════════════════════════════════════════════════════

def _intrusions_query(args):
    """Construit la query Intrusion avec filtres."""
    q = Intrusion.query.join(EventEntry, Intrusion.entry_id == EventEntry.id)

    # Recherche utilisateur/ressource/type
    search = args.get('q', '').strip()
    if search:
        like = f'%{search}%'
        q = q.filter((EventEntry.username.ilike(like)) |
                     (EventEntry.resource_name.ilike(like)) |
                     (Intrusion.violation_type.ilike(like)))

    # Filtre date
    days = args.get('days')
    if days:
        try:
            cutoff = datetime.utcnow() - timedelta(days=int(days))
            q = q.filter(Intrusion.detected_at >= cutoff)
        except ValueError:
            pass

    return q.order_by(Intrusion.detected_at.desc())


@app.route('/ids/intrusions')
def ids_intrusions():
    page = max(1, int(request.args.get('page', 1) or 1))
    per_page = min(200, int(request.args.get('per_page', 50) or 50))

    q = _intrusions_query(request.args)
    total = q.count()
    items = q.limit(per_page).offset((page - 1) * per_page).all()
    pages = (total + per_page - 1) // per_page

    return render_template('ids_intrusions.html',
        intrusions=items,
        page=page, per_page=per_page, pages=pages, total=total,
        filter_q=request.args.get('q', ''),
        filter_days=request.args.get('days', ''))


@app.route('/ids/intrusions/export.csv')
def ids_intrusions_export_csv():
    """Export CSV des intrusions filtrées."""
    import csv, io
    q = _intrusions_query(request.args)
    rows = q.limit(10000).all()

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(['id', 'username', 'resource', 'task',
                     'execution_date', 'violation_type', 'detected_at'])
    for i in rows:
        e = i.entry
        writer.writerow([
            i.id, e.username, e.resource_name, e.task,
            e.execution_date.strftime('%Y-%m-%d %H:%M:%S') if e.execution_date else '',
            (i.violation_type or '').replace('\n', ' '),
            i.detected_at.strftime('%Y-%m-%d %H:%M:%S') if i.detected_at else '',
        ])

    return Response(output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition':
            f'attachment; filename=intrusions_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'})

@app.route('/ids/intrusions/partial')
def ids_intrusions_partial():
    intrusions = Intrusion.query.order_by(Intrusion.detected_at.desc()).limit(10).all()
    rows = ''
    for i in intrusions:
        vtype = i.violation_type or ''
        badge = 'red' if ('non authentifié' in vtype or 'non autorisée' in vtype) else 'amber'
        rows += (
            f'<tr><td><strong>{i.entry.username}</strong></td>'
            f'<td><code>{i.entry.resource_name}</code></td>'
            f'<td><span class="badge badge-gray">{i.entry.task}</span></td>'
            f'<td><span class="badge badge-{badge}">{vtype[:60]}</span></td>'
            f'<td style="color:var(--text-3);font-size:12px">'
            f'{i.detected_at.strftime("%d/%m %H:%M:%S")}</td></tr>'
        )
    return rows or '<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-3)">Aucune intrusion</td></tr>'

@app.route('/ids/intrusions/reset')
@editor_required
def ids_reset_intrusions():
    Intrusion.query.delete()
    Alert.query.filter(Alert.message.like('[IDS]%')).delete()
    for f in EventFile.query.all():
        f.analyzed = False
    db.session.commit()
    flash("Table d'intrusions réinitialisée.", 'info')
    return redirect(url_for('ids_intrusions'))


# ══════════════════════════════════════════════════════════════════
# MONITORING — SSE temps réel
# ══════════════════════════════════════════════════════════════════

@app.route('/ids/monitoring')
def ids_monitoring():
    from modules import module1_collector as m1
    from modules import module2_analyzer  as m2
    from modules import module3_policy    as m3
    from modules import module4_alerter   as m4
    recent = Intrusion.query.order_by(Intrusion.detected_at.desc()).limit(10).all()
    return render_template('ids_monitoring.html',
        m1=m1.status, m2=m2.status, m3=m3.status, m4=m4.status,
        sniffer=m1.sniffer_status,
        nids=m1.nids_status,
        logwatcher=m1.logwatcher_status,
        auditd=m1.auditd_status,
        recent_intrusions=recent,
        events_dir=EVENTS_DIR, alerts_dir=ALERTS_DIR)

@app.route('/stream/stats')
def stream_stats():
    def generate():
        from modules import module1_collector as m1
        from modules import module2_analyzer  as m2
        from modules import module4_alerter   as m4
        while True:
            try:
                db.session.expire_all()
                data = {
                    'intrusions':       Intrusion.query.count(),
                    'alerts':           Alert.query.count(),
                    'critical':         Alert.query.filter_by(severity='critical').count(),
                    'high':             Alert.query.filter_by(severity='high').count(),
                    'files':            EventFile.query.count(),
                    'entries':          EventEntry.query.count(),
                    'm1_sources':       m1.status['sources'],
                    'm1_events_today':  m1.status['events_today'],
                    'm2_analyzed':      m2.status['analyzed'],
                    'm2_intrusions':    m2.status['intrusions'],
                    'm2_last_check':    m2.status['last_check'],
                    'm4_alerts_sent':   m4.status['alerts_sent'],
                    'm4_queue':         m4.status['queue_size'],
                    'sniffer_packets':  m1.sniffer_status['packets_captured'],
                    'log_lines':        m1.logwatcher_status['lines_processed'],
                    'log_entries':      m1.logwatcher_status['entries_created'],
                    'ts':               datetime.utcnow().strftime('%H:%M:%S'),
                }
                yield f'data: {json.dumps(data)}\n\n'
            except Exception as e:
                yield f'data: {json.dumps({"error": str(e)})}\n\n'
            time_module.sleep(3)

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ══════════════════════════════════════════════════════════════════
# PARAMÈTRES — Configuration SMTP et intégrité
# ══════════════════════════════════════════════════════════════════

@app.route('/ids/settings', methods=['GET', 'POST'])
def ids_settings():
    import json as _json
    config_file = os.path.join(BASE_DIR, 'ids_config.json')
    integrity_file = os.path.join(BASE_DIR, 'ids_integrity.conf')

    cfg = {'smtp': {'host': '', 'port': 587, 'user': '', 'password': '',
                    'from': '', 'to': '', 'tls': True}}
    if os.path.exists(config_file):
        try:
            with open(config_file) as f:
                cfg = _json.load(f)
        except Exception:
            pass

    integrity_paths = ''
    if os.path.exists(integrity_file):
        with open(integrity_file, encoding='utf-8') as f:
            integrity_paths = f.read()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'smtp':
            cfg['smtp'] = {
                'host':     request.form.get('smtp_host', ''),
                'port':     int(request.form.get('smtp_port', 587)),
                'user':     request.form.get('smtp_user', ''),
                'password': request.form.get('smtp_password', ''),
                'from':     request.form.get('smtp_from', ''),
                'to':       request.form.get('smtp_to', ''),
                'tls':      request.form.get('smtp_tls') == 'on',
            }
            with open(config_file, 'w') as f:
                _json.dump(cfg, f, indent=2)
            log_action('config_update', target='smtp')
            flash('Configuration SMTP sauvegardée.', 'success')

        elif action == 'webhooks':
            cfg['slack_webhook']   = request.form.get('slack_webhook', '').strip()
            cfg['discord_webhook'] = request.form.get('discord_webhook', '').strip()
            cfg['teams_webhook']   = request.form.get('teams_webhook', '').strip()
            cfg['min_severity']    = request.form.get('min_severity', 'low')
            cfg['syslog'] = {
                'host': request.form.get('syslog_host', '').strip(),
                'port': int(request.form.get('syslog_port', 514) or 514),
            }
            with open(config_file, 'w') as f:
                _json.dump(cfg, f, indent=2)
            log_action('config_update', target='webhooks')
            flash('Configuration webhooks sauvegardée (rechargée automatiquement).', 'success')

        elif action == 'integrity':
            paths = request.form.get('integrity_paths', '')
            with open(integrity_file, 'w', encoding='utf-8') as f:
                f.write('# Fichiers surveillés — un chemin par ligne\n')
                f.write(paths.strip() + '\n')
            log_action('config_update', target='integrity')
            flash('Fichiers surveillés sauvegardés. Redémarrez le collecteur pour appliquer.', 'success')

        return redirect(url_for('ids_settings'))

    smtp = cfg.get('smtp', {})
    return render_template('ids_settings.html',
        smtp=smtp,
        webhooks=cfg,
        integrity_paths=integrity_paths,
        config_file=config_file,
        integrity_file=integrity_file)


# ══════════════════════════════════════════════════════════════════
# INITIALISATION
# ══════════════════════════════════════════════════════════════════

def _seed():
    if IDSUser.query.count() == 0:
        for username, role in [('alice','admin'),('bob','analyst'),
                               ('charlie','user'),('diana','user')]:
            db.session.add(IDSUser(username=username, role=role))
        db.session.commit()

    if Resource.query.count() == 0:
        for name, desc in [
            ('database',      'Base de données principale'),
            ('web_server',    'Serveur web'),
            ('file_storage',  'Stockage de fichiers'),
            ('email_server',  'Serveur de messagerie'),
            ('ssh_server',    'Accès SSH'),
            ('system',        'Système d\'exploitation'),
            ('user_management','Gestion utilisateurs'),
            ('firewall',      'Pare-feu'),
        ]:
            db.session.add(Resource(name=name, description=desc))
        db.session.commit()

    if AccessPolicy.query.count() == 0:
        alice   = IDSUser.query.filter_by(username='alice').first()
        bob     = IDSUser.query.filter_by(username='bob').first()
        charlie = IDSUser.query.filter_by(username='charlie').first()
        db_res  = Resource.query.filter_by(name='database').first()
        web     = Resource.query.filter_by(name='web_server').first()
        storage = Resource.query.filter_by(name='file_storage').first()
        ssh     = Resource.query.filter_by(name='ssh_server').first()
        system  = Resource.query.filter_by(name='system').first()
        y0, y1  = datetime(2026,1,1), datetime(2026,12,31)
        for u, r, t, s, e in [
            (alice,   db_res,  'read',   y0, y1),
            (alice,   db_res,  'write',  y0, y1),
            (alice,   db_res,  'admin',  y0, y1),
            (alice,   ssh,     'login',  y0, y1),
            (alice,   system,  'execute',y0, y1),
            (bob,     db_res,  'read',   y0, datetime(2026,6,30)),
            (bob,     web,     'read',   y0, y1),
            (bob,     web,     'write',  y0, y1),
            (bob,     ssh,     'login',  y0, y1),
            (charlie, storage, 'read',   y0, y1),
            (charlie, storage, 'write',  datetime(2026,3,1), datetime(2026,9,30)),
            (charlie, ssh,     'login',  y0, y1),
        ]:
            db.session.add(AccessPolicy(user_id=u.id, resource_id=r.id,
                                        task=t, start_date=s, end_date=e))
        db.session.commit()

    # ── Patterns 'detect' : seed initial si aucun n'existe ─────────────────
    if AccessPolicy.query.filter_by(policy_type='detect').count() == 0:
        # Pour les patterns, on a besoin d'un user 'virtuel' qui représente
        # "tout utilisateur" (wildcard). On crée *_ANY si absent.
        any_user = IDSUser.query.filter_by(username='*').first()
        if not any_user:
            any_user = IDSUser(username='*', role='system')
            db.session.add(any_user)
            db.session.commit()

        y0, y1 = datetime(2026,1,1), datetime(2099,12,31)
        ssh  = Resource.query.filter_by(name='ssh_server').first()
        web  = Resource.query.filter_by(name='web_server').first()
        db_r = Resource.query.filter_by(name='database').first()
        sysr = Resource.query.filter_by(name='system').first()
        fs   = Resource.query.filter_by(name='file_storage').first()

        # (resource, task, threshold, window_sec, severity, pattern_name)
        patterns_seed = [
            (ssh,  'failed_login', 5, 5,   'critical', 'BRUTE_FORCE_SSH'),
            (web,  'failed_login', 5, 30,  'high',     'BRUTE_FORCE_WEB'),
            (db_r, 'failed_login', 3, 10,  'critical', 'BRUTE_FORCE_DB'),
            (sysr, 'execute',      20,60,  'high',     'EXEC_FLOOD'),
            (sysr, 'execute',      5, 10,  'critical', 'PRIVESC_ATTEMPT'),
            (fs,   'read',         50,30,  'high',     'FILE_READ_FLOOD'),
            (fs,   'delete',       10,30,  'critical', 'FILE_DELETE_FLOOD'),
        ]
        for res, task, thr, win, sev, name in patterns_seed:
            if not res:
                continue
            db.session.add(AccessPolicy(
                user_id=any_user.id, resource_id=res.id,
                task=task, policy_type='detect',
                start_date=y0, end_date=y1, active=True,
                threshold=thr, window_sec=win,
                severity=sev, pattern_name=name,
            ))
        db.session.commit()


# Ajouter la méthode helper au module3_policy pour éviter l'import circulaire
def _load_policy_direct_helper(flask_app):
    """Charge la politique directement depuis la DB (helper pour module3_policy)."""
    with flask_app.app_context():
        from models import AccessPolicy
        policies = AccessPolicy.query.filter_by(active=True).all()
        return [
            {'username':   p.user.username, 'resource': p.resource.name,
             'task': p.task, 'policy_type': p.policy_type,
             'start_date': p.start_date, 'end_date': p.end_date}
            for p in policies
        ]


def _migrate_schema():
    """Ajoute les nouvelles colonnes aux tables existantes (SQLite ALTER TABLE).
    Évite les erreurs si la DB date d'une version antérieure du modèle."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    # web_user : totp_secret, totp_enabled
    if inspector.has_table('web_user'):
        cols = {c['name'] for c in inspector.get_columns('web_user')}
        with db.engine.begin() as conn:
            if 'totp_secret' not in cols:
                conn.execute(text('ALTER TABLE web_user ADD COLUMN totp_secret VARCHAR(64)'))
            if 'totp_enabled' not in cols:
                conn.execute(text('ALTER TABLE web_user ADD COLUMN totp_enabled BOOLEAN DEFAULT 0'))

    # access_policy : threshold, window_sec, severity, pattern_name (pour policy_type='detect')
    if inspector.has_table('access_policy'):
        cols = {c['name'] for c in inspector.get_columns('access_policy')}
        with db.engine.begin() as conn:
            if 'threshold' not in cols:
                conn.execute(text('ALTER TABLE access_policy ADD COLUMN threshold INTEGER'))
            if 'window_sec' not in cols:
                conn.execute(text('ALTER TABLE access_policy ADD COLUMN window_sec INTEGER'))
            if 'severity' not in cols:
                conn.execute(text('ALTER TABLE access_policy ADD COLUMN severity VARCHAR(20)'))
            if 'pattern_name' not in cols:
                conn.execute(text('ALTER TABLE access_policy ADD COLUMN pattern_name VARCHAR(80)'))


with app.app_context():
    db.create_all()
    _migrate_schema()
    _seed()
    # Compte admin par défaut (admin/admin si IDS_ADMIN_PASSWORD non défini)
    ensure_default_admin(app)
    # Export policy.conf si absent
    from modules import module3_policy as _m3
    if not os.path.exists(_m3.POLICY_FILE):
        _m3.export_to_file(app)
    # Injecter le helper dans module3 (important pour /ids/run et autres routes)
    _m3._load_policy_direct = _load_policy_direct_helper

if __name__ == '__main__':
    # Démarrer les 4 modules
    _start_modules()
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
