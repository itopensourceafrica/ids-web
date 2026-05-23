"""
IDS Web Platform — Orchestrateur principal

Démarre les 4 modules démons au lancement puis expose l'interface web.
"""

import os
import sys
import json
import queue
import time as time_module
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, Response, stream_with_context)
from models import (db, Alert, Resource, IDSUser, AccessPolicy,
                    EventFile, EventEntry, Intrusion, NidsRule)
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY']                  = 'ids_super_secret_2026'
app.config['SQLALCHEMY_DATABASE_URI']     = 'sqlite:///ids.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

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

    m3.start(app)           # Politique d'abord (les autres en dépendent)
    time_module.sleep(1)    # Laisser la politique se charger
    m1.start(app)           # Collecteur d'événements
    m2.start(app, _alert_queue)  # Analyseur
    m4.start(app, _alert_queue)  # Générateur d'alertes

    print('[IDS] Les 4 modules sont démarrés.', file=sys.stderr)


# ══════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════

@app.route('/favicon.ico')
def favicon():
    return Response(status=204)


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


@app.route('/alerts')
def alerts():
    return render_template('alerts.html',
        alerts=Alert.query.order_by(Alert.timestamp.desc()).all())

@app.route('/ack_alert/<int:alert_id>')
def ack_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.acknowledged = True
    db.session.commit()
    return redirect(url_for('alerts'))

@app.route('/ack_all_alerts')
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
    rule_type = request.args.get('type', 'hids')  # hids ou nids
    return render_template('ids_policy.html',
        rule_type=rule_type,
        policies=AccessPolicy.query.all(),
        nids_rules=NidsRule.query.order_by(NidsRule.id).all(),
        users=IDSUser.query.all(),
        resources=Resource.query.all(),
        policy_status=m3.status,
        policy_file=m3.POLICY_FILE,
    )

# ── Règles NIDS ────────────────────────────────────────────────────────────
@app.route('/ids/policy/nids/add', methods=['POST'])
def ids_add_nids_rule():
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
    flash('Règle NIDS ajoutée.', 'success')
    return redirect(url_for('ids_policy', type='nids'))

@app.route('/ids/policy/nids/toggle/<int:rule_id>')
def ids_toggle_nids_rule(rule_id):
    r = NidsRule.query.get_or_404(rule_id)
    r.active = not r.active
    db.session.commit()
    return redirect(url_for('ids_policy', type='nids'))

@app.route('/ids/policy/nids/delete/<int:rule_id>')
def ids_delete_nids_rule(rule_id):
    db.session.delete(NidsRule.query.get_or_404(rule_id))
    db.session.commit()
    flash('Règle NIDS supprimée.', 'info')
    return redirect(url_for('ids_policy', type='nids'))

@app.route('/ids/policy/add', methods=['POST'])
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
def ids_toggle_policy(policy_id):
    p = AccessPolicy.query.get_or_404(policy_id)
    p.active = not p.active
    db.session.commit()
    return redirect(url_for('ids_policy'))

@app.route('/ids/policy/delete/<int:policy_id>')
def ids_delete_policy(policy_id):
    db.session.delete(AccessPolicy.query.get_or_404(policy_id))
    db.session.commit()
    flash('Règle supprimée.', 'info')
    return redirect(url_for('ids_policy'))

@app.route('/ids/policy/import', methods=['POST'])
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
def ids_create_file():
    next_num = (EventFile.query.count() or 0) + 1
    db.session.add(EventFile(file_number=next_num,
        name=request.form.get('name') or f'Fichier_{next_num:03d}'))
    db.session.commit()
    flash(f'Fichier #{next_num} créé.', 'success')
    return redirect(url_for('ids_files'))

@app.route('/ids/files/delete/<int:file_id>')
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
def ids_nids_set_interface():
    interface = request.form.get('interface', 'any')
    from modules import module1_collector as m1
    m1.sniffer_status['interface'] = interface
    flash(f"Interface NIDS changée : {interface}", 'success')
    return redirect(url_for('ids_nids'))

# ══════════════════════════════════════════════════════════════════
# INTRUSIONS
# ══════════════════════════════════════════════════════════════════

@app.route('/ids/intrusions')
def ids_intrusions():
    return render_template('ids_intrusions.html',
        intrusions=Intrusion.query.order_by(Intrusion.detected_at.desc()).all())

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
            smtp = {
                'host':     request.form.get('smtp_host', ''),
                'port':     int(request.form.get('smtp_port', 587)),
                'user':     request.form.get('smtp_user', ''),
                'password': request.form.get('smtp_password', ''),
                'from':     request.form.get('smtp_from', ''),
                'to':       request.form.get('smtp_to', ''),
                'tls':      request.form.get('smtp_tls') == 'on',
            }
            with open(config_file, 'w') as f:
                _json.dump({'smtp': smtp}, f, indent=2)
            # Reload SMTP config in Module 4
            from modules import module4_alerter as m4
            m4.status  # trigger import; reload config on next alert
            flash('Configuration SMTP sauvegardée.', 'success')

        elif action == 'integrity':
            paths = request.form.get('integrity_paths', '')
            with open(integrity_file, 'w', encoding='utf-8') as f:
                f.write('# Fichiers surveillés — un chemin par ligne\n')
                f.write(paths.strip() + '\n')
            flash('Fichiers surveillés sauvegardés. Redémarrez le collecteur pour appliquer.', 'success')

        return redirect(url_for('ids_settings'))

    smtp = cfg.get('smtp', {})
    return render_template('ids_settings.html',
        smtp=smtp,
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


with app.app_context():
    db.create_all()
    _seed()
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
