from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ── Utilisateurs de l'application web (admin/viewer/analyst) ──────────────
class WebUser(db.Model):
    """Utilisateur de l'interface web — distinct des IDSUser (utilisateurs surveillés)."""
    __tablename__ = 'web_user'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20), default='viewer')  # admin / analyst / viewer
    active        = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime)
    # 2FA TOTP (RFC 6238)
    totp_secret   = db.Column(db.String(64))    # base32, généré par pyotp
    totp_enabled  = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def can_edit(self):
        return self.role in ('admin', 'analyst')


# ── Brute force tracker (persistant) ──────────────────────────────────────
class LoginAttempt(db.Model):
    """Tentative de connexion (échec ou succès) — persisté pour survivre aux restarts."""
    __tablename__ = 'login_attempt'
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address  = db.Column(db.String(45), index=True)
    username    = db.Column(db.String(80))
    success     = db.Column(db.Boolean, default=False)
    user_agent  = db.Column(db.String(200))


# ── Log d'audit des actions admin ──────────────────────────────────────────
class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
    user_id     = db.Column(db.Integer, db.ForeignKey('web_user.id'))
    username    = db.Column(db.String(80))           # snapshot en cas de suppression
    action      = db.Column(db.String(100), nullable=False)
    target      = db.Column(db.String(200))          # objet concerné
    ip_address  = db.Column(db.String(45))
    user_agent  = db.Column(db.String(200))
    details     = db.Column(db.Text)

    user = db.relationship('WebUser', backref='audit_logs')


# ── Alertes produites par le Module 4 ──────────────────────────────────────
class Alert(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow)
    message      = db.Column(db.Text, nullable=False)
    severity     = db.Column(db.String(20))
    acknowledged = db.Column(db.Boolean, default=False)


# ── Configuration HIDS — utilisateurs, ressources, politique ───────────────
class Resource(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


class IDSUser(db.Model):
    __tablename__ = 'ids_user'
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(100), nullable=False, unique=True)
    role       = db.Column(db.String(50), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AccessPolicy(db.Model):
    __tablename__ = 'access_policy'
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('ids_user.id'),  nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'),  nullable=False)
    task        = db.Column(db.String(100), nullable=False)
    policy_type = db.Column(db.String(10), default='allow')  # 'allow' ou 'deny'
    start_date  = db.Column(db.DateTime, nullable=False)
    end_date    = db.Column(db.DateTime, nullable=False)
    active      = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    user     = db.relationship('IDSUser',  backref='policies')
    resource = db.relationship('Resource', backref='policies')


# ── Règles NIDS (réseau) — format avancé style firewall ────────────────────
class NidsRule(db.Model):
    __tablename__ = 'nids_rule'
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    version     = db.Column(db.String(10), default='ipv4')     # ipv4 / ipv6 / any
    protocol    = db.Column(db.String(10), default='tcp')      # tcp / udp / icmp / any
    src_ip      = db.Column(db.String(50), default='0.0.0.0/0')
    dst_ip      = db.Column(db.String(50), default='0.0.0.0/0')
    src_port    = db.Column(db.String(20), default='any')      # any / 80 / 1000-2000
    dst_port    = db.Column(db.String(20), default='any')
    tcp_flags   = db.Column(db.String(30), default='')         # syn|ack|fin (vide = any)
    action      = db.Column(db.String(10), default='alert')    # accept / deny / alert
    severity    = db.Column(db.String(20), default='medium')   # critical / high / medium / low
    active      = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


# ── Données d'analyse ──────────────────────────────────────────────────────
class EventFile(db.Model):
    __tablename__ = 'event_file'
    id          = db.Column(db.Integer, primary_key=True)
    file_number = db.Column(db.Integer, nullable=False)
    name        = db.Column(db.String(100))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    analyzed    = db.Column(db.Boolean, default=False)

    entries = db.relationship('EventEntry', backref='file', lazy=True)


class EventEntry(db.Model):
    __tablename__ = 'event_entry'
    id             = db.Column(db.Integer, primary_key=True)
    file_id        = db.Column(db.Integer, db.ForeignKey('event_file.id'), nullable=False)
    username       = db.Column(db.String(100), nullable=False)
    resource_name  = db.Column(db.String(100), nullable=False)
    task           = db.Column(db.String(100), nullable=False)
    execution_date = db.Column(db.DateTime, nullable=False)
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)


class Intrusion(db.Model):
    __tablename__ = 'intrusion'
    id             = db.Column(db.Integer, primary_key=True)
    entry_id       = db.Column(db.Integer, db.ForeignKey('event_entry.id'), nullable=False)
    violation_type = db.Column(db.String(200))
    detected_at    = db.Column(db.DateTime, default=datetime.utcnow)

    entry = db.relationship('EventEntry', backref='intrusion_record', uselist=False)
