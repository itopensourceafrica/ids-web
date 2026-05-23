from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


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
