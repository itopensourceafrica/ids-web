"""Fonctions d'analyse : réseau (règles) et comportemental (politique d'accès)."""
import re
import sys
from models import db, SecurityRule, Alert, AccessPolicy, Intrusion


def analyze_network_event(event):
    """Compare un événement réseau aux règles de sécurité."""
    rules = SecurityRule.query.filter_by(active=True).all()
    for rule in rules:
        match = False
        cond = rule.condition.lower()
        if "port==" in cond:
            try:
                if event.port == int(cond.split("==")[1]):
                    match = True
            except Exception:
                pass
        elif "keyword=" in cond:
            keyword = cond.split("keyword=")[1]
            if keyword in (event.payload or "").lower():
                match = True
        elif re.search(rule.condition, event.payload or "", re.IGNORECASE):
            match = True

        if match:
            db.session.add(Alert(
                event_id=event.id,
                rule_id=rule.id,
                message=f"{rule.name} — {rule.description}",
                severity=rule.severity
            ))
    db.session.commit()


def analyze_access_entry(entry):
    """Compare une entrée comportementale à la politique d'accès (temps réel).
    Ne commit pas — le caller est responsable du commit.
    """
    policies = AccessPolicy.query.filter_by(active=True).all()

    authorized = False
    for policy in policies:
        if (policy.user.username == entry.username and
                policy.resource.name == entry.resource_name and
                policy.task == entry.task):
            if policy.start_date <= entry.execution_date <= policy.end_date:
                authorized = True
                break

    if authorized:
        return

    user_known = any(p.user.username == entry.username for p in policies)
    if not user_known:
        violation = "User not authenticated in security policy"
        severity = 'critical'
    else:
        task_match = any(
            p.user.username == entry.username and
            p.resource.name == entry.resource_name and
            p.task == entry.task
            for p in policies
        )
        if task_match:
            violation = "Execution date outside the allowed range"
            severity = 'high'
        else:
            violation = "Task or resource not allowed for this user"
            severity = 'critical'

    intrusion = Intrusion(entry_id=entry.id, violation_type=violation)
    db.session.add(intrusion)
    db.session.flush()

    db.session.add(Alert(
        message=f"[IDS] {entry.username} | {entry.task} on {entry.resource_name} | {violation}",
        severity=severity
    ))

    print(
        f"[IDS] INTRUSION DETECTED: {entry.username} | {entry.task} "
        f"on {entry.resource_name} | {violation}",
        file=sys.stderr
    )
