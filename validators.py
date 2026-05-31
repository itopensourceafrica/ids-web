"""Input validation for NIDS rules and other forms."""

import re
import ipaddress


# ── Regex patterns ─────────────────────────────────────────────────────────
RE_PORT_RANGE = re.compile(r'^(\d+)(?:-(\d+))?$')
RE_TCP_FLAGS  = re.compile(r'^[a-zA-Z|,\s]*$')
RE_NAME       = re.compile(r'^[\w\-\. ]{1,100}$')


def validate_ip_cidr(value: str, allow_any: bool = True) -> tuple[bool, str]:
    """Validates an IP or CIDR (IPv4/IPv6). Returns (valid, error_msg)."""
    value = (value or '').strip()
    if not value:
        return False, 'IP is empty'

    if allow_any and value.lower() in ('any', '*', '0.0.0.0/0', '::/0'):
        return True, ''

    try:
        ipaddress.ip_network(value, strict=False)
        return True, ''
    except ValueError as e:
        return False, f"Invalid IP/CIDR '{value}': {e}"


def validate_port_range(value: str, allow_any: bool = True) -> tuple[bool, str]:
    """Validates a single port or a range (e.g.: '80', '1000-2000', 'any')."""
    value = (value or '').strip()
    if not value:
        return False, 'Port is empty'

    if allow_any and value.lower() in ('any', '*', '0-65535'):
        return True, ''

    m = RE_PORT_RANGE.match(value)
    if not m:
        return False, f"Invalid port format '{value}' (expected: 80 or 1000-2000)"

    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo

    if not (0 <= lo <= 65535):
        return False, f'Port {lo} out of range 0-65535'
    if not (0 <= hi <= 65535):
        return False, f'Port {hi} out of range 0-65535'
    if lo > hi:
        return False, f'Start port ({lo}) > end ({hi})'

    return True, ''


def validate_tcp_flags(value: str) -> tuple[bool, str]:
    """Validates TCP flags string (e.g.: 'syn|ack|fin')."""
    value = (value or '').strip()
    if not value:
        return True, ''  # empty = any

    if not RE_TCP_FLAGS.match(value):
        return False, 'TCP flags: invalid characters'

    valid_flags = {'fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr'}
    for f in re.split(r'[|,\s]+', value):
        f = f.strip().lower()
        if f and f not in valid_flags:
            return False, f"Invalid TCP flag: '{f}' (valid: {', '.join(sorted(valid_flags))})"

    return True, ''


def validate_rule_name(value: str) -> tuple[bool, str]:
    """Validates a NIDS rule name."""
    value = (value or '').strip()
    if not value:
        return False, 'Name is required'
    if len(value) > 100:
        return False, 'Name too long (max 100)'
    if not RE_NAME.match(value):
        return False, "Invalid name (letters, digits, spaces, '-', '_', '.' only)"
    return True, ''


def validate_enum(value: str, allowed: set, field: str) -> tuple[bool, str]:
    """Validates that a value is in an allowed set."""
    if value not in allowed:
        return False, f'Invalid {field}. Values: {", ".join(sorted(allowed))}'
    return True, ''


def validate_nids_rule_form(form) -> tuple[bool, list]:
    """Validates all fields of a NIDS rule form.

    Returns (valid, errors).
    `form` is `request.form` (dict-like).
    """
    errors = []

    ok, msg = validate_rule_name(form.get('name'))
    if not ok: errors.append(msg)

    ok, msg = validate_enum(form.get('version', 'ipv4'),
                             {'ipv4', 'ipv6', 'any'}, 'version')
    if not ok: errors.append(msg)

    ok, msg = validate_enum(form.get('protocol', 'tcp'),
                             {'tcp', 'udp', 'icmp', 'any'}, 'protocol')
    if not ok: errors.append(msg)

    ok, msg = validate_ip_cidr(form.get('src_ip', '0.0.0.0/0'))
    if not ok: errors.append(f'Source IP: {msg}')

    ok, msg = validate_ip_cidr(form.get('dst_ip', '0.0.0.0/0'))
    if not ok: errors.append(f'Dest IP: {msg}')

    ok, msg = validate_port_range(form.get('src_port', 'any'))
    if not ok: errors.append(f'Source port: {msg}')

    ok, msg = validate_port_range(form.get('dst_port', 'any'))
    if not ok: errors.append(f'Dest port: {msg}')

    ok, msg = validate_tcp_flags(form.get('tcp_flags', ''))
    if not ok: errors.append(f'TCP flags: {msg}')

    ok, msg = validate_enum(form.get('action', 'alert'),
                             {'alert', 'deny', 'accept'}, 'action')
    if not ok: errors.append(msg)

    ok, msg = validate_enum(form.get('severity', 'medium'),
                             {'low', 'medium', 'high', 'critical'}, 'severity')
    if not ok: errors.append(msg)

    return (len(errors) == 0), errors
