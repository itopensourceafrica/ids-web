"""Enrichissement des alertes avec threat intelligence + géolocalisation.

Sources :
  - AbuseIPDB (https://www.abuseipdb.com/) — réputation IP via API key
  - ip-api.com (gratuit, sans clé) — géolocalisation

Toutes les requêtes externes ont :
  - Timeout court (3s) pour ne pas bloquer le pipeline d'alertes
  - Cache mémoire de 24h (évite de spam les APIs)
  - Échec silencieux : si l'API est down, on continue sans enrichissement
"""

import os
import json
import time
import urllib.request
import urllib.parse
import threading
from collections import OrderedDict


# ── Configuration via env vars ─────────────────────────────────────────────
ABUSEIPDB_API_KEY  = os.environ.get('IDS_ABUSEIPDB_KEY', '')
ABUSEIPDB_TIMEOUT  = int(os.environ.get('IDS_ABUSEIPDB_TIMEOUT', '3'))
GEOIP_ENABLED      = os.environ.get('IDS_GEOIP_ENABLED', '1') == '1'
GEOIP_TIMEOUT      = int(os.environ.get('IDS_GEOIP_TIMEOUT', '3'))

# Cache TTL = 24h
CACHE_TTL = 86400


class _TTLCache:
    """Cache LRU avec TTL — thread-safe."""
    def __init__(self, max_size=1000):
        self._data = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_size

    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            ts, value = entry
            if time.time() - ts > CACHE_TTL:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key, value):
        with self._lock:
            self._data[key] = (time.time(), value)
            if len(self._data) > self._max:
                self._data.popitem(last=False)


_abuse_cache = _TTLCache()
_geo_cache   = _TTLCache()


def _is_private_ip(ip):
    """Skip les IPs privées (pas la peine d'enrichir)."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True  # Si on ne sait pas, on skip


# ── AbuseIPDB ───────────────────────────────────────────────────────────────

def lookup_abuseipdb(ip: str) -> dict:
    """Retourne {abuse_score: 0-100, total_reports: N, country: 'XX'} ou {}.

    Échec silencieux si pas de clé ou API down.
    """
    if not ABUSEIPDB_API_KEY or _is_private_ip(ip):
        return {}

    cached = _abuse_cache.get(ip)
    if cached is not None:
        return cached

    try:
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90'
        req = urllib.request.Request(url, headers={
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json',
        })
        with urllib.request.urlopen(req, timeout=ABUSEIPDB_TIMEOUT) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        d = data.get('data', {})
        result = {
            'abuse_score':   d.get('abuseConfidenceScore', 0),
            'total_reports': d.get('totalReports', 0),
            'country':       d.get('countryCode', ''),
            'isp':           d.get('isp', ''),
            'usage_type':    d.get('usageType', ''),
        }
        _abuse_cache.set(ip, result)
        return result
    except Exception:
        # Cache le résultat vide aussi pour ne pas re-tenter
        _abuse_cache.set(ip, {})
        return {}


# ── GeoIP via ip-api.com (gratuit, no key) ─────────────────────────────────

def lookup_geoip(ip: str) -> dict:
    """Retourne {country, city, lat, lon, org} ou {}.

    Limite gratuite : 45 req/min. Cache 24h évite de hit la limite.
    """
    if not GEOIP_ENABLED or _is_private_ip(ip):
        return {}

    cached = _geo_cache.get(ip)
    if cached is not None:
        return cached

    try:
        url = f'http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,country,countryCode,city,lat,lon,org,isp'
        with urllib.request.urlopen(url, timeout=GEOIP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        if data.get('status') != 'success':
            _geo_cache.set(ip, {})
            return {}
        result = {
            'country':      data.get('country', ''),
            'country_code': data.get('countryCode', ''),
            'city':         data.get('city', ''),
            'lat':          data.get('lat', 0),
            'lon':          data.get('lon', 0),
            'org':          data.get('org', ''),
            'isp':          data.get('isp', ''),
        }
        _geo_cache.set(ip, result)
        return result
    except Exception:
        _geo_cache.set(ip, {})
        return {}


# ── Enrichissement combiné ──────────────────────────────────────────────────

def enrich_ip(ip: str) -> dict:
    """Lookup combiné AbuseIPDB + GeoIP."""
    if _is_private_ip(ip):
        return {}

    out = {}
    abuse = lookup_abuseipdb(ip)
    if abuse:
        out.update(abuse)
    geo = lookup_geoip(ip)
    if geo:
        out.update({
            'geo_country':      geo.get('country'),
            'geo_country_code': geo.get('country_code'),
            'geo_city':         geo.get('city'),
            'geo_org':          geo.get('org'),
            'geo_isp':          geo.get('isp'),
        })
    return out


def format_enrichment(enrichment: dict) -> str:
    """Format compact pour ajouter dans le message d'alerte."""
    if not enrichment:
        return ''

    parts = []
    score = enrichment.get('abuse_score')
    if score is not None:
        emoji = '🔴' if score >= 75 else '🟠' if score >= 25 else '🟡' if score > 0 else '🟢'
        parts.append(f'{emoji} AbuseIPDB:{score}/100')
        if enrichment.get('total_reports'):
            parts.append(f'({enrichment["total_reports"]} reports)')

    location = []
    if enrichment.get('geo_city'):
        location.append(enrichment['geo_city'])
    if enrichment.get('geo_country'):
        location.append(enrichment['geo_country'])
    elif enrichment.get('country'):
        location.append(enrichment['country'])
    if location:
        parts.append('📍 ' + ', '.join(location))

    if enrichment.get('geo_org'):
        parts.append(f'({enrichment["geo_org"]})')

    return ' | '.join(parts)
