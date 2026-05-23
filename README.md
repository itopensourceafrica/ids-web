# IDS Web — Système de Détection d'Intrusions

Plateforme de détection d'intrusions modulaire, développée en Python/Flask. Elle repose sur quatre modules indépendants qui fonctionnent en permanence comme des démons dès le lancement de l'application. Elle tourne sur Linux et Windows, en local comme en production.

---

## Sommaire

- [Architecture](#architecture)
- [Installation](#installation)
- [Démarrage](#démarrage)
- [Structure du projet](#structure-du-projet)
- [Les 4 modules](#les-4-modules)
- [Sources de données](#sources-de-données)
- [Logique de détection](#logique-de-détection)
- [Types de violations](#types-de-violations)
- [Format policy.conf](#format-policyconf)
- [Règles NIDS (nids_rules.conf)](#règles-nids-nids_rulesconf)
- [Format des fichiers d'événements](#format-des-fichiers-dévénements)
- [Format des alertes](#format-des-alertes)
- [Guide d'utilisation de l'interface web](#guide-dutilisation-de-linterface-web)
- [Tests réels](#tests-réels)
- [Configuration email](#configuration-email)
- [Déploiement production](#déploiement-production)
- [Améliorations prévues](#améliorations-prévues)

---

## Architecture

Le système est organisé en pipeline à quatre étages. Chaque module est un démon indépendant qui démarre automatiquement avec l'application.

```
  ┌─────────────────────────────┐     ┌─────────────────────────────┐
  │      MODULE 1               │     │      MODULE 3               │
  │      Collecteur             │     │      Politique de sécurité  │
  │                             │     │                             │
  │  • /var/log/auth.log        │     │  • CRUD individuel (web)    │
  │  • /var/log/audit/audit.log │     │  • Import/Export policy.conf│
  │  • Windows Event Log        │     │  • Hot reload automatique   │
  │  • Capture réseau (scapy)   │     │  • Format: user;res;task;   │
  │  • Intégrité fichiers       │     │           start;end;actif   │
  │  • Surveillance processus   │     │                             │
  └──────────────┬──────────────┘     └──────────────┬──────────────┘
                 │ events/YYYY-MM-DD.jsonl            │ politique active
                 └────────────────────┬───────────────┘
                                      ▼
                   ┌──────────────────────────────────┐
                   │          MODULE 2                 │
                   │          Analyseur                │
                   │                                   │
                   │  Surveille events/ en continu     │
                   │  Compare chaque événement aux     │
                   │  règles de la politique           │
                   │  Violation → Intrusion en DB      │
                   └──────────────────┬────────────────┘
                                      │ queue thread-safe
                                      ▼
                   ┌──────────────────────────────────┐
                   │          MODULE 4                 │
                   │          Générateur d'alertes     │
                   │                                   │
                   │  Format détaillé (qui, quoi,      │
                   │  pourquoi) → alerts/YYYY-MM-DD.log│
                   │  Sauvegarde en DB                 │
                   │  Envoi email SMTP (optionnel)     │
                   └──────────────────────────────────┘
```

---

## Installation

### Linux — Ubuntu / Debian

```bash
# 1. Récupérer le projet
cd /opt && git clone <repo> ids_web && cd ids_web

# 2. Installer Python 3.10+ et pip
sudo apt update && sudo apt install python3 python3-pip -y

# 3. Installer les dépendances Python
#    Sur Ubuntu 24.04+ ajouter --break-system-packages (PEP 668)
pip3 install flask flask-sqlalchemy scapy psutil python-dotenv gunicorn

# 4. Installer auditd (HIDS — surveillance système avancée)
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd && sudo systemctl start auditd

# 5. Installer scapy pour root également (capture réseau)
sudo pip3 install scapy --break-system-packages

# 6. Autoriser la lecture des logs (optionnel si on lance avec sudo)
sudo chmod o+r /var/log/auth.log

# 7. Lancer — IMPORTANT : utiliser sudo -E pour préserver les packages
#    Python installés dans ~/.local/ tout en obtenant les droits root
sudo -E python3 app.py
```

> **Pourquoi `sudo -E` ?** Sans le flag `-E`, sudo réinitialise l'environnement et root ne voit pas les packages installés dans `~/.local/lib/python3.X/site-packages/` de l'utilisateur. Résultat : `ModuleNotFoundError: No module named 'flask'`. Le flag `-E` préserve `$PATH` et `$PYTHONPATH`.

### Linux — RHEL / CentOS / Fedora

```bash
pip3 install flask flask-sqlalchemy scapy psutil python-dotenv gunicorn
sudo dnf install audit -y
sudo systemctl enable auditd && sudo systemctl start auditd
sudo chmod o+r /var/log/secure
sudo -E python3 app.py
```

### Windows

```powershell
# 1. Installer Python 3.10+ depuis https://python.org
# 2. Installer Npcap depuis https://npcap.com (nécessaire pour scapy)

# 3. Dans PowerShell en tant qu'Administrateur
pip install flask flask-sqlalchemy scapy psutil python-dotenv

# 4. Lancer en tant qu'Administrateur (Event Log + capture réseau)
python app.py
```

> **Note Windows** : pour un accès avancé au journal d'événements Windows, installer `pywin32` (`pip install pywin32`). Sans ce paquet, le collecteur utilise `wevtutil` via subprocess, ce qui fonctionne sur toutes les versions de Windows sans dépendance supplémentaire.

---

## Démarrage

Une fois lancé, l'interface web est accessible à :

```
http://localhost:5000
```

Les quatre modules démarrent automatiquement dans l'ordre suivant :

```
[MODULE 3] Politique chargée depuis policy.conf
[MODULE 1] Collecteur démarré (OS=Linux)
[MODULE 2] Analyseur démarré
[MODULE 4] Générateur d'alertes démarré
[IDS] Les 4 modules sont démarrés.
```

---

## Structure du projet

```
ids_web/
│
├── app.py                       # Orchestrateur principal et routes Flask
├── models.py                    # Modèles de données SQLAlchemy
├── policy.conf                  # Politique de sécurité (éditable à chaud)
├── nids_rules.conf              # Règles NIDS — ports, signatures, whitelist (éditable à chaud)
├── ids_config.json              # Configuration email SMTP (optionnel)
├── requirements.txt
├── README.md
│
├── modules/
│   ├── __init__.py
│   ├── module1_collector.py     # MODULE 1 — Collecteur d'événements
│   ├── module2_analyzer.py      # MODULE 2 — Analyseur et détecteur
│   ├── module3_policy.py        # MODULE 3 — Gestion de la politique
│   └── module4_alerter.py       # MODULE 4 — Générateur d'alertes
│
├── events/                      # Fichiers JSONL produits par Module 1
│   └── YYYY-MM-DD.jsonl         # Un fichier par jour
│
├── alerts/                      # Logs d'alertes produits par Module 4
│   └── YYYY-MM-DD.log           # Un fichier par jour
│
├── templates/                   # Templates HTML de l'interface web
└── instance/
    └── ids.db                   # Base de données SQLite
```

---

## Les 4 modules

### Module 1 — Collecteur d'événements

Observe en permanence plusieurs sources système et réseau. Pour chaque événement détecté, il produit une ligne JSON dans le fichier `events/YYYY-MM-DD.jsonl` du jour.

| Collecteur | Source | OS | Droits requis |
|---|---|---|---|
| `LinuxLogCollector` | `/var/log/auth.log`, `/var/log/secure`, `/var/log/audit/audit.log` | Linux | Lecture seule |
| `WindowsLogCollector` | Journal Security, System (via `wevtutil`) | Windows | Administrateur |
| `NetworkCapture` | Paquets IP (scapy) + moteur de règles NIDS configurables | Linux + Windows | root / Admin |
| `FileIntegrityMonitor` | Hash SHA-256 des fichiers critiques | Linux + Windows | Lecture seule |
| `ProcessMonitor` | Nouveaux processus suspects (psutil) | Linux + Windows | Utilisateur standard |

### Module 2 — Analyseur d'événements

Surveille le dossier `events/` toutes les 3 secondes. Pour chaque nouvelle ligne JSON, il compare les quatre champs de l'événement (`username`, `resource`, `task`, `execution_date`) aux règles actives de la politique. Si aucune règle n'autorise cet accès, une intrusion est enregistrée et transmise au Module 4.

Il effectue également deux analyses complémentaires de manière indépendante :

- **Détection brute force** : comptage des `failed_login` par utilisateur sur une fenêtre glissante de 60 secondes. Alerte déclenchée à 5 tentatives.
- **Détection scan de ports** : comptage des ports distincts contactés par une même IP sur 60 secondes. Alerte déclenchée à 15 ports différents.

### Module 3 — Gestion de la politique de sécurité

Gère les règles d'accès de deux façons complémentaires :

- **Interface web** : ajout, suppression, activation/désactivation de chaque règle individuellement.
- **Fichier `policy.conf`** : modification globale en éditant directement le fichier texte. Le module surveille ce fichier en permanence et recharge automatiquement la politique dès qu'une modification est détectée, sans redémarrer l'application.

### Module 4 — Générateur d'alertes

Reçoit les intrusions depuis le Module 2 via une file d'attente thread-safe. Pour chaque intrusion, il génère une alerte formatée qui explique précisément la violation, l'enregistre dans la base de données, l'écrit dans le fichier log du jour, et l'envoie par email si un serveur SMTP est configuré.

---

## Sources de données

Il est important de comprendre ce que chaque source observe réellement sur le système.

### `/var/log/auth.log` — Source principale sur Linux

C'est la source la plus fiable et la plus riche sur Linux. Elle enregistre :

- Les connexions SSH réussies et échouées
- Toutes les commandes `sudo` avec le nom de l'utilisateur et la commande exécutée
- Les changements d'utilisateur via `su`
- Les sessions PAM (login console, connexions locales)
- Les modifications de comptes (`useradd`, `usermod`, `passwd`)

**Ce qu'elle ne voit pas** : ce que l'utilisateur fait une fois connecté (accès fichiers, requêtes SQL, navigation web). Pour couvrir ces cas, il faut activer `auditd` (voir section [Améliorations prévues](#améliorations-prévues)).

### Capture réseau (scapy) — Nécessite root

Intercepte tous les paquets IP qui transitent par les interfaces réseau de la machine. Permet de détecter les connexions sur des ports suspects, les scans de ports, et les payloads réseau contenant des signatures d'attaque (injection SQL, etc.). Ne voit pas le contenu des communications chiffrées (HTTPS, SSH).

### Intégrité des fichiers (SHA-256)

Calcule le condensat SHA-256 des fichiers critiques (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`, `/etc/crontab`) toutes les 30 secondes et compare avec la valeur précédente. Toute modification génère un événement immédiatement.

### Surveillance des processus (psutil)

Détecte l'apparition de nouveaux processus dont le nom ou la ligne de commande correspond à une liste d'outils offensifs connus (97 outils répertoriés : nmap, hydra, netcat, mimikatz, sqlmap, xmrig, etc.).

---

## Logique de détection

La détection repose sur une comparaison directe entre les champs de chaque événement et les règles actives de la politique. Un accès est considéré comme une intrusion si **aucune règle** ne l'autorise explicitement. Le principe est le refus par défaut.

Pour chaque événement `(username, resource, task, execution_date)`, l'analyseur effectue trois vérifications en cascade :

```
Étape 1 — L'utilisateur est-il connu de la politique ?
  NON → intrusion : utilisateur inconnu (critique)

Étape 2 — Existe-t-il une règle pour (user, resource, task) ?
  NON → intrusion : accès non autorisé (critique)

Étape 3 — La date/heure est-elle dans la plage autorisée ?
  NON → intrusion : violation de date ou d'horaire (haute)

  OUI à tout → accès autorisé, aucune intrusion
```

---

## Types de violations

| Type | Code | Sévérité | Description |
|---|---|---|---|
| Utilisateur inconnu | `user_unknown` | Critique | L'utilisateur n'apparaît dans aucune règle de la politique |
| Accès non autorisé | `unauthorized_access` | Critique | La combinaison (utilisateur, ressource, tâche) n'est couverte par aucune règle |
| Date expirée | `date_violation` | Haute | L'accès a lieu en dehors de la plage de dates de la règle |
| Heure non autorisée | `time_violation` | Haute | L'accès a lieu en dehors de la plage horaire définie (`HH:MM`) |
| Brute force | `brute_force` | Critique | ≥ 5 tentatives de connexion échouées en 60 secondes |
| Scan de ports | `user_unknown` | Critique | ≥ 15 ports distincts contactés depuis la même IP en 60 secondes |
| Processus suspect | `unauthorized_access` | Critique | Outil offensif détecté par le moniteur de processus |
| Fichier modifié | `unauthorized_access` | Haute | Hash SHA-256 d'un fichier critique a changé |

---

## Format policy.conf

Le fichier `policy.conf` définit l'ensemble des accès autorisés sur le système. Chaque ligne représente une règle, avec les champs séparés par un point-virgule.

```
# Syntaxe
username ; resource ; task ; start_date ; end_date ; active

# Dates — deux formats supportés
# YYYY-MM-DD          : autorisation valable toute la journée
# YYYY-MM-DD HH:MM    : restriction à une plage horaire précise
```

**Exemples concrets :**

```ini
# Alice (admin) — accès complet à la base de données toute l'année
alice;database;read;2026-01-01;2026-12-31;1
alice;database;write;2026-01-01;2026-12-31;1
alice;database;admin;2026-01-01;2026-12-31;1

# Bob (analyste) — accès DB limité au premier semestre
bob;database;read;2026-01-01;2026-06-30;1

# Charlie — écriture sur le stockage uniquement entre 08h et 18h
charlie;file_storage;write;2026-01-01 08:00;2026-12-31 18:00;1

# Règle désactivée (sans suppression)
diana;web_server;read;2026-01-01;2026-12-31;0
```

**Tâches reconnues :** `read`, `write`, `delete`, `execute`, `admin`, `login`, `failed_login`, `backup`, `restore`, `connect`, `port_scan`

**Ressources détectées automatiquement à partir des logs :**

| Ressource | Déclencheur |
|---|---|
| `ssh_server` | Connexions SSH (`sshd`) |
| `database` | Commandes `mysql`, `psql`, `sqlite3` via sudo |
| `web_server` | Processus `nginx`, `apache2`, `httpd` |
| `email_server` | Commandes `sendmail`, `postfix`, `dovecot` |
| `system` | Sessions PAM, commandes `su` |
| `file_storage` | Accès à `/etc/passwd`, `/etc/shadow`, etc. |
| `user_management` | Commandes `useradd`, `usermod`, `passwd` |
| `network_scanner` | Scan de ports détecté par le Module 1 |

---

## Règles NIDS (nids_rules.conf)

Le fichier `nids_rules.conf` configure le moteur de détection réseau. Il est créé automatiquement au premier démarrage avec des règles par défaut et **rechargé à chaud** dès qu'il est modifié (toutes les 500 paquets analysés).

Le NIDS combine quatre mécanismes :

- **Règles par port** — alerte sur connexion à des ports dangereux (SSH, RDP, ports C2, bases de données exposées)
- **Signatures payload** — détection de motifs suspects dans le contenu des paquets (injections SQL, XSS, path traversal, commandes shell)
- **Suivi de session TCP** — chaque connexion `(src, dst, dport)` est tracée, fermée sur FIN/RST, nettoyée après 30 min
- **Extraction SNI TLS** — le nom de domaine de destination est lu en clair depuis le `ClientHello` (même pour TLS 1.3), sans déchiffrement, ce qui permet de détecter les connexions vers des domaines suspects (`.onion`, `ngrok`, `pastebin`...)

### Format

```
# Règle d'alerte
alert ; proto ; port ; payload_pattern ; severity ; description ; resource

# Whitelist (jamais alerté)
whitelist ; ip  ; 192.168.1.1   ; description
whitelist ; net ; 10.0.0.0/8    ; description
```

| Champ | Valeurs |
|---|---|
| `proto` | `tcp`, `udp`, `any` |
| `port` | numéro de port ou `any` |
| `payload_pattern` | sous-chaîne à chercher dans le payload (insensible à la casse), ou `-` |
| `severity` | `critical`, `high`, `medium`, `low` |
| `resource` | nom de ressource IDS (optionnel, déduit du port sinon) |

### Exemples

```ini
# ── Whitelist — IPs/réseaux jamais alertés ───────────────────────────
whitelist;ip;127.0.0.1;Loopback local
whitelist;net;10.0.0.0/8;Réseau privé classe A
whitelist;net;192.168.0.0/16;Réseau privé classe C

# ── Ports dangereux ──────────────────────────────────────────────────
alert;tcp;22;-;medium;Connexion SSH détectée;ssh_server
alert;tcp;3389;-;high;Connexion RDP (Bureau à distance);rdp_server
alert;tcp;3306;-;high;MySQL exposé sur le réseau;database
alert;tcp;4444;-;critical;Port Metasploit par défaut;network_scanner
alert;tcp;31337;-;critical;Port backdoor classique;network_scanner

# ── Signatures payload ───────────────────────────────────────────────
alert;any;any;SELECT * FROM;critical;Injection SQL — SELECT *;database
alert;any;any;UNION SELECT;critical;Injection SQL — UNION SELECT;database
alert;any;any;DROP TABLE;critical;Injection SQL — DROP TABLE;database
alert;any;any;/bin/sh;critical;Tentative injection shell;system
alert;any;any;<script>;high;Tentative XSS — balise script;web_server
alert;any;any;../../../;high;Path traversal détecté;web_server
```

Une même `(IP source, port)` ou `(IP source, signature)` ne génère qu'une alerte toutes les **60 secondes**, même sous fort trafic.

---

## Format des fichiers d'événements

Le Module 1 écrit un fichier au format JSONL (une ligne JSON par événement) dans le dossier `events/`. Ces fichiers constituent la trace horodatée de toute l'activité observée sur le système.

```json
{
  "id": "3f7a1c2e-8b4d-4e2a-9f1c-0d3a5e7b9c1d",
  "ts": "2026-05-22T10:30:00.123456",
  "source": "auth.log",
  "username": "alice",
  "resource": "ssh_server",
  "task": "login",
  "execution_date": "2026-05-22T10:30:00",
  "raw": "May 22 10:30:00 hostname sshd[1234]: Accepted password for alice from 192.168.1.10"
}
```

---

## Format des alertes

Le Module 4 écrit les alertes dans `alerts/YYYY-MM-DD.log`. Chaque alerte explique précisément pourquoi l'accès a été classé comme une intrusion.

```
═══════════════════════════════════════════════════════
[CRITIQUE] 2026-05-22 03:14:00 UTC
───────────────────────────────────────────────────────
INTRUSION DÉTECTÉE
  Utilisateur : hacker_01
  Ressource   : database
  Tâche       : admin
  Date accès  : 2026-05-22 03:14:00
  Source      : auth.log
───────────────────────────────────────────────────────
  Violation   : Utilisateur 'hacker_01' absent de la politique de sécurité
  Type        : user_unknown
  Ligne brute : May 22 03:14:00 sudo: hacker_01 : COMMAND=/usr/bin/mysql
═══════════════════════════════════════════════════════
```

---

## Guide d'utilisation de l'interface web

Ce guide explique **précisément** ce que tu vois sur chaque page : d'où viennent les données, comment elles sont générées, et ce que chaque compteur/tableau représente.

### **Dashboard (`http://localhost:5000/`)**

#### Compteur "Alertes critiques" (badge rouge)

**Valeur :** `SELECT COUNT(*) FROM alert WHERE severity='critical'`

**Ce qu'il représente :** Nombre d'alertes jugées critiques par le système.

**Comment une alerte devient "critical" :**
- Module 2 détecte une violation de type `user_unknown` → severity `'critical'`
  - Exemple : utilisateur `hacker_01` tente une action, mais n'existe pas dans la politique
- Module 2 détecte une violation de type `unauthorized_access` → severity `'critical'`
  - Exemple : utilisateur `bob` tente d'accéder à `email_server`, alors qu'aucune règle ne l'y autorise
- Module 2 détecte une violation de type `brute_force` → severity `'critical'`
  - Exemple : 5+ tentatives SSH échouées en 60 secondes

**Flux complet :**
1. Module 1 crée un événement JSONL : `{ username: "hacker_01", resource: "database", task: "admin", ... }`
2. Module 2 lit cet événement, le compare à AccessPolicy
3. Pas de correspondance → Module 2 génère `violation['severity'] = 'critical'`
4. Module 2 enqueue cette intrusion pour Module 4
5. Module 4 crée une Alert en DB avec `severity='critical'`
6. Interface affiche ce compteur

#### Compteur "Alertes hautes" (badge orange)

**Valeur :** `SELECT COUNT(*) FROM alert WHERE severity='high'`

**Comment une alerte devient "high" :**
- Module 2 détecte une violation de type `date_violation` → severity `'high'`
  - Exemple : `bob` accède au jour où sa règle a expiré (après 2026-06-30)
- Module 2 détecte une violation de type `time_violation` → severity `'high'`
  - Exemple : `charlie` accède entre 19:00-23:59, alors que son accès est restreint 08:00-18:00
- NIDS détecte une intrusion réseau → severity `'high'`
  - Exemple : connexion sur port SSH (22) depuis une IP non whitelistée

#### Compteur "Total alertes"

**Valeur :** `SELECT COUNT(*) FROM alert`

**Simple :** Somme de toutes les alertes (critical + high + medium + low).

#### Compteur "Intrusions"

**Valeur :** `SELECT COUNT(*) FROM intrusion`

**Ce qu'il représente :** Nombre de violations de politique détectées.

**Important :** Une `Intrusion` ≠ une `Alert`. 
- **Intrusion** = le fait brut qu'une violation a été détectée (créée par Module 2)
- **Alert** = le message formaté affiché à l'utilisateur (créé par Module 4)

Normalement, 1 Intrusion = 1 Alert.

#### Compteur "Fichiers d'événements"

**Valeur :** `SELECT COUNT(*) FROM event_file`

**Ce qu'il représente :** Nombre de fichiers d'analyse batch créés.

**Important :** Ces fichiers ne sont **pas** créés automatiquement. Tu les crées manuellement depuis `/ids/files/create` pour faire de l'analyse batch (historique).

#### Table "Dernières intrusions détectées"

Affiche les **15 dernières** Intrusions avec :
- **Horodatage** : quand l'événement s'est produit (`i.entry.execution_date`)
- **Utilisateur** : qui a déclenché (`i.entry.username`)
- **Ressource** : quoi (`i.entry.resource_name`)
- **Tâche** : action tentée (`i.entry.task`)
- **Type violation** : le message complet généré par Module 2, ex:
  ```
  "Accès de 'alice' hors de la plage horaire autorisée (08:00 → 18:00) — heure d'accès : 23:45"
  ```
- **Détectée le** : quand l'IDS a créé cette intrusion (`i.detected_at`)

---

### **Alertes (`http://localhost:5000/alerts`)**

#### En-tête

```
Alertes
13 alertes — 3 non lues
[Tout acquitter ↗]
```

- **13 alertes** = `Alert.query.count()`
- **3 non lues** = `Alert.query.filter_by(acknowledged=False).count()`

Chaque alerte a un champ `acknowledged` (boolean) : 
- À la création → `acknowledged=False` (rouge, non lue)
- Après clic "Acquitter" → `acknowledged=True` (grise)

#### Table des alertes

**Colonne "Sévérité":**
- Badge **rouge** si `severity='critical'` (user_unknown, unauthorized_access, brute_force)
- Badge **orange** si `severity='high'` (date_violation, time_violation, network_intrusion)

**Colonne "Source":**
- Badge **[IDS]** (rouge) si le message commence par `"[IDS]"` (créé par Module 4 via Module 2)
- Badge **Réseau** (gris) sinon (ancien système, peu actif)

**Colonne "Message":**
- Tronqué à 80 caractères
- Format typique : `[IDS] alice | write sur database | Aucune règle n'autorise...`

**Bouton "Acquitter" :**
- Clique → `/ack_alert/<id>` → `acknowledged=True`

**Bouton "Tout acquitter" :**
- Route `/ack_all_alerts` → met tous les `acknowledged=False` → `True`
- Utile pour vider la liste des non-lues en un coup

---

### **Table des Intrusions (`http://localhost:5000/ids/intrusions`)**

#### En-tête

```
Table des Intrusions
Violations de la politique de sécurité (127)
[↺ Réinitialiser]
```

**127** = `Intrusion.query.count()`

#### Colonnes du tableau

**"Type violation":**
Selon le type de violation détecté par Module 2 :

| Type détecté | Message généré |
|---|---|
| `user_unknown` | `Utilisateur 'X' absent de la politique de sécurité` |
| `unauthorized_access` | `Aucune règle n'autorise 'X' à effectuer 'TASK' sur 'RESOURCE'` |
| `date_violation` | `Accès de 'X' hors de la plage autorisée (YYYY-MM-DD → YYYY-MM-DD)` |
| `time_violation` | `Accès de 'X' hors de la plage horaire autorisée (HH:MM → HH:MM)` |
| `brute_force` | `Brute force détecté : N tentatives échouées en 60s pour 'X'` |
| `network_intrusion` | `Connexion entrante suspecte depuis X.X.X.X sur RESOURCE` |

**Code-couleur des badges :**
```
Si "inconnu" ou "absent" ou "network_intrusion" dans le message → badge ROUGE
Si "horaire" ou "date" ou "plage" dans le message → badge ORANGE
Sinon → badge ORANGE
```

---

### **Monitoring (`http://localhost:5000/ids/monitoring`)**

Affiche en **temps réel** (SSE) le statut des 4 collecteurs du Module 1.

#### Section "Sniffer Réseau (scapy)"

```
ACTIF (pouls vert)
Paquets capturés : 12457
Règles NIDS : 32
Signatures : 27
Whitelist : 4 entrée(s)
Démarré : 10:23
```

**Paquets capturés :**
- `sniffer_status['packets_captured']` — incrémenté chaque fois qu'un paquet IP passe
- Code : `self._count += 1` dans `handle(pkt)`

**Règles NIDS :**
- `nids_status['rules']` — nombre de lignes `alert;...` chargées depuis `nids_rules.conf`
- Par défaut : 32 règles (ports dangereux + signatures)

**Signatures :**
- `nids_status['signatures']` — nombre de règles avec un `payload_pattern`
- Exemple : `alert;any;any;SELECT * FROM;critical;...` → 1 signature

**Whitelist :**
- `nids_status['whitelisted']` — nombre d'entrées `whitelist;ip;...` ou `whitelist;net;...`
- Exemple : `whitelist;ip;127.0.0.1` + `whitelist;net;10.0.0.0/8` → 2 whitelisted

#### Section "Auditd"

```
ACTIF
Événements parsés : 427
Règles chargées : 11/11
Démarré : 10:23
```

**Événements parsés :**
- `auditd_status['events_parsed']` — nombre de lignes lues et convertis depuis `/var/log/audit/audit.log`
- Chaque ligne valide → 1 événement JSONL

**Règles chargées :**
- `auditd_status['rules_loaded']` — nombre de règles auditctl appliquées au démarrage (11 règles dans `ids_audit.rules`)
- Format : `11/11` = 11 chargées sur 11 tentées

#### Section "Lecteur de Logs (auth.log)"

```
ACTIF
Fichier : /var/log/auth.log
Lignes lues : 523
Entrées créées : 148
Démarré : 10:23
```

**Lignes lues :**
- `logwatcher_status['lines_processed']` — nombre de lignes totales parsées

**Entrées créées :**
- `logwatcher_status['entries_created']` — nombre d'événements valides extraits
- Raison de la différence (523 → 148) : beaucoup de lignes ne sont pas des événements intéressants

Module 1 relit auth.log toutes les 3s depuis un curseur (`.events_cursor.json`) pour ne pas rejouer les vieilles lignes.

#### Section "FileIntegrityMonitor"

```
ACTIF
Fichiers surveillés : 7
Baseline calculée : 2026-05-23 10:23
```

**Fichiers surveillés :**
- Nombre de fichiers listés dans `ids_integrity.conf`
- Par défaut : 7 (passwd, shadow, sudoers, sshd_config, crontab, hosts, pam.d/common-auth)

**Toutes les 30 secondes :**
- Module 1 calcule `sha256(contenu)` pour chaque fichier
- Compare avec le hash précédent
- Si différent → crée événement JSONL `{ source: "file_integrity", ... }`
- Module 2 détecte → Intrusion + Alert

---

### **Politique de Sécurité (`http://localhost:5000/ids/policy`)**

#### En-tête

```
16 active(s)
[↓ Télécharger] [↑ Importer] [→ Exporter]
```

**16 active(s)** = `AccessPolicy.query.filter_by(active=True).count()`

**Boutons :**
- **Exporter** : Sauvegarde la DB dans `policy.conf` (fichier texte éditable)
- **Importer** : Charge `policy.conf` dans la DB
- **Télécharger** : Récupère `policy.conf` comme fichier `.txt`

#### Formulaire "Ajouter une règle"

```
Utilisateur : [alice, bob, charlie, ...]
Ressource   : [database, web_server, ssh_server, ...]
Tâche       : [read, write, delete, execute, admin, login, ...]
Début       : [2026-01-01] [00:00]
Fin         : [2026-12-31] [23:59]
```

Crée une nouvelle `AccessPolicy` :
- **Utilisateur** : qui (de `IDSUser`)
- **Ressource** : quoi (de `Resource`)
- **Tâche** : action (liste fixe)
- **Dates/heures** : plage d'autorisation

Exemple : `alice;database;read;2026-01-01 00:00;2026-12-31 23:59;1` = alice peut lire la DB toute l'année.

#### Table des règles existantes

| Utilisateur | Ressource | Tâche | Début | Fin | Statut | Actions |
|---|---|---|---|---|---|---|
| alice | database | read | 01/01/2026 | 31/12/2026 | Actif | [⏻] [🗑] |

**Statut :**
- **Vert "Actif"** = `active=True` → Module 2 utilise cette règle
- **Gris "Inactif"** = `active=False` → Module 2 l'ignore

**Bouton ⏻ (Toggle) :**
- Inverse `active` sans supprimer

**Bouton 🗑 (Delete) :**
- Supprime la règle (cascade : supprime aussi les enfants)

---

### **Utilisateurs (`http://localhost:5000/ids/users`)**

#### Table

| Utilisateur | Rôle | Actions |
|---|---|---|
| alice | admin | [🗑] |
| bob | user | [🗑] |

**Rôle :**
- `admin` ou `user` — déclaratif uniquement
- C'est `AccessPolicy` (tâches) qui restreint réellement

**Formulaire "Ajouter un utilisateur" :**
```
Nom : [texte]
Rôle : [admin | user]
```

Crée un nouvel `IDSUser`. Validation : username unique.

**Bouton 🗑 (Delete) :**
- Supprime l'utilisateur ET toutes ses règles `AccessPolicy` (cascade)

---

### **Ressources (`http://localhost:5000/ids/resources`)**

#### Table

| Ressource | Description | Actions |
|---|---|---|
| database | Base de données principale | [🗑] |
| ssh_server | Serveur SSH | [🗑] |

Créées au démarrage par `_seed()`. Éditable.

**Formulaire "Ajouter une ressource" :**
```
Nom : [texte unique]
Description : [texte]
```

Crée une `Resource`. Une fois créée, apparaît dans les dropdowns de Policy.

---

### **Fichiers d'événements (`http://localhost:5000/ids/files`)**

#### Formulaire "Créer un fichier vide"

```
Nom (optionnel) : [Session_Audit_001]
[Créer]
```

Crée un `EventFile` avec `file_number` auto-incrémenté. C'est pour faire de l'analyse batch (historique, importation de données).

#### Table des fichiers

| # | Nom | Entrées | Créé le | Statut | Actions |
|---|---|---|---|---|---|
| 1 | Batch_001 | 45 | 23/05 10:23 | Analysé | [👁] [🗑] |

**Entrées :**
- `EventEntry.query.filter_by(file_id=f.id).count()`

**Statut :**
- **"Analysé"** si `analyzed=True` (Module 2 a traité ce fichier)
- **"Vide"** si 0 entrées

**Lien 👁 (Voir) :**
- Accès `/ids/files/<file_id>` → liste des entrées + bouton "Ajouter une entrée"

---

### **Paramètres (`http://localhost:5000/ids/settings`)**

#### Section 1 : SMTP (Email)

```
Hôte SMTP : [smtp.gmail.com]
Port      : [587]
Utilisateur : [ton@email.com]
Mot de passe : [••••••••]
Adresse "De" : [ids@votredomaine.com]
Adresse "À" : [admin@votredomaine.com]
TLS activé : [✓]
[Sauvegarder]
```

Sauvegardé dans `ids_config.json` (JSON local).

Quand Module 4 crée une alerte et qu'`ids_config.json` existe, il envoie un email à l'adresse "À".

#### Section 2 : Surveillance d'intégrité

```
Fichiers à surveiller (un par ligne) :

/etc/passwd
/etc/shadow
/etc/sudoers
...
```

Sauvegardé dans `ids_integrity.conf` (un fichier par ligne).

Module 1 relit ce fichier toutes les 30s et surveille les SHA-256.

---

### **Moteur d'Analyse (`http://localhost:5000/ids`)**

#### Stats (6 cartes)

| Utilisateurs | Ressources | Règles | Fichiers | Entrées | Intrusions |
|---|---|---|---|---|---|
| 6 | 8 | 16 | 2 | 92 | 11 |

D'où ça vient :
```python
IDSUser.query.count()
Resource.query.count()
AccessPolicy.query.filter_by(active=True).count()
EventFile.query.count()
EventEntry.query.count()
Intrusion.query.count()
```

#### Formulaire "Lancer l'Analyse"

```
N — Entrées max / fichier : [100]
P — Nombre de fichiers : [2]
M — Taille table intrusions : [1000]
K — Règles max : [16]
[Analyser]
```

**Paramètres :**
- **N** : Max d'entrées à analyser par fichier
- **P** : Nombre de fichiers à traiter (les plus récents)
- **M** : Cap sur le nombre d'intrusions à créer
- **K** : Max de règles à charger

**Clic "Analyser" :**
1. Charge jusqu'à **K** règles actives
2. Charge jusqu'à **P** fichiers (plus récents)
3. Pour chaque fichier, lit jusqu'à **N** entrées
4. Pour chaque entrée, appelle `_check_event()` → détecte violations
5. Crée Intrusions + Alerts pour chaque violation
6. Redirige vers `/ids/intrusions`

---

## Tests réels

### Test 1 — Connexion SSH autorisée

```bash
# alice est dans policy.conf avec la règle login/ssh_server → aucune intrusion
ssh alice@localhost
```

### Test 2 — Connexion SSH non autorisée

```bash
# compte "pirate" absent de policy.conf → intrusion immédiate
ssh pirate@localhost
```

### Test 3 — Brute force SSH

```bash
# 5 tentatives échouées en moins de 60 secondes → alerte brute_force
for i in $(seq 1 6); do ssh fakeuser@localhost 2>/dev/null; done
```

### Test 4 — Escalade de privilèges (sudo)

```bash
# charlie n'est pas autorisé à exécuter mysql → intrusion
sudo -u charlie mysql -u root
```

### Test 5 — Fichier critique modifié

```bash
# Modification de /etc/hosts → détectée en moins de 30 secondes
sudo sh -c 'echo "# test" >> /etc/hosts'
```

### Test 6 — Outil offensif détecté

```bash
# nmap est dans la liste SUSPICIOUS → intrusion via ProcessMonitor
nmap localhost
```

### Test 7 — Scan de ports réseau (nécessite sudo pour l'IDS)

```bash
# Depuis une autre machine ou un autre terminal
nmap -sS -p 1-100 <ip_machine>
# → 15 ports différents en 60s → détection scan
```

### Test 8 — Scénario intégré complet

Depuis l'interface web, aller dans **Scénario → Charger et Analyser**. Ce scénario simule 25 événements répartis sur 4 fichiers avec les trois types de violations (utilisateur inconnu, escalade de privilèges, date expirée). Résultat attendu : 17 à 18 intrusions détectées.

---

## Configuration email

Pour recevoir les alertes par email, créer un fichier `ids_config.json` à la racine du projet :

```json
{
  "smtp": {
    "host": "smtp.gmail.com",
    "port": 587,
    "user": "votre@gmail.com",
    "password": "app_password_google",
    "from": "ids@votredomaine.com",
    "to": "admin@votredomaine.com",
    "tls": true
  }
}
```

> Pour Gmail, utiliser un [mot de passe d'application](https://support.google.com/accounts/answer/185833) et non le mot de passe du compte.

---

## Déploiement production

### Linux avec systemd

```bash
# 1. Copier le projet
sudo cp -r . /opt/ids_web

# 2. Créer le service systemd
sudo tee /etc/systemd/system/ids.service > /dev/null <<EOF
[Unit]
Description=IDS Web Platform
After=network.target

[Service]
User=root
WorkingDirectory=/opt/ids_web
ExecStart=python3 /opt/ids_web/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 3. Activer et démarrer
sudo systemctl daemon-reload
sudo systemctl enable ids
sudo systemctl start ids

# 4. Vérifier
sudo systemctl status ids
sudo journalctl -u ids -f
```

### Dépendances

```
Flask>=3.1.0
Flask-SQLAlchemy>=3.1.1
scapy>=2.6.1          # capture réseau (Linux + Windows avec Npcap)
psutil>=5.9.0         # surveillance des processus
python-dotenv>=1.0.1
gunicorn>=23.0.0      # serveur WSGI pour production Linux
```

---

## Améliorations prévues

Les fonctionnalités suivantes sont identifiées comme prioritaires pour une version future. Elles ne sont pas encore implémentées.

### Haute priorité

**Intégration de `auditd` (Linux)**
La source actuelle (`auth.log`) ne voit que les connexions et les commandes `sudo`. Elle ne voit pas ce que l'utilisateur fait une fois connecté : accès aux fichiers, requêtes base de données, navigation sur des ressources internes. L'intégration du framework d'audit Linux (`auditd`) permettrait de surveiller l'intégralité de l'activité système, y compris chaque appel système, chaque accès fichier et chaque exécution de commande, pour n'importe quel utilisateur.

```bash
# Exemple de règles auditd à ajouter
auditctl -w /var/lib/mysql -p rwa -k database_access
auditctl -a always,exit -F arch=b64 -S execve -k exec_commands
auditctl -w /etc/passwd -p wa -k passwd_change
```

**Corrélation IP → Utilisateur**
Le Module 1 collecte des événements réseau où `username` est l'adresse IP source. Il n'y a pas encore de mécanisme pour relier une IP à un utilisateur authentifié (par exemple, l'IP `10.0.0.5` = session SSH d'`alice`). Une table de corrélation basée sur les sessions SSH actives permettrait une détection plus précise.

**Restriction par jour de la semaine**
Le format `policy.conf` supporte les plages de dates et d'heures, mais pas encore les jours de la semaine. Ajouter un champ `jours` (ex : `LUN-VEN`) permettrait de définir des règles du type "alice peut accéder à la base de données uniquement en semaine, entre 8h et 18h".

### Priorité moyenne

**Analyse inotify en temps réel**
Le Module 2 relit les fichiers d'événements toutes les 3 secondes par polling. Remplacer cette approche par `inotify` (Linux) ou `ReadDirectoryChangesW` (Windows) permettrait une réaction instantanée à chaque nouvel événement, sans délai de scrutation.

**Réduction des faux positifs du ProcessMonitor**
Le moniteur de processus déclenche des intrusions pour tout processus dont le nom correspond à sa liste (incluant `kubectl`, `python`, `curl`, etc. si leurs arguments sont suspects). Un système de liste blanche par utilisateur (`alice` est autorisée à lancer `python3`) éviterait les alertes non pertinentes.

**Support des logs applicatifs**
Ajouter la lecture des logs de serveurs web (`/var/log/nginx/access.log`, `/var/log/apache2/access.log`) et de bases de données (`/var/log/mysql/mysql.log`) pour détecter les attaques applicatives sans dépendre de la capture réseau.

### Priorité basse

**Export des alertes vers Syslog / SIEM**
Permettre l'envoi des alertes vers un serveur syslog centralisé ou un SIEM externe (Splunk, Graylog, Elastic) via le protocole RFC 5424.

**Authentification de l'interface web**
L'interface web est actuellement accessible sans authentification. Ajouter un système de login pour protéger l'accès à la configuration et aux données de détection.

**Règles réseau personnalisées avec regex**
Les règles réseau actuelles supportent des conditions simples (`port==N`, `keyword=X`). Étendre le moteur pour accepter des expressions régulières complètes sur les payloads réseau.

**Suppression automatique des vieux fichiers**
Les fichiers `events/` et `alerts/` s'accumulent sans limite. Ajouter une politique de rétention configurable (ex : conserver 30 jours).
