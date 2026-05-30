# IDS Web — Système de Détection d'Intrusions

Plateforme de détection d'intrusions modulaire, développée en Python/Flask. Elle repose sur **sept modules indépendants** qui fonctionnent en permanence comme des démons dès le lancement de l'application : collecte multi-source, analyseur deny-by-default avec patterns configurables, gestion de politique, alertes multicanal, maintenance, corrélation de chaînes d'attaque et détection d'anomalies comportementales. Elle tourne sur Linux et Windows, en local comme en production.

---

## Sommaire

- [Architecture](#architecture)
- [Installation](#installation)
- [Démarrage](#démarrage)
- [Structure du projet](#structure-du-projet)
- [Les 7 modules](#les-7-modules)
- [Sources de données](#sources-de-données)
- [Éléments surveillés — Liste complète](#éléments-surveillés--liste-complète)
- [Ressources & modèle d'accès](#ressources--modèle-daccès)
- [Sécurité & authentification web](#sécurité--authentification-web)
- [Notifications externes](#notifications-externes)
- [Logique de détection](#logique-de-détection)
- [Types de violations](#types-de-violations)
- [Format policy.conf](#format-policyconf)
- [Règles NIDS (nids_rules.conf)](#règles-nids-nids_rulesconf)
- [Format des fichiers d'événements](#format-des-fichiers-dévénements)
- [Format des alertes](#format-des-alertes)
- [Guide d'utilisation de l'interface web](#guide-dutilisation-de-linterface-web)
- [Variables d'environnement](#variables-denvironnement)
- [Tests réels](#tests-réels)
- [Déploiement production](#déploiement-production)
- [Améliorations prévues](#améliorations-prévues)

---

## Architecture

Le système est organisé en pipeline à **cinq étages**. Chaque module est un démon indépendant qui démarre automatiquement avec l'application. Un cinquième module (maintenance) tourne en arrière-plan pour la purge et l'archivage.

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

#### Installation automatique (recommandée)

```bash
git clone <repo> ids_web && cd ids_web
sudo ./deploy/install.sh
```

Le script installe Python, auditd, toutes les dépendances Python (depuis `requirements.txt`), génère un `IDS_SECRET_KEY` aléatoire et propose la création d'un service systemd.

#### Installation manuelle

```bash
# 1. Récupérer le projet
cd /opt && git clone <repo> ids_web && cd ids_web

# 2. Installer Python 3.10+ et pip
sudo apt update && sudo apt install python3 python3-pip -y

# 3. Installer TOUTES les dépendances Python depuis requirements.txt
#    Sur Ubuntu 24.04+ le flag --break-system-packages est OBLIGATOIRE (PEP 668)
pip3 install -r requirements.txt --break-system-packages

# 4. Installer auditd (HIDS — surveillance système avancée)
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd && sudo systemctl start auditd

# 5. Installer scapy pour root également (capture réseau)
sudo pip3 install -r requirements.txt --break-system-packages

# 6. Autoriser la lecture des logs (optionnel si on lance avec sudo)
sudo chmod o+r /var/log/auth.log

# 7. Lancer — IMPORTANT : utiliser sudo -E pour préserver les packages
#    Python installés dans ~/.local/ tout en obtenant les droits root
sudo -E python3 app.py
```

> **Pourquoi `sudo -E` ?** Sans le flag `-E`, sudo réinitialise l'environnement et root ne voit pas les packages installés dans `~/.local/lib/python3.X/site-packages/` de l'utilisateur. Résultat : `ModuleNotFoundError: No module named 'flask'`. Le flag `-E` préserve `$PATH` et `$PYTHONPATH`.

### Linux — RHEL / CentOS / Fedora

```bash
sudo dnf install python3 python3-pip audit -y
pip3 install -r requirements.txt --break-system-packages
sudo systemctl enable auditd && sudo systemctl start auditd
sudo chmod o+r /var/log/secure
sudo -E python3 app.py
```

### Windows

#### Installation automatique (recommandée)

```powershell
# PowerShell en Administrateur
powershell -ExecutionPolicy Bypass -File deploy\install-windows.ps1
```

Le script vérifie Sysmon + npcap, installe les dépendances Python et génère les secrets.

#### Installation manuelle

```powershell
# 1. Installer Python 3.10+ depuis https://python.org
# 2. Installer Sysmon (HIDS Windows avancé)
#    Téléchargement : https://docs.microsoft.com/sysinternals/downloads/sysmon
#    Installation : Sysmon64.exe -accepteula -i sysmonconfig.xml
# 3. Installer Npcap (capture réseau scapy)
#    Téléchargement : https://npcap.com

# 4. Dans PowerShell en tant qu'Administrateur
pip install -r requirements.txt

# 5. Définir les secrets
$env:IDS_SECRET_KEY  = -join ((1..64) | %{Get-Random -Maximum 16 | %{'{0:x}' -f $_}})
$env:IDS_ADMIN_PASSWORD = 'votre-mot-de-passe-fort'

# 6. Lancer en tant qu'Administrateur (Event Log + capture réseau + Sysmon)
python app.py
```

> **Sysmon** est requis pour bénéficier de la surveillance avancée Windows (process create, network connections, registry monitoring via Sysmon). Sans Sysmon, l'IDS fonctionne mais les détections Windows seront limitées au journal Security/System standard.

> **Npcap** est requis pour la capture réseau. Sans npcap, le NIDS sera désactivé sur Windows (mais le HIDS continue de fonctionner).

---

## Démarrage

Une fois lancé, l'interface web est accessible à :

```
http://localhost:5000
```

### Identifiants de connexion

| Méthode d'installation | Username | Password |
|---|---|---|
| Manuel Linux (sans `IDS_ADMIN_PASSWORD`) | `admin` | `admin` |
| Script `./deploy/install-windows.ps1` | `admin` | mot de passe fort généré (ex. `V8GnqQc~!Wb.Tqg`) — affiché à la fin du script et sauvegardé dans `C:\Program Files\IDS_Web\.secrets.txt` |
| `IDS_ADMIN_PASSWORD` défini avant le 1er démarrage | `admin` | la valeur fournie |

Le mot de passe doit être changé via **Compte → Mot de passe** après la première connexion.

### Démarrage des modules

Les **sept modules** démarrent automatiquement dans l'ordre suivant :

```
[MODULE 3] Politique chargée depuis policy.conf
[MODULE 1] Collecteur démarré (OS=Linux)
[MODULE 2] Analyseur démarré
[MODULE 2] 7 patterns detect chargés
[MODULE 4] Générateur d'alertes démarré
[MODULE 5] Maintenance démarrée
[MODULE 6] Corrélation kill chain démarrée (fenêtre 1800s)
[MODULE 7] Détecteur d'anomalies démarré
[IDS] Les 7 modules sont démarrés.
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

## Les 7 modules

### Module 1 — Collecteur d'événements

Observe en permanence plusieurs sources système et réseau. Pour chaque événement détecté, il produit une ligne JSON dans le fichier `events/YYYY-MM-DD.jsonl` du jour.

| Collecteur | Source | OS | Droits requis |
|---|---|---|---|
| `LinuxLogCollector` | `/var/log/auth.log`, `/var/log/secure` | Linux | Lecture seule |
| `AuditdCollector` | `/var/log/audit/audit.log` (11 règles auditd) | Linux | Lecture seule |
| `LinuxPersistenceMonitor` | cron, systemd, init.d, profile.d, /root/.ssh | Linux | Lecture seule |
| `SUIDMonitor` | Détecte nouveaux SUID/SGID (escalade de privilèges) | Linux | Lecture seule |
| `WindowsLogCollector` | Journal Security, System (via `wevtutil`) | Windows | Administrateur |
| `SysmonCollector` | Journal Sysmon (Events 1, 3, 7, 11, 12, 13, 22, 25) | Windows | Administrateur + Sysmon installé |
| `WindowsRegistryMonitor` | 9 clés de persistence (Run, Winlogon, IFEO...) | Windows | Administrateur |
| `WindowsServiceMonitor` | Nouveaux services + binPath suspects | Windows | Administrateur |
| `NetworkCapture` | Paquets IP/IPv6 (scapy) + moteur de règles + JA3 + DNS tunnel | Linux + Windows | root / Admin (+ npcap sur Windows) |
| `FileIntegrityMonitor` | Hash SHA-256 des fichiers critiques | Linux + Windows | Lecture seule |
| `ProcessMonitor` | Nouveaux processus suspects (160+ outils offensifs) | Linux + Windows | Utilisateur standard |

### Module 2 — Analyseur d'événements

Surveille le dossier `events/` toutes les 3 secondes. Pour chaque nouvelle ligne JSON, il compare les quatre champs de l'événement (`username`, `resource`, `task`, `execution_date`) aux règles actives de la politique. Si aucune règle n'autorise cet accès, une intrusion est enregistrée et transmise au Module 4.

Le système fonctionne en **deny-by-default** avec **accumulation cumulative de droits** : chaque règle `allow` ajoute une permission, chaque règle `deny` la retire. Les règles sont évaluées dans l'ordre.

Il exécute également un **moteur de patterns de détection comportementale** configurable depuis l'interface (`/ids/policy` → onglet *Patterns Detect*). Chaque pattern associe une ressource, une tâche, un seuil et une fenêtre temporelle. Sept patterns sont fournis par défaut :

| Pattern | Ressource | Tâche | Seuil / Fenêtre | Sévérité |
|---|---|---|---|---|
| `BRUTE_FORCE_SSH` | `ssh_server` | `failed_login` | 5 / 5 s | critical |
| `BRUTE_FORCE_WEB` | `web_server` | `failed_login` | 5 / 30 s | high |
| `BRUTE_FORCE_DB` | `database` | `failed_login` | 3 / 10 s | critical |
| `EXEC_FLOOD` | `system` | `execute` | 20 / 60 s | high |
| `PRIVESC_ATTEMPT` | `system` | `execute` | 5 / 10 s | critical |
| `FILE_READ_FLOOD` | `file_system` | `read` | 50 / 30 s | high |
| `FILE_DELETE_FLOOD` | `file_system` | `delete` | 10 / 30 s | critical |

Les seuils sont modifiables à chaud, sans toucher au code. La détection de **scan de ports** réseau (15 ports distincts par IP en 60 s) est assurée au niveau du Module 1 (collecteur).

### Module 3 — Gestion de la politique de sécurité

Gère les règles d'accès de deux façons complémentaires :

- **Interface web** : ajout, suppression, activation/désactivation de chaque règle individuellement.
- **Fichier `policy.conf`** : modification globale en éditant directement le fichier texte. Le module surveille ce fichier en permanence et recharge automatiquement la politique dès qu'une modification est détectée, sans redémarrer l'application.

Deux types de règles coexistent dans `/ids/policy` via un toggle :

- **HIDS** : `user × resource × task × policy_type (allow/deny) × plage de dates`
- **NIDS** : `name × version (ipv4/v6) × protocol × src_ip × dst_ip × src_port × dst_port × tcp_flags × action (alert/deny/accept)`

### Module 4 — Générateur d'alertes

Reçoit les intrusions depuis le Module 2 via une file d'attente thread-safe. Pour chaque intrusion, il génère une alerte formatée qui explique précisément la violation, puis la distribue sur tous les canaux configurés :

- **Fichier log** `alerts/YYYY-MM-DD.log`
- **Base de données** (modèle `Alert`)
- **Email SMTP** (optionnel)
- **Webhooks** : Slack (Block Kit), Discord (embeds), MS Teams (MessageCard)
- **Syslog** vers SIEM (Splunk, ELK, Wazuh) — RFC 3164 UDP

Filtre par sévérité minimale configurable (`min_severity`).

### Module 5 — Maintenance & housekeeping

Démon qui tourne en arrière-plan (toutes les heures par défaut) pour assurer la santé long-terme du système :

- **Purge DB** : supprime les `Alert` acquittées, `Intrusion`, `EventEntry`, `AuditLog` plus anciens que la rétention configurée
- **Rotation des fichiers** : compresse en `.gz` les fichiers `events/` et `alerts/` plus anciens que 2 jours
- **Suppression des archives** : supprime les `.gz` plus anciens que `ARCHIVE_RETENTION_DAYS` (90j par défaut)

Configuration via variables d'environnement (voir [Variables d'environnement](#variables-denvironnement)).

### Module 6 — Corrélation de chaînes d'attaque (kill chain)

Une intrusion isolée ne révèle qu'un fragment de l'intention de l'attaquant. Ce module **relie des intrusions successives** d'un même acteur (adresse IP ou utilisateur) pour reconstituer une chaîne d'attaque. Il scanne la table des intrusions toutes les 60 s sur une fenêtre glissante de 30 min (`IDS_KILLCHAIN_WINDOW`) et détecte trois enchaînements caractéristiques :

| Pattern | Séquence détectée |
|---|---|
| `SCAN_THEN_BREACH` | Scan de ports → force brute (reconnaissance puis exploitation) |
| `BREACH_THEN_EXEC` | Force brute → exécution de commande (accès puis action) |
| `PERSIST_AFTER_EXEC` | Exécution → modification de persistance (cron, registre, systemd) |

Émet une alerte **critique** `kill_chain_*` décrivant les étapes horodatées, avec déduplication par couple (pattern, acteur).

### Module 7 — Détection d'anomalies comportementales

Approche statistique non supervisée. Pour chaque utilisateur surveillé, il construit une **baseline** de comportement normal sur 7 jours (`IDS_BASELINE_DAYS`) :

- distribution horaire de l'activité (24 intervalles)
- ressources habituellement accédées
- tâches habituellement effectuées
- taux moyen d'échecs de connexion

Toutes les 5 min (`IDS_ANOMALY_INTERVAL`), l'activité récente est comparée à la baseline. Trois écarts déclenchent une alerte **moyenne** `behavior_anomaly` :

- heure inhabituelle (Z-score > 3,0, paramètre `IDS_ANOMALY_ZSCORE`)
- ressource jamais/rarement vue par cet utilisateur
- tâche inhabituelle pour cet utilisateur

Minimum 50 échantillons requis avant tout scoring pour éviter les faux positifs sur les profils peu observés.

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

Détecte l'apparition de nouveaux processus dont le nom ou la ligne de commande correspond à une liste d'outils offensifs connus (plus de 160 outils répertoriés : nmap, hydra, netcat, mimikatz, sqlmap, xmrig, etc.).

---

## Éléments surveillés — Liste complète

### HIDS — Host-based Intrusion Detection

#### 1. Authentification Linux (`/var/log/auth.log`)
- **SSH logins** — réussis et échoués
- **Sudo commands** — avec utilisateur et commande exécutée
- **Su transitions** — changements d'utilisateur
- **PAM events** — sessions console et locales
- **Brute force** — 5+ tentatives échouées en 60s

#### 2. Auditd — Appels système (11 règles)
- **Exécutions root** : `execve` avec `euid=0` — toutes les commandes lancées en tant que root
- **Fichiers critiques** (lectures, écritures, suppressions) :
  - `/etc/passwd` — base utilisateurs
  - `/etc/shadow` — mots de passe hachés
  - `/etc/sudoers` — permissions sudo
  - `/etc/ssh/sshd_config` — configuration SSH
  - `/etc/crontab` — tâches planifiées
  - `/etc/hosts` — résolutions DNS locales
  - `/etc/pam.d/common-auth` — authentification système
- **Gestion des utilisateurs** :
  - `useradd`, `userdel`, `usermod` — création/suppression/modification
  - `passwd` — changements de mots de passe
  - `chauthtok` — modifications d'authentification
- **Connexions réseau sortantes** — deprecated (trop bruyant)

#### 3. Intégrité fichiers — SHA-256 (baseline 30s)
Les 7 fichiers critiques sont hachés toutes les 30 secondes et comparés. Toute modification génère immédiatement une intrusion :
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/crontab`, `/etc/hosts`, `/etc/pam.d/common-auth`

#### 4. Surveillance processus — 160+ outils offensifs détectés

**Shells alternatifs :** bash, sh, zsh, ksh, tcsh, csh, busybox, ash, mksh

**Reconnaissance réseau :** nc, ncat, netcat, socat, nmap, netstat, ss, arp, whois, dig, nslookup, host, traceroute, mtr, hping3, tcpdump, strace, dtrace, ltrace

**Transfert de fichiers :** wget, curl, scp, sftp, rsync, ftp, lftp, rclone

**Scripting & interprétation :** python, python2, python3, perl, ruby, php, node, npm, go, rust, java, javac

**Exploitation :** metasploit, meterpreter, empire, mimikatz, hashcat, john, aircrack, sqlmap, nikto, burp, zaproxy, commix

**Monitoring système :** ps, top, htop, iotop, nethogs, lsof, ss, netstat

**Autres outils suspects :** screen, tmux, expect, telnet, openssl, ssl_client

#### 5. Persistence Linux (LinuxPersistenceMonitor)

Surveille toutes les 2 minutes les emplacements de persistence :
- `/etc/cron.d`, `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly`, `/etc/cron.monthly`
- `/var/spool/cron`, `/var/spool/cron/crontabs`
- `/etc/systemd/system`, `/lib/systemd/system`
- `/etc/init.d`, `/etc/profile.d`
- `/root/.ssh` (authorized_keys)

Détecte : nouveau fichier, modification (mtime), suppression.

#### 6. Escalade de privilèges Linux (SUIDMonitor)

Scan toutes les 10 minutes des binaires SUID/SGID dans : `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/tmp`, `/var/tmp`, `/dev/shm`, `/home`.

Alerte critique si un nouveau SUID apparaît dans `/tmp`, `/home`, `/var/tmp`, `/dev/shm` (emplacements suspects pour backdoors).

Whitelist : su, sudo, passwd, mount, ping, pkexec, crontab, etc. (SUID Linux légitimes).

### HIDS Windows

#### 1. WindowsLogCollector — Event Log Security/System

Lit `wevtutil qe Security` et `wevtutil qe System` pour les EventIDs :

| EventID | Tâche | Resource | Description |
|---|---|---|---|
| 4624 | login | system | Connexion réussie |
| 4625 | failed_login | system | Connexion échouée |
| 4672 | admin | system | Privilèges admin assignés |
| 4688 | execute | system | Nouveau process créé |
| 4663 | read | file_storage | Accès fichier |
| 4720 | write | user_management | Compte créé |
| 4732 | write | user_management | Ajout à groupe |
| 7045 | execute | system | Nouveau service installé |

#### 2. SysmonCollector — Équivalent auditd

Lit `Microsoft-Windows-Sysmon/Operational` (requiert Sysmon installé). Events surveillés :

| EventID | Description | Détection enrichie |
|---|---|---|
| 1 | Process Create | Détecte processus suspects (mimikatz, psexec...) + LOLBins (certutil, mshta, powershell -enc) |
| 3 | Network Connection | Trace connexions sortantes par processus |
| 7 | Image Loaded | Alerte sur DLL non signée |
| 11 | File Create | Alerte si drop dans Startup/AppData/Temp avec extensions exécutables |
| 12-13 | Registry modification | Alerte si modification d'une clé de persistence |
| 22 | DNS Query | Alerte si domaine suspect (.onion, ngrok, pastebin) |
| 25 | Process Tampering | Toujours critique |

Installation Sysmon : voir https://docs.microsoft.com/sysinternals/downloads/sysmon

#### 3. WindowsRegistryMonitor — Persistence registre

Surveille toutes les 60s les valeurs des clés de persistence :
- `HKLM/HKCU \Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM/HKCU \Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM \Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
- `HKLM \Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` (IFEO hijacking)
- `HKLM \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

Détecte : nouvelle valeur, modification, suppression.

#### 4. WindowsServiceMonitor — Persistence services

Surveille toutes les 60s la liste des services Windows (`sc query state=all`).

Alerte sur :
- Nouveau service installé
- Service avec binPath suspect : `powershell`, `cmd.exe /c`, `rundll32`, `mshta`, `wscript`, `cscript`, `regsvr32`, `certutil`, `bitsadmin`, chemin dans `\users\` / `\temp\` / `\appdata\`

#### 5. Intégrité fichiers Windows

Surveille SHA-256 de 10 fichiers critiques :
`hosts`, `networks`, `protocol`, `services`, `SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`, `win.ini`, `GroupPolicy\Machine\Registry.pol`.

### NIDS — Network-based Intrusion Detection

#### 1. Détection port scan
- **Seuil** : ≥ 15 ports distincts contactés en 60 secondes
- **Fenêtre glissante** : port SYN non répondu = port différent comptabilisé
- **Source** : adresse IP source unique

#### 2. Ports dangereux surveillés
| Port | Protocole | Service | Risque |
|------|-----------|---------|--------|
| 23 | TCP | Telnet | Authentification en clair |
| 3306 | TCP | MySQL | Base de données exposée |
| 5432 | TCP | PostgreSQL | Base de données exposée |
| 1433 | TCP | MSSQL | Serveur SQL Microsoft exposé |
| 445 | TCP | SMB | Partage Windows exploitable |
| 139 | TCP | NetBIOS | Partage ancienne génération |
| 3389 | TCP | RDP | Bureau à distance |
| 21 | TCP | FTP | Transfert en clair |
| 25, 587 | TCP | SMTP | Messagerie |
| 4444, 1337, 6666, 9001 | TCP | Divers | Proxies, C2, accès non autorisé |

#### 3. Signatures payload — Injection & traversée
Le moteur cherche des patterns suspects dans le contenu des paquets (insensible à la casse) :

**SQL Injection :** SELECT, UNION, DROP, INSERT, UPDATE, DELETE, EXEC, script, FROM, WHERE, LIKE, OR, AND

**XSS (Cross-Site Scripting) :** `<script>`, `onerror=`, `onclick=`, `onload=`, `onmouseover=`, `javascript:`, `<iframe>`

**Path Traversal :** `../`, `..\\`, `%2e%2e`, `....`, `%252e`

**Shell Injection :** `;`, `|`, `||`, `&&`, `` ` ``, `$()`, `/bin/sh`, `/bin/bash`

**Buffer Overflow :** patterns de padding excessif, offsets suspects

**Command Injection :** metacharacters shell, redirection

#### 4. Extraction SNI TLS
- **Objectif** : lire le domaine de destination sans déchiffrer
- **Technique** : parse du `ClientHello` (TLS handshake initial)
- **Cas détectés** : `.onion` (Tor), `ngrok.io`, `pastebin.com`, `webhook.site`, domaines C2 connus

#### 5. Suivi TCP session
- **Clé** : `(IP source, IP destination, port destination)`
- **Durée** : jusqu'à FIN/RST ou timeout 30 min
- **Déduplication** : une même session ne génère qu'une alerte toutes les 60s

#### 6. JA3 fingerprinting TLS

Calcule la signature JA3 (MD5 des paramètres TLS ClientHello : version, ciphers, extensions, curves, formats).

Une signature JA3 identifie de manière unique un client TLS — utile pour détecter les outils malveillants même via HTTPS chiffré. Base de signatures connues intégrée :

| JA3 hash | Identifié comme |
|---|---|
| `6734f37431670b3ab4292b8f60f29984` | Trickbot |
| `54328bd36c14bd82ddaa0c04b25ed9ad` | Emotet |
| `a0e9f5d64349fb13191bc781f81f42e1` | Cobalt Strike |
| `72a589da586844d7f0818ce684948eea` | Tor browser |

Génère un événement source `nids/ja3` avec déduplication 5 min par (src, ja3).

#### 7. Détection DNS tunneling

Analyse les requêtes DNS (UDP port 53) pour détecter l'exfiltration via tunneling :

- **Volume anormal** : > 50 requêtes en 60s vers le même domaine racine
- **Sous-domaine long** : > 50 caractères (encoding base64/base32)
- **Entropie élevée** : entropie de Shannon > 4.0 sur le sous-domaine (données chiffrées/aléatoires)

Génère un événement source `nids/dns_tunnel` avec déduplication 5 min par domaine.

#### 8. Support IPv6

Le moteur de capture traite IPv4 (`IP`) et IPv6 (`IPv6`) de la même manière :
- Match d'IP avec CIDR
- TCP/UDP avec ports source/destination
- Filtre loopback `::1 ↔ ::1`
- Toutes les règles NIDS s'appliquent indifféremment

### Contrôle d'accès — Tâches surveillées (Politique Allow/Deny)

Le système fonctionne en **deny-by-default** avec accumulation cumulative de droits :

1. **read** — Lecture fichiers, consultation données
2. **write** — Écriture, modification, création
3. **delete** — Suppression, destruction
4. **execute** — Exécution de commandes, scripts, binaires
5. **admin** — Commandes administrateur, configuration système
6. **login** — Authentification SSH, console, connexion
7. **failed_login** — Tentatives échouées (brute force tracker)
8. **backup** — Opérations de sauvegarde
9. **network_access** — Connexions réseau (NIDS)

**Exemple cumul droits :**
```
alice;database;allow;read;2026-01-01;2026-12-31;1
alice;database;allow;write;2026-01-01;2026-12-31;1
alice;database;deny;delete;2026-01-01;2026-12-31;1

→ alice a : read + write, mais PAS delete
```

### Ressources protégées

| Ressource | Domaine | Déclencheur |
|---|---|---|
| `ssh_server` | HIDS | Connexions SSH sshd |
| `file_system` | HIDS | Accès fichiers critiques |
| `user_management` | HIDS | useradd, userdel, passwd |
| `database` | HIDS | mysql, psql, sqlite3 |
| `backup` | HIDS | Sauvegarde, restauration |
| `network_access` | NIDS | Connexions réseau |
| `web_server` | HIDS | Processus nginx, apache |

---

## Sécurité & authentification web

L'accès à l'interface web est protégé par authentification. **Aucune page n'est accessible sans être connecté** (sauf `/login` et `/favicon.ico`).

### Comptes utilisateurs web

Trois rôles existent (modèle `WebUser`) :

| Rôle | Permissions |
|---|---|
| **admin** | Tout : gestion des comptes web, modification de toutes les règles, audit log |
| **analyst** | Modifie les règles HIDS/NIDS, acquitte les alertes, change les paramètres |
| **viewer** | Lecture seule (alertes, intrusions, monitoring) |

### Premier démarrage

Au premier lancement, un compte `admin / admin` est créé automatiquement (avertissement dans les logs).
Pour définir un mot de passe initial sécurisé :

```bash
export IDS_ADMIN_PASSWORD='un-mot-de-passe-fort'
```

**Changement obligatoire** via `/account/password` après la première connexion.

### Protections en place

- **Hash mots de passe** : Werkzeug (PBKDF2-SHA256)
- **Protection CSRF** : token unique par session, vérifié sur tous les POST
- **Rate limiting login** : 5 échecs / 5 min / IP → blocage temporaire
- **Sessions** : HttpOnly, SameSite=Lax, timeout 8h
- **Cookie secure** : activable via `IDS_HTTPS=1` (derrière reverse proxy HTTPS)
- **SECRET_KEY** : depuis `IDS_SECRET_KEY` (sinon généré aléatoire à chaque démarrage)
- **Audit log** : toutes les actions admin sont tracées (`AuditLog` en DB)

### Gestion des comptes web

L'admin accède à `/admin/users` (visible dans le menu Config → Comptes web) pour :

- Créer des utilisateurs avec rôle
- Activer/désactiver un compte
- Voir le journal d'audit (qui a fait quoi, depuis quelle IP, à quelle heure)

---

## Notifications externes

Le Module 4 distribue chaque alerte sur tous les canaux configurés simultanément.
Configuration via la page **Paramètres** (`/ids/settings`) ou directement dans `ids_config.json`.

### Canaux supportés

| Canal | Format | Configuration |
|---|---|---|
| **Email SMTP** | Texte brut (alerte formatée) | host, port, user, password, from, to, tls |
| **Slack** | Block Kit (couleurs par sévérité) | `slack_webhook` |
| **Discord** | Embed (couleurs par sévérité) | `discord_webhook` |
| **MS Teams** | MessageCard | `teams_webhook` |
| **Syslog** | RFC 3164 UDP → SIEM | `syslog.host`, `syslog.port` (défaut 514) |

### Filtre par sévérité

Le paramètre `min_severity` détermine la sévérité minimale pour notifier (low / medium / high / critical).

Exemple : `min_severity=high` → seules les alertes high et critical déclenchent les webhooks (le stockage local DB et fichier garde tout).

### Exemple `ids_config.json` complet

```json
{
  "smtp": {
    "host": "smtp.gmail.com", "port": 587, "tls": true,
    "user": "ids@example.com", "password": "...",
    "from": "ids@example.com", "to": "soc@example.com"
  },
  "slack_webhook": "https://hooks.slack.com/services/T00/B00/XYZ",
  "discord_webhook": "https://discord.com/api/webhooks/123/abc",
  "teams_webhook": "https://outlook.office.com/webhook/...",
  "min_severity": "high",
  "syslog": { "host": "splunk.internal", "port": 514 }
}
```

La configuration est rechargée automatiquement toutes les 60 secondes (pas besoin de redémarrer).

---

## Ressources & modèle d'accès

Une **ressource** est un actif/objet protégé que l'IDS surveille. C'est le « **sur QUOI** » dans le modèle de sécurité.

Chaque événement est représenté par un triplet :

> **QUI** (`username`) fait **QUOI** (`task`) sur **QUELLE RESSOURCE** (`resource`)

Exemple : `roberto` — `failed_login` — sur `ssh_server`.

La ressource sert à trois choses :

1. **Étiqueter les événements** — le collecteur (Module 1) associe une ressource à chaque activité détectée.
2. **Écrire les politiques** — chaque règle `allow`/`deny`/`detect` est définie *par ressource* (ex. « 5 `failed_login` sur `ssh_server` en 5 s = brute force »).
3. **Relier** ce qui se passe (événement) à ce qui est autorisé (policy).

### Liste canonique des ressources

> ⚠️ **Important** : ces noms doivent correspondre **exactement** entre le collecteur (`module1_collector.py`) et la table `resource` (seed dans `app.py`). Un nom divergent fait qu'un événement ne matche **aucune** policy ni pattern. Le collecteur est la source de vérité.

| Ressource | Représente |
|---|---|
| `system` | Le système d'exploitation (exécution de commandes) |
| `ssh_server` | Accès SSH |
| `web_server` | Serveur web |
| `database` | Base de données |
| `file_system` | Système de fichiers (lecture/écriture/suppression) |
| `user_management` | Gestion des comptes utilisateurs |
| `network_scanner` | Activité réseau / scan de ports |
| `email_server` | Serveur de messagerie |
| `firewall` | Pare-feu |
| `registry` | Registre Windows (HIDS Windows) |

### Mapping commande → ressource

Pour les événements système (auditd / Sysmon), la fonction `_cmd_to_resource()` déduit la ressource à partir de la commande exécutée :

| Commande détectée | Ressource |
|---|---|
| `mysql`, `psql`, `sqlite3`, `mongod`, `redis-cli` | `database` |
| `nginx`, `apache2`, `httpd`, `flask` | `web_server` |
| `sendmail`, `postfix`, `dovecot`, `mail` | `email_server` |
| `useradd`, `usermod`, `passwd`, `chpasswd` | `user_management` |
| `iptables`, `ufw`, `firewall` | `firewall` |
| (tout le reste) | `system` |

> 🛠️ **Note de cohérence** : auparavant le collecteur émettait deux noms pour le même concept de fichiers (`file_storage` **et** `file_system`), et le seed créait des ressources (`file_storage`) absentes des événements. Tout est désormais unifié sur `file_system`, ce qui débloque les patterns `FILE_READ_FLOOD` / `FILE_DELETE_FLOOD` et `EXEC_FLOOD` / `PRIVESC_ATTEMPT` (ressource `system`).

Les ressources se gèrent dans l'interface web via **IDS → Ressources**.

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

## Variables d'environnement

Toutes les configurations sensibles ou opérationnelles passent par des variables d'environnement.

### Sécurité (auth web)

| Variable | Défaut | Description |
|---|---|---|
| `IDS_SECRET_KEY` | aléatoire (re-généré au boot) | Clé Flask pour signer les sessions. **Fournissez-en une fixe en prod** (`openssl rand -hex 32`) pour ne pas déconnecter les utilisateurs à chaque redémarrage |
| `IDS_ADMIN_PASSWORD` | `admin` | Mot de passe initial du compte admin créé au premier démarrage |
| `IDS_HTTPS` | `0` | Mettre à `1` derrière un reverse proxy HTTPS → cookie session Secure |

### Réseau & process

| Variable | Défaut | Description |
|---|---|---|
| `IDS_BIND` | `0.0.0.0:5000` | Adresse:port d'écoute |
| `IDS_LOG_LEVEL` | `info` | gunicorn loglevel : debug / info / warning / error |
| `IDS_ACCESS_LOG` | `-` (stdout) | Fichier access log gunicorn |
| `IDS_ERROR_LOG` | `-` (stdout) | Fichier error log gunicorn |

### Rétention & maintenance (Module 5)

| Variable | Défaut | Description |
|---|---|---|
| `IDS_ALERT_RETENTION_DAYS` | `30` | Supprime les `Alert` acquittées plus anciennes |
| `IDS_EVENT_RETENTION_DAYS` | `7` | Supprime les `EventEntry` (batch analysis) plus anciens |
| `IDS_ARCHIVE_RETENTION_DAYS` | `90` | Supprime les fichiers `.gz` plus anciens (events/alerts) |
| `IDS_AUDIT_RETENTION_DAYS` | `180` | Supprime les `AuditLog` plus anciens |
| `IDS_COMPRESS_AFTER_DAYS` | `2` | Compresse en `.gz` les fichiers events/alerts plus anciens |
| `IDS_MAINTENANCE_INTERVAL` | `3600` | Intervalle (s) entre deux passes du Module 5 |

### Exemple de fichier `/etc/ids_web/env`

```bash
IDS_SECRET_KEY=fd83c1a8e7b9...  # openssl rand -hex 32
IDS_ADMIN_PASSWORD=mon-mot-de-passe-fort
IDS_HTTPS=1
IDS_BIND=127.0.0.1:5000  # derrière nginx
IDS_ALERT_RETENTION_DAYS=60
IDS_LOG_LEVEL=warning
```

À charger dans systemd : `EnvironmentFile=/etc/ids_web/env`.

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

### Installation automatique Linux (recommandée)

Le projet fournit un script d'installation production qui :
- Installe auditd, libpcap, dépendances pip
- Copie l'app dans `/opt/ids_web/`
- Configure auditd avec les règles IDS
- Génère un `SECRET_KEY` aléatoire + mot de passe admin fort
- Crée le service systemd
- Démarre l'IDS

```bash
sudo ./deploy/install.sh
```

À la fin, le script affiche le mot de passe admin généré (aussi sauvegardé dans `/opt/ids_web/.secrets`).

### Installation manuelle Linux (gunicorn + systemd)

```bash
# 1. Copier le projet
sudo cp -r . /opt/ids_web

# 2. Installer les dépendances
sudo pip3 install -r /opt/ids_web/requirements.txt

# 3. Configurer auditd
sudo cp /opt/ids_web/ids_audit.rules /etc/audit/rules.d/ids.rules
sudo augenrules --load

# 4. Personnaliser le service systemd (changer SECRET_KEY et password)
sudo cp /opt/ids_web/deploy/ids-web.service /etc/systemd/system/
sudo nano /etc/systemd/system/ids-web.service  # éditer les Environment=

# 5. Activer et démarrer
sudo systemctl daemon-reload
sudo systemctl enable --now ids-web

# 6. Vérifier
sudo systemctl status ids-web
sudo journalctl -u ids-web -f
```

Le service est servi par **gunicorn** (production), pas le serveur dev de Flask.
**workers=1 obligatoire** (les démons IDS partagent des threads/queues en mémoire — plusieurs workers causeraient des doublons d'alertes).

### Installation Windows

```powershell
# Exécuter en Administrateur
powershell -ExecutionPolicy Bypass -File deploy\install-windows.ps1
```

Le script vérifie/installe :
- **Sysmon** (équivalent auditd Windows) — manuel depuis https://docs.microsoft.com/sysinternals/downloads/sysmon
- **npcap** (capture réseau scapy) — manuel depuis https://npcap.com/
- Dépendances Python
- Génère secrets aléatoires (stockés en variables d'environnement système)

Pour exécuter en service Windows, utiliser [NSSM](https://nssm.cc/) :

```cmd
nssm install IDS_Web "C:\Python\python.exe" "C:\Program Files\IDS_Web\app.py"
nssm start IDS_Web
```

### Déploiement Docker

```bash
# Build
docker build -t ids-web .

# Run (network=host requis pour scapy sniffer)
docker run -d --name ids-web \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --network host \
  -e IDS_SECRET_KEY=$(openssl rand -hex 32) \
  -e IDS_ADMIN_PASSWORD='choose-a-strong-pwd' \
  -v $(pwd)/instance:/app/instance \
  -v $(pwd)/events:/app/events \
  -v $(pwd)/alerts:/app/alerts \
  -v /var/log:/var/log:ro \
  ids-web
```

Image basée sur `python:3.12-slim` avec healthcheck intégré.

### Reverse proxy nginx (HTTPS recommandé)

```nginx
server {
    listen 443 ssl http2;
    server_name ids.example.com;

    ssl_certificate     /etc/letsencrypt/live/ids.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ids.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

N'oubliez pas `IDS_HTTPS=1` côté IDS pour activer le cookie session `Secure`.

### Dépendances Python

Voir `requirements.txt`. Versions minimales :

```
Flask>=3.1.0
Flask-SQLAlchemy>=3.1.1
Werkzeug>=3.0
scapy>=2.6.1          # capture réseau (Linux + Windows avec npcap)
psutil>=5.9.0         # surveillance des processus
gunicorn>=23.0.0      # serveur WSGI production Linux
```

---

## Améliorations prévues

### Déjà implémentées dans cette version

- ✅ **Auditd Linux** — 11 règles surveillant exec en root, fichiers critiques, gestion users
- ✅ **Sysmon Windows** — équivalent auditd via journal Sysmon (Events 1, 3, 7, 11, 12, 13, 22, 25)
- ✅ **Persistence Linux** — cron, systemd, init.d, profile.d, /root/.ssh
- ✅ **Persistence Windows** — registre (Run, Winlogon, IFEO...) + services (binPath suspects)
- ✅ **SUID Monitor Linux** — détection d'escalade de privilèges
- ✅ **NIDS avancé** — IPv6, JA3 fingerprinting, DNS tunneling
- ✅ **Authentification web** — Werkzeug + CSRF + audit log + 3 rôles
- ✅ **Notifications externes** — Slack, Discord, Teams, Syslog vers SIEM
- ✅ **Pagination + filtres + export CSV** sur alertes et intrusions
- ✅ **Rétention configurable** — purge auto DB + compression gzip + suppression archives
- ✅ **Déploiement** — gunicorn + systemd + Dockerfile + scripts install

### Restantes

**Corrélation IP → Utilisateur**
Le Module 1 collecte des événements réseau où `username` est l'adresse IP source. Une table de corrélation basée sur les sessions SSH/RDP actives permettrait de lier une IP à un utilisateur authentifié pour une détection plus précise.

**Restriction par jour de la semaine**
Le format `policy.conf` supporte les plages de dates et d'heures, mais pas encore les jours de la semaine. Ajouter un champ `jours` (ex : `LUN-VEN`) permettrait : "alice peut accéder à la base uniquement en semaine, 8h-18h".

**Analyse inotify en temps réel**
Le Module 2 relit les fichiers d'événements toutes les 3 secondes par polling. Remplacer par `inotify` (Linux) / `ReadDirectoryChangesW` (Windows) permettrait une réaction instantanée.

**Réduction des faux positifs ProcessMonitor**
Système de liste blanche par utilisateur (`alice` est autorisée à lancer `python3`) pour éviter les alertes non pertinentes.

**Logs applicatifs**
Lecture de `/var/log/nginx/access.log`, `/var/log/apache2/access.log`, `/var/log/mysql/mysql.log` pour détecter les attaques applicatives sans dépendre de la capture réseau.

**Threat intelligence**
Enrichissement automatique des IP sources via AbuseIPDB, AlienVault OTX, GeoIP (Maxmind) pour contextualiser les alertes NIDS.

**Règles réseau avec regex**
Les règles NIDS fichier acceptent des sous-chaînes (`payload_pattern`). Étendre pour supporter des regex complètes sur le payload.

**Dashboard graphique temps réel**
Charts temps réel (Chart.js) sur le tableau de bord pour visualiser l'évolution des alertes par sévérité, par heure, par source.
