#!/usr/bin/env bash
# =============================================================================
#  IDS Web — Script d'installation pour Ubuntu / Debian
# =============================================================================
#  Usage :
#     chmod +x install.sh
#     ./install.sh                 # installation interactive
#     sudo ./install.sh --auto     # installation automatique (production)
#
#  Ce script :
#    1. Installe les dépendances système (python3, libpcap, auditd, etc.)
#    2. Crée un environnement virtuel Python
#    3. Installe toutes les dépendances Python
#    4. Initialise la base SQLite + utilisateur admin par défaut
#    5. (Optionnel) Installe un service systemd
# =============================================================================

set -e   # Stop on first error
set -u   # Stop on undefined variable

# ── Couleurs pour l'affichage ───────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Variables ───────────────────────────────────────────────────────────────
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${APP_DIR}/venv"
PYTHON_BIN="python3"
SERVICE_NAME="ids-web"
AUTO_MODE=0

# ── Parse arguments ─────────────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --auto|-y)   AUTO_MODE=1 ;;
        --help|-h)
            grep '^#' "$0" | head -20
            exit 0
            ;;
    esac
done

# ── Helpers ─────────────────────────────────────────────────────────────────
log_info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}      $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*" >&2; }

confirm() {
    if [ "$AUTO_MODE" -eq 1 ]; then return 0; fi
    read -p "$1 [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# ── Bannière ────────────────────────────────────────────────────────────────
cat <<'EOF'

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║         IDS Web — Installation Ubuntu / Debian             ║
║         HIDS + NIDS + Web Dashboard + 2FA TOTP             ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

EOF

log_info "Dossier de l'application : $APP_DIR"

# ── 1. Vérifications de base ────────────────────────────────────────────────
log_info "Étape 1/6 : Vérification de l'environnement"

if [ ! -f "$APP_DIR/app.py" ]; then
    log_error "app.py introuvable dans $APP_DIR"
    log_error "Lance le script depuis le dossier racine de l'application"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    log_warn "Tu n'es pas root. Certaines étapes (apt, systemd) nécessitent sudo."
    log_warn "Le script t'invitera à entrer ton mot de passe sudo si besoin."
fi

# ── 2. Dépendances système ──────────────────────────────────────────────────
log_info "Étape 2/6 : Installation des paquets système"

PKGS=(
    python3 python3-venv python3-pip python3-dev
    libpcap-dev libffi-dev libssl-dev build-essential
    auditd audispd-plugins
    iproute2 net-tools
    sqlite3
    curl git
)

if confirm "Installer les paquets système (apt) ? (~150 Mo)"; then
    sudo apt update
    sudo apt install -y "${PKGS[@]}"
    log_ok "Paquets système installés"
else
    log_warn "Étape système ignorée (suppose déjà installé)"
fi

# ── 3. Environnement virtuel Python ─────────────────────────────────────────
log_info "Étape 3/6 : Création de l'environnement virtuel"

if [ -d "$VENV_DIR" ]; then
    log_warn "venv déjà présent : $VENV_DIR"
    if confirm "Recréer le venv (efface l'existant) ?"; then
        rm -rf "$VENV_DIR"
        $PYTHON_BIN -m venv "$VENV_DIR"
        log_ok "venv recréé"
    fi
else
    $PYTHON_BIN -m venv "$VENV_DIR"
    log_ok "venv créé : $VENV_DIR"
fi

# ── 4. Dépendances Python ───────────────────────────────────────────────────
log_info "Étape 4/6 : Installation des dépendances Python"

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip wheel

if [ -f "$APP_DIR/requirements.txt" ]; then
    pip install -r "$APP_DIR/requirements.txt"
else
    log_warn "requirements.txt absent, installation des deps minimales"
    pip install Flask Flask-SQLAlchemy Werkzeug scapy psutil gunicorn pyotp "qrcode[pil]" requests python-dotenv
fi

log_ok "Dépendances Python installées"

# ── 5. Initialisation de la base de données ────────────────────────────────
log_info "Étape 5/6 : Initialisation de la base SQLite"

cd "$APP_DIR"
"$VENV_DIR/bin/python" - <<'PYEOF'
import sys
sys.path.insert(0, '.')
from app import app, db
with app.app_context():
    db.create_all()
    print("Base de données initialisée (instance/ids.db)")
PYEOF

log_ok "Base SQLite prête"

# ── 6. Service systemd (optionnel) ──────────────────────────────────────────
log_info "Étape 6/6 : Service systemd (optionnel)"

if confirm "Installer un service systemd pour lancer l'IDS au démarrage ?"; then
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=IDS Web — HIDS + NIDS + Dashboard
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment="PATH=${VENV_DIR}/bin:/usr/bin:/bin"
ExecStart=${VENV_DIR}/bin/gunicorn -w 1 -b 0.0.0.0:5000 --timeout 120 app:app
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    log_ok "Service installé : sudo systemctl start $SERVICE_NAME"
fi

# ── Fin ─────────────────────────────────────────────────────────────────────
cat <<EOF

${GREEN}╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                  INSTALLATION TERMINÉE                     ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝${NC}

  Pour lancer l'IDS :

    cd $APP_DIR
    sudo -E $VENV_DIR/bin/gunicorn -w 1 -b 0.0.0.0:5000 --timeout 120 app:app

  Ou avec systemd (si installé) :

    sudo systemctl start $SERVICE_NAME
    sudo systemctl status $SERVICE_NAME

  Interface web :  http://localhost:5000
  Identifiants  :  admin / admin   (à changer immédiatement)

  Logs en temps réel :
    sudo journalctl -u $SERVICE_NAME -f

EOF
