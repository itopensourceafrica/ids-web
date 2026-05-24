#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# IDS Web — Installation Production (Linux)
#
# Usage : sudo ./deploy/install.sh
#
# Ce script :
#   1. Installe les dépendances système (auditd, libpcap, python3-pip)
#   2. Copie l'IDS dans /opt/ids_web
#   3. Installe les dépendances Python
#   4. Configure auditd avec les règles IDS
#   5. Crée le service systemd
#   6. Génère les secrets aléatoires
#   7. Démarre le service
# ═══════════════════════════════════════════════════════════════════════════

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en root (sudo)"
    exit 1
fi

INSTALL_DIR="/opt/ids_web"
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "═══════════════════════════════════════════════════════"
echo "  IDS Web — Installation Production"
echo "═══════════════════════════════════════════════════════"
echo "  Source : $SOURCE_DIR"
echo "  Cible  : $INSTALL_DIR"
echo "═══════════════════════════════════════════════════════"
echo

# 1. Dépendances système
echo "[1/7] Installation des paquets système..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-pip \
    libpcap0.8 libpcap-dev \
    auditd audispd-plugins \
    openssl

# 2. Copier les fichiers
echo "[2/7] Copie de l'application dans $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$SOURCE_DIR/"{app.py,auth.py,models.py,wsgi.py,gunicorn_conf.py,modules,templates,requirements.txt,*.conf,*.rules} \
    "$INSTALL_DIR/" 2>/dev/null || true
mkdir -p "$INSTALL_DIR/instance" "$INSTALL_DIR/events" "$INSTALL_DIR/alerts"
chmod 750 "$INSTALL_DIR/instance"

# 3. Dépendances Python
echo "[3/7] Installation des dépendances Python..."
pip3 install -q --break-system-packages -r "$INSTALL_DIR/requirements.txt" \
    || pip3 install -q -r "$INSTALL_DIR/requirements.txt"

# 4. Configuration auditd
echo "[4/7] Configuration auditd..."
if [ -f "$INSTALL_DIR/ids_audit.rules" ]; then
    cp "$INSTALL_DIR/ids_audit.rules" /etc/audit/rules.d/ids.rules
    augenrules --load 2>/dev/null || auditctl -R "$INSTALL_DIR/ids_audit.rules" 2>/dev/null || true
    systemctl enable auditd
    systemctl restart auditd
fi

# 5. Générer les secrets
echo "[5/7] Génération des secrets..."
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_PWD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)

# Sauver les secrets pour la première connexion
SECRETS_FILE="$INSTALL_DIR/.secrets"
cat > "$SECRETS_FILE" <<EOF
# IDS Web — Secrets de première installation
# Date : $(date)

IDS_SECRET_KEY=$SECRET_KEY
IDS_ADMIN_PASSWORD=$ADMIN_PWD

# Première connexion :
#   Username : admin
#   Password : $ADMIN_PWD
#
# Changez le mot de passe via /account/password après la première connexion.
EOF
chmod 600 "$SECRETS_FILE"

# 6. Service systemd
echo "[6/7] Installation du service systemd..."
# Adapter les variables dans le .service
sed -e "s|CHANGEZ_MOI_PAR_UN_HEX_RANDOM_DE_64_CARACTERES|$SECRET_KEY|" \
    -e "s|CHANGEZ_MOI|$ADMIN_PWD|" \
    "$SOURCE_DIR/deploy/ids-web.service" > /etc/systemd/system/ids-web.service

systemctl daemon-reload
systemctl enable ids-web

# 7. Démarrer
echo "[7/7] Démarrage du service..."
systemctl restart ids-web
sleep 3
systemctl status ids-web --no-pager -l || true

echo
echo "═══════════════════════════════════════════════════════"
echo "  ✓ Installation terminée"
echo "═══════════════════════════════════════════════════════"
echo
echo "  Interface web : http://$(hostname -I | awk '{print $1}'):5000"
echo
echo "  Première connexion :"
echo "    Username : admin"
echo "    Password : $ADMIN_PWD"
echo
echo "  Secrets sauvegardés : $SECRETS_FILE (mode 600)"
echo
echo "  Commandes utiles :"
echo "    sudo systemctl status ids-web"
echo "    sudo journalctl -u ids-web -f"
echo "    sudo systemctl restart ids-web"
echo
