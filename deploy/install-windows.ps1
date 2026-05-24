# ═══════════════════════════════════════════════════════════════════════════
# IDS Web — Installation Windows (PowerShell, exécuter en Admin)
#
# Usage : powershell -ExecutionPolicy Bypass -File deploy\install-windows.ps1
#
# Ce script :
#   1. Installe Python et les dépendances pip
#   2. Vérifie/installe Sysmon (équivalent auditd)
#   3. Vérifie/installe npcap (capture réseau)
#   4. Génère les secrets
#   5. Crée un service Windows via NSSM (optionnel)
# ═══════════════════════════════════════════════════════════════════════════

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$InstallDir = 'C:\Program Files\IDS_Web'
$SourceDir  = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "═══════════════════════════════════════════════════════"
Write-Host "  IDS Web — Installation Windows"
Write-Host "═══════════════════════════════════════════════════════"
Write-Host "  Source : $SourceDir"
Write-Host "  Cible  : $InstallDir"
Write-Host "═══════════════════════════════════════════════════════"

# 1. Vérifier Python 3
Write-Host "`n[1/5] Vérification de Python..."
try {
    $pyVersion = python --version 2>&1
    Write-Host "  ✓ $pyVersion"
} catch {
    Write-Host "  ✗ Python non installé."
    Write-Host "    Téléchargez : https://www.python.org/downloads/"
    exit 1
}

# 2. Vérifier Sysmon
Write-Host "`n[2/5] Vérification de Sysmon..."
$sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if ($sysmon -and $sysmon.Status -eq 'Running') {
    Write-Host "  ✓ Sysmon installé et en cours d'exécution"
} else {
    Write-Host "  ⚠️  Sysmon non installé (recommandé pour HIDS Windows complet)"
    Write-Host "    Téléchargez : https://docs.microsoft.com/sysinternals/downloads/sysmon"
    Write-Host "    Installez : Sysmon64.exe -accepteula -i sysmonconfig.xml"
}

# 3. Vérifier npcap
Write-Host "`n[3/5] Vérification de npcap..."
if (Test-Path 'C:\Windows\System32\Npcap') {
    Write-Host "  ✓ npcap installé"
} else {
    Write-Host "  ⚠️  npcap non installé (REQUIS pour la capture réseau NIDS)"
    Write-Host "    Téléchargez : https://npcap.com/"
}

# 4. Copier l'application
Write-Host "`n[4/5] Copie de l'application..."
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}
Copy-Item -Path "$SourceDir\*" -Destination $InstallDir -Recurse -Force
New-Item -ItemType Directory -Path "$InstallDir\instance" -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\events"   -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\alerts"   -Force | Out-Null

# Installer les dépendances Python
Write-Host "  Installation des dépendances Python..."
python -m pip install -q -r "$InstallDir\requirements.txt"

# 5. Générer secrets
Write-Host "`n[5/5] Génération des secrets..."
$secretKey = -join ((1..64) | ForEach-Object {Get-Random -Maximum 16 | ForEach-Object {'{0:x}' -f $_}})
$adminPwd  = -join ((33..126) | Get-Random -Count 20 | ForEach-Object {[char]$_})

# Sauver les secrets
$secretsFile = "$InstallDir\.secrets.txt"
@"
# IDS Web — Secrets de première installation
# Date : $(Get-Date)

IDS_SECRET_KEY=$secretKey
IDS_ADMIN_PASSWORD=$adminPwd

# Première connexion :
#   Username : admin
#   Password : $adminPwd
"@ | Out-File -FilePath $secretsFile -Encoding UTF8

# Variables d'environnement système
[Environment]::SetEnvironmentVariable('IDS_SECRET_KEY',     $secretKey, 'Machine')
[Environment]::SetEnvironmentVariable('IDS_ADMIN_PASSWORD', $adminPwd,  'Machine')

Write-Host "`n═══════════════════════════════════════════════════════"
Write-Host "  ✓ Installation terminée"
Write-Host "═══════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Lancement manuel :"
Write-Host "    cd '$InstallDir'"
Write-Host "    python app.py"
Write-Host ""
Write-Host "  Première connexion :"
Write-Host "    URL      : http://localhost:5000"
Write-Host "    Username : admin"
Write-Host "    Password : $adminPwd"
Write-Host ""
Write-Host "  Secrets sauvegardés : $secretsFile"
Write-Host ""
Write-Host "  Pour créer un service Windows :"
Write-Host "    Utilisez NSSM (https://nssm.cc/) :"
Write-Host "    nssm install IDS_Web 'C:\Python\python.exe' '$InstallDir\app.py'"
Write-Host "    nssm start IDS_Web"
