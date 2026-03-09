#!/bin/bash
# ============================================================
# deploy-admin.sh — System-wide install with dconf lockdown
# Must be run as root/sudo by IT admin
# ============================================================

set -e

EXT_UUID="sensitive-ss@security.local"
SYSTEM_EXT_DIR="/usr/share/gnome-shell/extensions/$EXT_UUID"
SCHEMA_DIR="/usr/share/glib-2.0/schemas"
DCONF_PROFILE="/etc/dconf/profile/user"
DCONF_DEFAULTS="/etc/dconf/db/local.d/01-sensitive-ss"
DCONF_LOCKS="/etc/dconf/db/local.d/locks/sensitive-ss"
LOG_DIR="/var/log"
LOG_FILE="$LOG_DIR/sensitive-ss.log"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

echo "==> Deploying sensitive-ss extension system-wide..."

# --- Build for current GNOME version ---
bash "$SCRIPT_DIR/build.sh"

# --- Install extension files ---
mkdir -p "$SYSTEM_EXT_DIR/schemas"
cp "$SCRIPT_DIR/metadata.json" "$SYSTEM_EXT_DIR/"
cp "$SCRIPT_DIR/extension.js" "$SYSTEM_EXT_DIR/"
cp "$SCRIPT_DIR/schemas/"*.xml "$SYSTEM_EXT_DIR/schemas/"

# --- Install and compile schema system-wide ---
cp "$SCRIPT_DIR/schemas/"*.xml "$SCHEMA_DIR/"
glib-compile-schemas "$SCHEMA_DIR/"
echo "    Schema compiled."

# --- Set up log file with correct permissions ---
touch "$LOG_FILE"
chmod 662 "$LOG_FILE"
chown root:adm "$LOG_FILE"
echo "    Log file: $LOG_FILE"

# --- Configure dconf profile ---
if [ ! -f "$DCONF_PROFILE" ]; then
    mkdir -p "$(dirname "$DCONF_PROFILE")"
    cat > "$DCONF_PROFILE" <<EOF
user-db:user
system-db:local
EOF
    echo "    Created dconf profile."
else
    if ! grep -q "system-db:local" "$DCONF_PROFILE"; then
        echo "system-db:local" >> "$DCONF_PROFILE"
        echo "    Added system-db:local to dconf profile."
    fi
fi

# --- Set admin defaults ---
mkdir -p "$(dirname "$DCONF_DEFAULTS")"
cat > "$DCONF_DEFAULTS" <<EOF
[org/gnome/shell/extensions/sensitive-ss]
sensitive-patterns=['app.example.com', 'Admin Dashboard']
ignore-patterns=['Google Search', '- Google -', 'google.com/search']
log-path='$LOG_FILE'
warning-duration=5
EOF
echo "    dconf defaults written."
echo "    IMPORTANT: Edit $DCONF_DEFAULTS to set your actual patterns before running dconf update."

# --- Lock down sensitive-patterns and ignore-patterns ---
mkdir -p "$(dirname "$DCONF_LOCKS")"
cat > "$DCONF_LOCKS" <<EOF
/org/gnome/shell/extensions/sensitive-ss/sensitive-patterns
/org/gnome/shell/extensions/sensitive-ss/ignore-patterns
EOF
echo "    dconf locks applied (patterns and ignore list are read-only for users)."

# --- Update dconf database ---
dconf update
echo "    dconf database updated."

echo ""
echo "==> Deployment complete!"
echo ""
echo "Admin commands:"
echo ""
echo "  Update patterns:"
echo "    Edit: $DCONF_DEFAULTS"
echo "    Then run: sudo dconf update"
echo ""
echo "  View current config:"
echo "    gsettings get org.gnome.shell.extensions.sensitive-ss sensitive-patterns"
echo ""
echo "  Enable for all users (each user runs):"
echo "    gnome-extensions enable $EXT_UUID"
echo ""
echo "  SIEM agent config — add log source:"
echo "    <localfile>"
echo "      <location>$LOG_FILE</location>"
echo "      <log_format>json</log_format>"
echo "    </localfile>"
