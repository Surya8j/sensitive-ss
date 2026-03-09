#!/bin/bash
# ============================================================
# install-local.sh — Install extension for testing (no sudo)
# ============================================================

set -e

EXT_UUID="sensitive-ss@security.local"
EXT_DIR="$HOME/.local/share/gnome-shell/extensions/$EXT_UUID"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Build for current GNOME version
echo "==> Building extension for your GNOME version..."
bash "$SCRIPT_DIR/build.sh"

echo "==> Installing sensitive-ss extension locally..."

# Create extension directory
mkdir -p "$EXT_DIR/schemas"

# Copy files
cp "$SCRIPT_DIR/metadata.json" "$EXT_DIR/"
cp "$SCRIPT_DIR/extension.js" "$EXT_DIR/"
cp "$SCRIPT_DIR/schemas/"*.xml "$EXT_DIR/schemas/"

# Compile schemas locally
echo "==> Compiling GSettings schemas..."
glib-compile-schemas "$EXT_DIR/schemas/"

# Create log directory
mkdir -p "$HOME/.local/share/sensitive-ss"

echo ""
echo "==> Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Restart GNOME Shell:"
echo "     - X11:    Alt+F2 → type 'r' → Enter"
echo "     - Wayland: Log out and log back in"
echo ""
echo "  2. Enable the extension:"
echo "     gnome-extensions enable $EXT_UUID"
echo ""
echo "  3. Verify it's running (look for ':)' in topbar)"
echo ""
echo "  4. Configure sensitive patterns for testing:"
echo "     gsettings --schemadir \$HOME/.local/share/gnome-shell/extensions/$EXT_UUID/schemas/ set org.gnome.shell.extensions.sensitive-ss sensitive-patterns \"['App Dashboard', 'admin.example.com']\""
echo ""
echo "  5. Test: open a browser tab matching your configured"
echo "     patterns, then take a screenshot."
echo ""
echo "Log file: ~/.local/share/sensitive-ss/events.log"
