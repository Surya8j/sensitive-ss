# sensitive-ss — GNOME Shell Topbar Extension

Detects screenshot activity when sensitive sites are visible in any browser window across all monitors. Changes the topbar icon from `:)` to `:(` in red and logs JSON events for SIEM ingestion.

## How It Works

```
┌──────────────────────────────────────────────────┐
│                  GNOME Shell                      │
│                                                  │
│  1. Listens for window-created signal            │
│  2. If new window is a screenshot tool →         │
│  3. Scan visible browser windows on active        │
│     workspace (all monitors)                     │
│  4. Match titles against sensitive-patterns       │
│  5. Skip if title matches ignore-patterns         │
│  6. If match → change icon to :(  + log event    │
│                                                  │
│  Topbar:  :)  →  :(  (red, 5s)  →  :)           │
└──────────────────────────────────────────────────┘
                      │
                      ▼
            events.log (JSON)
                      │
                      ▼
              ┌──────────────┐
              │  SIEM Agent  │
              └──────────────┘
```

## Detection

**Screenshot tools detected** (via window-created signal):
flameshot, gnome-screenshot, spectacle, ksnip, shutter, peek, kazam, obs, simplescreenrecorder, scrot, maim

**Browsers supported:**
Firefox, Chrome/Chromium, Brave, Vivaldi, Opera, Edge, Zen, LibreWolf, Waterfox, Thorium

## What Gets Scanned

- Only **visible browser windows** on the **active workspace** across all monitors
- Only the **active tab** per browser window (background tabs are not visible to GNOME Shell)
- **Minimized windows** are skipped
- **Other workspaces** are skipped

## GNOME Version Support

The extension supports both legacy (GNOME 42–44) and ESM (GNOME 45+) formats. The `build.sh` script auto-detects your version and generates the correct `extension.js`.

```bash
./build.sh        # auto-detect
./build.sh 42     # force legacy
./build.sh 46     # force ESM
```

## Install — Local Testing (no sudo)

```bash
tar xzf sensitive-ss@security.local.tar.gz
cd sensitive-ss@security.local
chmod +x install-local.sh build.sh
./install-local.sh
```

Restart GNOME Shell (Alt+F2 → `r` → Enter), then enable:

```bash
gnome-extensions enable sensitive-ss@security.local
```

Configure patterns:

```bash
SD="--schemadir $HOME/.local/share/gnome-shell/extensions/sensitive-ss@security.local/schemas/"
S="org.gnome.shell.extensions.sensitive-ss"

# Set sensitive patterns
gsettings $SD set $S sensitive-patterns "['App Dashboard', 'admin.example.com']"

# View current
gsettings $SD get $S sensitive-patterns

# View ignore patterns (defaults include Google Search)
gsettings $SD get $S ignore-patterns
```

Log location: `~/.local/share/sensitive-ss/events.log`

### Configure Patterns (local)

```bash
SD="--schemadir $HOME/.local/share/gnome-shell/extensions/sensitive-ss@security.local/schemas/"
S="org.gnome.shell.extensions.sensitive-ss"

# View
gsettings $SD get $S sensitive-patterns
gsettings $SD get $S ignore-patterns

# Set (replace all)
gsettings $SD set $S sensitive-patterns "['App Dashboard', 'admin.example.com']"
gsettings $SD set $S ignore-patterns "['Google Search', '- Google -']"

# Add (copy current list, append new entry)
gsettings $SD set $S sensitive-patterns "['App Dashboard', 'admin.example.com', 'new.portal.com']"

# Remove (rewrite without the entry)
gsettings $SD set $S sensitive-patterns "['App Dashboard']"

# Clear all
gsettings $SD set $S sensitive-patterns "[]"
```

No GNOME restart needed — changes apply on the next detection.

### Uninstall (local)

```bash
gnome-extensions disable sensitive-ss@security.local
rm -rf ~/.local/share/gnome-shell/extensions/sensitive-ss@security.local
rm -rf ~/.local/share/sensitive-ss
```

Restart GNOME Shell (Alt+F2 → `r` → Enter).

## Deploy — Production (admin/sudo)

```bash
sudo chmod +x deploy-admin.sh build.sh
sudo ./deploy-admin.sh
```

This will:
1. Auto-detect GNOME version and build the correct extension
2. Install extension system-wide
3. Compile GSettings schema
4. Set dconf defaults for patterns
5. **Lock** `sensitive-patterns` and `ignore-patterns` so users cannot modify them
6. Create log file with proper permissions

### Update patterns (admin only)

Edit `/etc/dconf/db/local.d/01-sensitive-ss`:

```ini
[org/gnome/shell/extensions/sensitive-ss]
sensitive-patterns=['App Dashboard', 'admin.example.com']
ignore-patterns=['Google Search', '- Google -', 'google.com/search']
```

Then apply:

```bash
sudo dconf update
```

Users cannot modify `sensitive-patterns` or `ignore-patterns` after lockdown.

### Add/remove patterns (admin)

Edit `/etc/dconf/db/local.d/01-sensitive-ss`, update the arrays, then:

```bash
sudo dconf update
```

### View current config (admin)

```bash
gsettings get org.gnome.shell.extensions.sensitive-ss sensitive-patterns
gsettings get org.gnome.shell.extensions.sensitive-ss ignore-patterns
```

### Uninstall (admin)

```bash
# Remove extension
sudo rm -rf /usr/share/gnome-shell/extensions/sensitive-ss@security.local

# Remove schema
sudo rm /usr/share/glib-2.0/schemas/org.gnome.shell.extensions.sensitive-ss.gschema.xml
sudo glib-compile-schemas /usr/share/glib-2.0/schemas/

# Remove dconf config and locks
sudo rm /etc/dconf/db/local.d/01-sensitive-ss
sudo rm /etc/dconf/db/local.d/locks/sensitive-ss
sudo dconf update

# Remove log file
sudo rm /var/log/sensitive-ss.log
```

Each user should also run:

```bash
gnome-extensions disable sensitive-ss@security.local
```

## SIEM Integration

The extension logs JSON events to a file that any SIEM can ingest.

1. Copy `siem-rules/sensitive_ss.xml` to your SIEM rules directory (sample rules provided)

2. Configure your SIEM agent to monitor the log file:

```
Location: /var/log/sensitive-ss.log       (production)
          ~/.local/share/sensitive-ss/events.log  (local testing)
Format:   JSON (one event per line)
```

3. Restart your SIEM agent after configuration

### Alert Levels (sample rules)

| Rule ID | Level | Trigger |
|---------|-------|---------|
| 100800  | 10    | Single screenshot on sensitive site |
| 100801  | 12    | 3+ screenshots in 5 minutes (same user) |
| 100802  | 12    | Screen recording tool (obs, kazam, etc.) |

## Log Format

```json
{
  "timestamp": "2026-03-09T14:30:22.123Z",
  "event_type": "screenshot_on_sensitive_site",
  "hostname": "dev-laptop",
  "user": "john",
  "detection_source": "window_monitor",
  "detection_tool": "flameshot",
  "sensitive_windows": [
    {
      "title": "Dashboard - Admin Portal - Google Chrome",
      "browser": "Google-chrome",
      "match_type": "pattern",
      "match_value": "admin portal"
    }
  ]
}
```

## GSettings Keys

| Key | Type | Default | Locked in prod |
|-----|------|---------|----------------|
| `sensitive-patterns` | string array | `[]` | Yes |
| `ignore-patterns` | string array | `['Google Search', '- Google -', 'google.com/search']` | Yes |
| `log-path` | string | `~/.local/share/sensitive-ss/events.log` | No |
| `warning-duration` | int | `5` (seconds) | No |

## Project Structure

```
sensitive-ss@security.local/
├── build.sh                    # Auto-detects GNOME version, generates extension.js
├── install-local.sh            # Testing (no sudo)
├── deploy-admin.sh             # Production (sudo + dconf lockdown)
├── extension.js                # Generated by build.sh
├── metadata.json               # Updated by build.sh
├── schemas/                    # GSettings schema
├── src/
│   ├── extension-legacy.js     # GNOME 42–44
│   └── extension-esm.js        # GNOME 45+
└── siem-rules/
    └── sensitive_ss.xml        # Sample SIEM rules
```

## Requirements

- GNOME Shell 42+ (tested on 42–47)
- No external dependencies
