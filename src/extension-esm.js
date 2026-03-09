/**
 * sensitive-ss — GNOME Shell Topbar Extension
 *
 * Detects screenshot activity when any browser window (across all monitors)
 * shows a sensitive site. Uses window-created signal to detect screenshot
 * tool windows appearing.
 *
 * Displays a topbar warning and logs JSON events for SIEM ingestion.
 *
 * Target: GNOME 45+ (ESM format)
 */

import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import Gio from 'gi://Gio';
import St from 'gi://St';
import Clutter from 'gi://Clutter';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const SCREENSHOT_WM_CLASSES = [
    'flameshot',
    'gnome-screenshot',
    'screenshot',
    'spectacle',
    'ksnip',
    'shutter',
    'peek',
    'kazam',
    'obs',
    'simplescreenrecorder',
    'scrot',
    'maim',
];

const BROWSER_WM_CLASSES = [
    'firefox',
    'google-chrome',
    'chromium',
    'brave',
    'vivaldi',
    'opera',
    'microsoft-edge',
    'zen',
    'librewolf',
    'waterfox',
    'thorium',
];

/* ------------------------------------------------------------------ */
/*  Indicator (topbar button)                                          */
/* ------------------------------------------------------------------ */

const ScreenshotIndicator = GObject.registerClass(
class ScreenshotIndicator extends PanelMenu.Button {

    _init(settings) {
        super._init(0.0, 'sensitive-ss');

        this._settings = settings;
        this._dismissTimeoutId = null;
        this._windowSignalId = null;
        this._isWarning = false;
        this._logPath = null;
        this._lastTriggerTime = 0;

        this._resolveLogPath();

        this._box = new St.BoxLayout({
            style_class: 'panel-status-menu-box',
        });

        this._icon = new St.Label({
            text: ':)',
            y_align: Clutter.ActorAlign.CENTER,
            style: 'font-weight: bold; font-size: 14px; color: #aaaaaa;',
        });

        this._box.add_child(this._icon);
        this.add_child(this._box);

        this._startWindowMonitor();
    }

    _resolveLogPath() {
        let configuredPath = this._settings.get_string('log-path');
        if (configuredPath && configuredPath.length > 0) {
            this._logPath = configuredPath;
        } else {
            const dataDir = GLib.build_filenamev([
                GLib.get_home_dir(), '.local', 'share', 'sensitive-ss',
            ]);
            GLib.mkdir_with_parents(dataDir, 0o755);
            this._logPath = GLib.build_filenamev([dataDir, 'events.log']);
        }
    }

    _startWindowMonitor() {
        const display = global.display;

        this._windowSignalId = display.connect('window-created', (display, metaWindow) => {
            if (!metaWindow) return;

            const wmClass = (metaWindow.get_wm_class() || '').toLowerCase();
            const title = (metaWindow.get_title() || '').toLowerCase();

            let detectedTool = null;
            for (let i = 0; i < SCREENSHOT_WM_CLASSES.length; i++) {
                if (wmClass.indexOf(SCREENSHOT_WM_CLASSES[i]) !== -1 ||
                    title.indexOf(SCREENSHOT_WM_CLASSES[i]) !== -1) {
                    detectedTool = SCREENSHOT_WM_CLASSES[i];
                    break;
                }
            }

            if (detectedTool) {
                this._onScreenshotDetected('window_monitor', detectedTool);
            }
        });
    }

    _onScreenshotDetected(source, tool) {
        const now = GLib.get_monotonic_time();
        if (this._lastTriggerTime && (now - this._lastTriggerTime) < 3000000) {
            return;
        }
        this._lastTriggerTime = now;

        const sensitiveWindows = this._findSensitiveBrowserWindows();
        if (sensitiveWindows.length === 0) return;

        const sensWindows = [];
        for (let i = 0; i < sensitiveWindows.length; i++) {
            sensWindows.push({
                title: sensitiveWindows[i].title,
                browser: sensitiveWindows[i].wmClass,
                match_type: sensitiveWindows[i].matchType,
                match_value: sensitiveWindows[i].matchValue,
            });
        }

        const event = {
            timestamp: new Date().toISOString(),
            event_type: 'screenshot_on_sensitive_site',
            hostname: GLib.get_host_name(),
            user: GLib.get_user_name(),
            detection_source: source,
            detection_tool: tool,
            sensitive_windows: sensWindows,
        };

        this._showWarning();
        this._logEvent(event);
    }

    _findSensitiveBrowserWindows() {
        const matches = [];
        const actors = global.get_window_actors();

        const patterns = this._settings.get_strv('sensitive-patterns')
            .map(p => p.toLowerCase());
        const ignorePatterns = this._settings.get_strv('ignore-patterns')
            .map(p => p.toLowerCase());

        if (patterns.length === 0)
            return matches;

        const activeWorkspace = global.workspace_manager.get_active_workspace();

        for (let i = 0; i < actors.length; i++) {
            const actor = actors[i];
            const metaWindow = actor.get_meta_window();
            if (!metaWindow) continue;

            if (!metaWindow.is_on_all_workspaces() &&
                metaWindow.get_workspace() !== activeWorkspace) {
                continue;
            }

            if (metaWindow.minimized) continue;

            const wmClass = (metaWindow.get_wm_class() || '').toLowerCase();
            let isBrowser = false;
            for (let b = 0; b < BROWSER_WM_CLASSES.length; b++) {
                if (wmClass.indexOf(BROWSER_WM_CLASSES[b]) !== -1) {
                    isBrowser = true;
                    break;
                }
            }
            if (!isBrowser) continue;

            const title = (metaWindow.get_title() || '').toLowerCase();
            if (!title) continue;

            let ignored = false;
            for (let g = 0; g < ignorePatterns.length; g++) {
                if (title.indexOf(ignorePatterns[g]) !== -1) {
                    ignored = true;
                    break;
                }
            }
            if (ignored) continue;

            for (let p = 0; p < patterns.length; p++) {
                if (title.indexOf(patterns[p]) !== -1) {
                    matches.push({
                        title: metaWindow.get_title(),
                        wmClass: metaWindow.get_wm_class(),
                        matchType: 'pattern',
                        matchValue: patterns[p],
                    });
                    break;
                }
            }
        }

        return matches;
    }

    _showWarning() {
        if (this._dismissTimeoutId) {
            GLib.source_remove(this._dismissTimeoutId);
            this._dismissTimeoutId = null;
        }

        this._isWarning = true;
        this._icon.set_text(':(');
        this._icon.set_style('font-weight: bold; font-size: 14px; color: #ff5555;');

        const durationSec = this._settings.get_int('warning-duration');
        const durationMs = durationSec * 1000;

        this._dismissTimeoutId = GLib.timeout_add(
            GLib.PRIORITY_DEFAULT,
            durationMs,
            () => {
                this._hideWarning();
                this._dismissTimeoutId = null;
                return GLib.SOURCE_REMOVE;
            }
        );
    }

    _hideWarning() {
        this._icon.set_text(':)');
        this._icon.set_style('font-weight: bold; font-size: 14px; color: #aaaaaa;');
        this._isWarning = false;
    }

    _logEvent(event) {
        try {
            const line = JSON.stringify(event) + '\n';
            const file = Gio.File.new_for_path(this._logPath);
            const stream = file.append_to(
                Gio.FileCreateFlags.NONE,
                null
            );
            const bytes = new GLib.Bytes(line);
            stream.write_bytes(bytes, null);
            stream.close(null);
        } catch (e) {
            console.error('[sensitive-ss] Failed to write log: ' + e.message);
        }
    }

    destroy() {
        if (this._windowSignalId) {
            global.display.disconnect(this._windowSignalId);
            this._windowSignalId = null;
        }
        if (this._dismissTimeoutId) {
            GLib.source_remove(this._dismissTimeoutId);
            this._dismissTimeoutId = null;
        }
        super.destroy();
    }
});

/* ------------------------------------------------------------------ */
/*  Extension entry point (GNOME 45+ ESM)                              */
/* ------------------------------------------------------------------ */

export default class SensitiveSSExtension extends Extension {

    enable() {
        this._settings = this.getSettings();
        this._indicator = new ScreenshotIndicator(this._settings);
        Main.panel.addToStatusArea(this.metadata.uuid, this._indicator);
    }

    disable() {
        if (this._indicator) {
            this._indicator.destroy();
            this._indicator = null;
        }
        this._settings = null;
    }
}
