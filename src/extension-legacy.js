/**
 * sensitive-ss — GNOME Shell Topbar Extension
 *
 * Detects screenshot activity when any browser window (across all monitors)
 * shows a sensitive site. Uses window-created signal to detect screenshot
 * tool windows appearing.
 *
 * Displays a topbar warning and logs JSON events for SIEM ingestion.
 *
 * Target: GNOME 42–44 (old-style extension format), Pop!_OS 22.04
 */

'use strict';

const { GLib, GObject, Gio, St, Clutter } = imports.gi;
const Main = imports.ui.main;
const PanelMenu = imports.ui.panelMenu;
const ExtensionUtils = imports.misc.extensionUtils;

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

// WM_CLASS substrings for screenshot tool windows
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

// WM_CLASS substrings that identify browser windows
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

        // --- Resolve log path ---
        this._resolveLogPath();

        // --- Build topbar UI ---
        this._box = new St.BoxLayout({
            style_class: 'panel-status-menu-box',
        });

        // Smiley icon — changes to sad face on alert
        this._icon = new St.Label({
            text: ':)',
            y_align: Clutter.ActorAlign.CENTER,
            style: 'font-weight: bold; font-size: 14px; color: #aaaaaa;',
        });

        this._box.add_child(this._icon);
        this.add_child(this._box);

        // --- Start detection ---
        this._startWindowMonitor();
        this._startScreenshotDBusMonitor();
    }

    /* ----- Log path resolution ----- */

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

    /* ================================================================== */
    /*  DETECTION 1: Window Monitor                                        */
    /*  Fires when a screenshot tool window appears                        */
    /* ================================================================== */

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

    /* ================================================================== */
    /*  DETECTION 2: GNOME Built-in Screenshot (D-Bus)                     */
    /*  Wraps org.gnome.Shell.Screenshot methods                           */
    /*  Catches PrtSc, Alt+PrtSc, Shift+PrtSc                             */
    /* ================================================================== */

    _startScreenshotDBusMonitor() {
        this._dbusPatched = false;
        this._origMethods = {};

        try {
            // Access the Screenshot D-Bus service implementation
            // In GNOME Shell, this is exposed as a global service
            const screenshotService = global.backend.get_dbus_daemon
                ? null  // Not directly accessible, use proxy approach
                : null;

            // Use D-Bus proxy to monitor Screenshot calls
            const bus = Gio.DBus.session;
            const self = this;

            // Monitor D-Bus for Screenshot method calls using a name watcher
            this._dbusWatchId = bus.signal_subscribe(
                null,                                    // sender
                'org.gnome.Shell.Screenshot',            // interface
                null,                                    // member (all signals)
                '/org/gnome/Shell/Screenshot',           // object path
                null,                                    // arg0
                Gio.DBusSignalFlags.NONE,
                function(_connection, _sender, _path, _iface, _signal, _params) {
                    self._onScreenshotDetected('dbus_screenshot', 'gnome-shell-screenshot');
                }
            );

            // Monitor for screenshot/screencast file creation
            // Resolve actual paths at runtime
            this._screenshotMonitors = [];
            const home = GLib.get_home_dir();
            const watchDirsSet = {};  // deduplicate

            // XDG user directories
            try {
                const [okP, outP] = GLib.spawn_command_line_sync('xdg-user-dir PICTURES');
                if (okP) {
                    const p = imports.byteArray.toString(outP).trim();
                    if (p) watchDirsSet[p] = true;
                }
            } catch (_e) { }

            try {
                const [okV, outV] = GLib.spawn_command_line_sync('xdg-user-dir VIDEOS');
                if (okV) {
                    const v = imports.byteArray.toString(outV).trim();
                    if (v) {
                        watchDirsSet[v] = true;
                        // Also watch Screencasts subfolder
                        watchDirsSet[v + '/Screencasts'] = true;
                    }
                }
            } catch (_e) { }

            // Flameshot save path
            try {
                const flameshotIni = GLib.build_filenamev([home, '.config', 'flameshot', 'flameshot.ini']);
                const iniFile = Gio.File.new_for_path(flameshotIni);
                if (iniFile.query_exists(null)) {
                    const [ok, contents] = iniFile.load_contents(null);
                    if (ok) {
                        const text = imports.byteArray.toString(contents);
                        const match = text.match(/savePath=(.+)/);
                        if (match && match[1]) {
                            watchDirsSet[match[1].trim()] = true;
                        }
                    }
                }
            } catch (_e) { }

            // Fallback defaults
            watchDirsSet[GLib.get_tmp_dir()] = true;
            watchDirsSet[GLib.build_filenamev([home, 'Pictures'])] = true;
            watchDirsSet[GLib.build_filenamev([home, 'Pictures', 'Screenshots'])] = true;
            watchDirsSet[GLib.build_filenamev([home, 'Videos'])] = true;
            watchDirsSet[GLib.build_filenamev([home, 'Videos', 'Screencasts'])] = true;

            const watchDirs = Object.keys(watchDirsSet);

            for (let i = 0; i < watchDirs.length; i++) {
                try {
                    const dir = Gio.File.new_for_path(watchDirs[i]);
                    if (!dir.query_exists(null)) continue;

                    const monitor = dir.monitor_directory(
                        Gio.FileMonitorFlags.NONE,
                        null
                    );

                    monitor.connect('changed', (monitor, file, otherFile, eventType) => {
                        if (eventType !== Gio.FileMonitorEvent.CREATED) return;

                        const name = file.get_basename().toLowerCase();

                        // Screenshot files
                        if (name.indexOf('screenshot') !== -1 ||
                            name.match(/\.(png|jpg|jpeg|bmp)$/)) {
                            self._onScreenshotDetected('file_monitor', 'screenshot-file');
                        }

                        // Screencast files
                        if (name.indexOf('screencast') !== -1 ||
                            name.match(/\.(webm|mp4|mkv)$/)) {
                            self._onScreenshotDetected('file_monitor', 'screencast-file');
                        }
                    });

                    this._screenshotMonitors.push(monitor);
                } catch (_e) {
                    // Directory doesn't exist or can't be monitored
                }
            }

            this._dbusPatched = true;
        } catch (_e) {
            // D-Bus monitoring not available, skip
        }
    }

    _stopScreenshotDBusMonitor() {
        if (this._dbusWatchId) {
            try {
                Gio.DBus.session.signal_unsubscribe(this._dbusWatchId);
            } catch (_e) {
                // Best effort
            }
            this._dbusWatchId = null;
        }

        if (this._screenshotMonitors) {
            for (let i = 0; i < this._screenshotMonitors.length; i++) {
                try {
                    this._screenshotMonitors[i].cancel();
                } catch (_e) {
                    // Best effort
                }
            }
            this._screenshotMonitors = null;
        }

        this._dbusPatched = false;
    }

    /* ================================================================== */
    /*  Common detection handler                                           */
    /* ================================================================== */

    _onScreenshotDetected(source, tool) {
        // Debounce: ignore triggers within 3 seconds of each other
        const now = GLib.get_monotonic_time();
        if (this._lastTriggerTime && (now - this._lastTriggerTime) < 3000000) {
            return;
        }
        this._lastTriggerTime = now;

        // Check all browser windows for sensitive sites
        const sensitiveWindows = this._findSensitiveBrowserWindows();
        if (sensitiveWindows.length === 0) return;

        // Build event
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

    /* ================================================================== */
    /*  Window scanning (all monitors)                                     */
    /* ================================================================== */

    _findSensitiveBrowserWindows() {
        const matches = [];
        const actors = global.get_window_actors();

        const patterns = this._settings.get_strv('sensitive-patterns')
            .map(p => p.toLowerCase());
        const ignorePatterns = this._settings.get_strv('ignore-patterns')
            .map(p => p.toLowerCase());

        if (patterns.length === 0)
            return matches;

        // Get the active workspace (visible on screen)
        const activeWorkspace = global.workspace_manager.get_active_workspace();

        for (let i = 0; i < actors.length; i++) {
            const actor = actors[i];
            const metaWindow = actor.get_meta_window();
            if (!metaWindow) continue;

            // Skip windows not on the active/visible workspace
            // (unless they're on all workspaces, like sticky windows)
            if (!metaWindow.is_on_all_workspaces() &&
                metaWindow.get_workspace() !== activeWorkspace) {
                continue;
            }

            // Skip minimized windows — not visible on screen
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

            // Check ignore patterns first — skip this window if matched
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

    /* ================================================================== */
    /*  Topbar warning                                                     */
    /* ================================================================== */

    _showWarning() {
        // If already warning, reset the timer
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

    /* ================================================================== */
    /*  JSON logging                                                       */
    /* ================================================================== */

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
            log('[sensitive-ss] Failed to write log: ' + e.message);
        }
    }

    /* ================================================================== */
    /*  Cleanup                                                            */
    /* ================================================================== */

    destroy() {
        this._stopScreenshotDBusMonitor();
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
/*  Extension entry point (GNOME 42–44 old-style)                      */
/* ------------------------------------------------------------------ */

let _indicator = null;
let _settings = null;

function init() {
    // Nothing to do here
}

function enable() {
    _settings = ExtensionUtils.getSettings(
        'org.gnome.shell.extensions.sensitive-ss'
    );
    _indicator = new ScreenshotIndicator(_settings);
    Main.panel.addToStatusArea('sensitive-ss@security.local', _indicator);
}

function disable() {
    if (_indicator) {
        _indicator.destroy();
        _indicator = null;
    }
    _settings = null;
}
