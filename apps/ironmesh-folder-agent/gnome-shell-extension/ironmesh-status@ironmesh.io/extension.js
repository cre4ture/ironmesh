import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import St from 'gi://St';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const STATUS_FILE_PATH = GLib.build_filenamev([
    GLib.get_user_runtime_dir(),
    'ironmesh',
    'gnome-status.json',
]);
const STATUS_STALE_AFTER_MS = 30_000;

const IronmeshIndicator = GObject.registerClass(
class IronmeshIndicator extends PanelMenu.Button {
    _init(extension) {
        super._init(0.0, 'IronMesh Status', false);

        this._extension = extension;
        this._statusFile = Gio.File.new_for_path(STATUS_FILE_PATH);
        this._statusFileMonitor = null;
        this._pollTimeoutId = null;

        this._icon = new St.Icon({
            icon_name: 'dialog-question-symbolic',
            style_class: 'system-status-icon',
        });
        this.add_child(this._icon);

        this._buildMenu();
        this._startMonitoring();
        this._reloadStatus();
    }

    _buildMenu() {
        const header = new PopupMenu.PopupMenuItem('IronMesh', {
            reactive: false,
            can_focus: false,
        });
        header.label.add_style_class_name('ironmesh-header');
        this.menu.addMenuItem(header);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._summaryRow = this._addStatusRow('Overall');
        this._connectionRow = this._addStatusRow('Connection');
        this._syncRow = this._addStatusRow('Local Sync');
        this._replicationRow = this._addStatusRow('Replication');

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._targetRow = this._addStatusRow('Target');
        this._updatedRow = this._addStatusRow('Updated');
    }

    _addStatusRow(title) {
        const item = new PopupMenu.PopupBaseMenuItem({
            reactive: false,
            can_focus: false,
        });
        item.add_style_class_name('ironmesh-status-row');

        const box = new St.BoxLayout({
            vertical: true,
            x_expand: true,
        });
        const titleLabel = new St.Label({
            text: title,
            x_align: St.Align.START,
            style_class: 'ironmesh-status-title',
        });
        const valueLabel = new St.Label({
            text: 'Waiting for IronMesh',
            x_align: St.Align.START,
            style_class: 'ironmesh-status-value',
        });
        const detailLabel = new St.Label({
            text: '',
            x_align: St.Align.START,
            style_class: 'ironmesh-status-detail',
        });
        detailLabel.clutter_text.set_line_wrap(true);
        detailLabel.clutter_text.set_line_wrap_mode(2);

        box.add_child(titleLabel);
        box.add_child(valueLabel);
        box.add_child(detailLabel);
        item.add_child(box);
        this.menu.addMenuItem(item);

        return {
            item,
            valueLabel,
            detailLabel,
        };
    }

    _startMonitoring() {
        try {
            this._statusFileMonitor = this._statusFile.monitor_file(
                Gio.FileMonitorFlags.NONE,
                null
            );
            this._statusFileMonitor.connect('changed', () => {
                this._reloadStatus();
            });
        } catch (error) {
            logError(error, 'IronMesh Status: failed to monitor status file');
        }

        this._pollTimeoutId = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT,
            5,
            () => {
                this._reloadStatus();
                return GLib.SOURCE_CONTINUE;
            }
        );
    }

    _reloadStatus() {
        try {
            const [ok, contents] = this._statusFile.load_contents(null);
            if (!ok) {
                this._applyMissingState('Waiting for IronMesh agent', 'Status file could not be loaded');
                return;
            }

            const text = new TextDecoder().decode(contents);
            const payload = JSON.parse(text);
            if (this._isStale(payload)) {
                this._applyMissingState(
                    'Waiting for live IronMesh updates',
                    'The GNOME indicator has not received a recent status update'
                );
                return;
            }

            this._applyPayload(payload);
        } catch (error) {
            if (error.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND)) {
                this._applyMissingState('Waiting for IronMesh agent', 'Start ironmesh-folder-agent with --publish-gnome-status');
                return;
            }

            logError(error, 'IronMesh Status: failed to reload status');
            this._applyMissingState('IronMesh status error', `${error}`);
        }
    }

    _isStale(payload) {
        const generatedUnixMs = payload?.generatedUnixMs ?? 0;
        if (generatedUnixMs <= 0)
            return true;
        return (Date.now() - generatedUnixMs) > STATUS_STALE_AFTER_MS;
    }

    _applyPayload(payload) {
        this._icon.icon_name = payload?.overall?.iconName ?? 'dialog-question-symbolic';

        this._applyFacet(this._summaryRow, payload?.overall);
        this._applyFacet(this._connectionRow, payload?.connection);
        this._applyFacet(this._syncRow, payload?.sync);
        this._applyFacet(this._replicationRow, payload?.replication);

        this._targetRow.valueLabel.text = payload?.profileLabel ?? 'IronMesh';
        this._targetRow.detailLabel.text = payload?.connectionTarget ?? 'No connection target reported';

        this._updatedRow.valueLabel.text = this._formatUpdated(payload?.generatedUnixMs ?? 0);
        this._updatedRow.detailLabel.text = payload?.rootDir ?? STATUS_FILE_PATH;
    }

    _applyFacet(row, facet) {
        row.valueLabel.text = facet?.summary ?? 'Unknown';
        row.detailLabel.text = facet?.detail ?? '';
        row.item.remove_style_class_name('ironmesh-state-error');
        row.item.remove_style_class_name('ironmesh-state-warning');
        row.item.remove_style_class_name('ironmesh-state-syncing');

        switch (facet?.state) {
        case 'error':
            row.item.add_style_class_name('ironmesh-state-error');
            break;
        case 'warning':
            row.item.add_style_class_name('ironmesh-state-warning');
            break;
        case 'syncing':
        case 'starting':
            row.item.add_style_class_name('ironmesh-state-syncing');
            break;
        default:
            break;
        }
    }

    _applyMissingState(summary, detail) {
        this._icon.icon_name = 'dialog-question-symbolic';

        this._applyFacet(this._summaryRow, {
            summary,
            detail,
            state: 'unknown',
        });
        this._applyFacet(this._connectionRow, {
            summary: 'No live connection data',
            detail: 'Waiting for the IronMesh agent status publisher',
            state: 'unknown',
        });
        this._applyFacet(this._syncRow, {
            summary: 'Local sync not publishing',
            detail: 'Start ironmesh-folder-agent with --publish-gnome-status',
            state: 'unknown',
        });
        this._applyFacet(this._replicationRow, {
            summary: 'Replication status unavailable',
            detail: 'Replication details appear once the agent can reach the server',
            state: 'unknown',
        });

        this._targetRow.valueLabel.text = 'IronMesh';
        this._targetRow.detailLabel.text = STATUS_FILE_PATH;
        this._updatedRow.valueLabel.text = 'No recent update';
        this._updatedRow.detailLabel.text = detail;
    }

    _formatUpdated(unixMs) {
        if (unixMs <= 0)
            return 'No update yet';

        const seconds = Math.floor(unixMs / 1000);
        const dateTime = GLib.DateTime.new_from_unix_local(seconds);
        if (!dateTime)
            return 'Update time unavailable';

        return dateTime.format('%Y-%m-%d %H:%M:%S');
    }

    destroy() {
        if (this._pollTimeoutId !== null) {
            GLib.Source.remove(this._pollTimeoutId);
            this._pollTimeoutId = null;
        }

        if (this._statusFileMonitor) {
            this._statusFileMonitor.cancel();
            this._statusFileMonitor = null;
        }

        super.destroy();
    }
});

export default class IronmeshStatusExtension extends Extension {
    enable() {
        this._indicator = new IronmeshIndicator(this);
        Main.panel.addToStatusArea(this.uuid, this._indicator);
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
    }
}
