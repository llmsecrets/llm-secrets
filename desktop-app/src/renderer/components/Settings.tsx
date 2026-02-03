import * as React from 'react';
import { useState, useEffect } from 'react';

type AutoLockInterval = 0 | 5 | 10 | 30;
type SecurityMode = 'simple' | 'advanced';
type SessionDuration = '15min' | '1hour' | '2hours' | '8hours' | 'until_restart';

interface SimpleSecretSettings {
  securityMode: SecurityMode;
  sessionDuration: number;
  backup: {
    enabled: boolean;
    frequency: string;
    recoveryPasswordSet: boolean;
  };
}

export const Settings: React.FC = () => {
  const [autoLockInterval, setAutoLockInterval] = useState<AutoLockInterval>(5);
  const [autoLockEnabled, setAutoLockEnabled] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [settings, setSettings] = useState<SimpleSecretSettings | null>(null);
  const [sessionDuration, setSessionDuration] = useState<SessionDuration>('2hours');

  useEffect(() => {
    loadAutoLockSettings();
    loadSimpleSecretSettings();
  }, []);

  const loadAutoLockSettings = async () => {
    try {
      const result = await window.electronAPI.autolockGetSettings();
      if (result.success && result.data) {
        setAutoLockEnabled(result.data.enabled);
        setAutoLockInterval(result.data.intervalMinutes as AutoLockInterval);
      }
    } catch (error) {
      console.error('Failed to load auto-lock settings:', error);
    }
  };

  const loadSimpleSecretSettings = async () => {
    try {
      const result = await window.electronAPI.getSimpleSecretSettings();
      if (result.success && result.data) {
        setSettings(result.data);
        // Convert session duration seconds to display value
        const durationSeconds = result.data.sessionDuration || 7200;
        if (durationSeconds <= 900) setSessionDuration('15min');
        else if (durationSeconds <= 3600) setSessionDuration('1hour');
        else if (durationSeconds <= 7200) setSessionDuration('2hours');
        else if (durationSeconds <= 28800) setSessionDuration('8hours');
        else setSessionDuration('until_restart');
      }
    } catch (error) {
      console.error('Failed to load LLM Secrets settings:', error);
    }
  };

  const handleAutoLockChange = async (event: React.ChangeEvent<HTMLSelectElement>) => {
    const minutes = parseInt(event.target.value, 10) as AutoLockInterval;
    setAutoLockInterval(minutes);
    setAutoLockEnabled(minutes > 0);

    try {
      const result = await window.electronAPI.autolockSetInterval(minutes);
      if (result.success) {
        setMessage({ type: 'success', text: minutes > 0 ? `Auto-lock set to ${minutes} minutes` : 'Auto-lock disabled' });
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to update auto-lock' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to update auto-lock settings' });
    }

    setTimeout(() => setMessage(null), 3000);
  };

  const handleSessionDurationChange = async (event: React.ChangeEvent<HTMLSelectElement>) => {
    const duration = event.target.value as SessionDuration;
    setSessionDuration(duration);

    try {
      const result = await window.electronAPI.saveSessionSettings(duration);
      if (result.success) {
        setMessage({ type: 'success', text: 'Session duration updated' });
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to update session duration' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to update session settings' });
    }

    setTimeout(() => setMessage(null), 3000);
  };

  const handleExportBackup = async () => {
    setIsExporting(true);
    setMessage(null);

    try {
      const result = await window.electronAPI.backupExport();
      if (result.success && result.data) {
        setMessage({ type: 'success', text: `Backup exported to ${result.data.path}` });
      } else if (result.error !== 'Export cancelled') {
        setMessage({ type: 'error', text: result.error || 'Export failed' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to export backup' });
    }

    setIsExporting(false);
    setTimeout(() => setMessage(null), 5000);
  };

  const handleImportBackup = async () => {
    setIsImporting(true);
    setMessage(null);

    try {
      const result = await window.electronAPI.backupImport();
      if (result.success && result.data) {
        const data = result.data;
        const parts = [];
        if (data.imported.settings) parts.push('settings');
        if (data.imported.wallets > 0) parts.push(`${data.imported.wallets} wallet(s)`);
        setMessage({ type: 'success', text: `Imported: ${parts.join(', ')}` });
        loadAutoLockSettings();
        loadSimpleSecretSettings();
      } else if (result.error !== 'Import cancelled') {
        setMessage({ type: 'error', text: result.error || 'Import failed' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to import backup' });
    }

    setIsImporting(false);
    setTimeout(() => setMessage(null), 5000);
  };

  // This version is Simple mode only
  const getSecurityModeDisplay = () => {
    return 'Simple (Windows Hello only)';
  };

  return (
    <div className="settings">
      <div className="card">
        <h2>Settings</h2>
        <p>Configure your LLM Secrets application preferences</p>

        {message && (
          <div className={`message ${message.type}`}>
            {message.text}
          </div>
        )}

        <div className="settings-section">
          <h3>Session Duration</h3>
          <p>How long your vault stays unlocked after authentication.</p>
          <select
            value={sessionDuration}
            onChange={handleSessionDurationChange}
            className="settings-select"
          >
            <option value="15min">15 minutes</option>
            <option value="1hour">1 hour</option>
            <option value="2hours">2 hours</option>
            <option value="8hours">8 hours</option>
            <option value="until_restart">Until app restart</option>
          </select>
        </div>

        <div className="settings-section">
          <h3>Auto-Lock</h3>
          <p>
            Automatically encrypt decrypted secrets after a period of inactivity.
          </p>
          <select
            value={autoLockInterval}
            onChange={handleAutoLockChange}
            className="settings-select"
          >
            <option value={5}>5 minutes</option>
            <option value={10}>10 minutes</option>
            <option value={30}>30 minutes</option>
            <option value={0}>Never</option>
          </select>
          {autoLockEnabled && (
            <p className="settings-note">
              Auto-lock is enabled. Secrets will be locked after {autoLockInterval} minutes of inactivity.
            </p>
          )}
        </div>

        <div className="settings-section">
          <h3>Backup & Restore</h3>
          <p>
            Export and import wallet configurations and settings.
          </p>
          <p className="settings-note">
            Note: For security, private keys are NOT included in backups.
            Only wallet addresses and app settings are exported.
          </p>
          <div className="button-group">
            <button
              className="btn-secondary"
              onClick={handleExportBackup}
              disabled={isExporting}
            >
              {isExporting ? 'Exporting...' : 'Export Settings'}
            </button>
            <button
              className="btn-secondary"
              onClick={handleImportBackup}
              disabled={isImporting}
            >
              {isImporting ? 'Importing...' : 'Import Settings'}
            </button>
          </div>
        </div>

      </div>

      <style>{`
        .settings-value {
          background: var(--card-bg, #f5f5f5);
          padding: 12px 16px;
          border-radius: 8px;
          margin-bottom: 8px;
        }
        .settings-grid {
          display: grid;
          gap: 8px;
          margin-bottom: 12px;
        }
        .settings-item {
          display: flex;
          justify-content: space-between;
          padding: 8px 12px;
          background: var(--card-bg, #f5f5f5);
          border-radius: 4px;
        }
        .settings-item .label {
          font-weight: 500;
        }
        .settings-item .value.success {
          color: #16a34a;
        }
        .settings-item .value.warning {
          color: #ca8a04;
        }
      `}</style>
    </div>
  );
};
