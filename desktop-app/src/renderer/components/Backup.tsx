import * as React from 'react';
import { useState, useEffect } from 'react';

interface BackupStatus {
  enabled: boolean;
  frequency: string;
  lastBackup: string | null;
  recoveryPasswordSet: boolean;
  backupNeeded: boolean;
}

export const Backup: React.FC = () => {
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [settingPassword, setSettingPassword] = useState(false);

  useEffect(() => {
    loadBackupStatus();
  }, []);

  const loadBackupStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await window.electronAPI.getBackupStatus();
      if (result.success) {
        setStatus(result.data);
      } else {
        // If we can't load status, show default state (not set up)
        setStatus({
          enabled: true,
          frequency: 'monthly',
          lastBackup: null,
          recoveryPasswordSet: false,
          backupNeeded: true
        });
      }
    } catch (err) {
      // On error, show default state so user can set up backup
      setStatus({
        enabled: true,
        frequency: 'monthly',
        lastBackup: null,
        recoveryPasswordSet: false,
        backupNeeded: true
      });
    }
    setLoading(false);
  };

  const handleSetRecoveryPassword = async () => {
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setSettingPassword(true);
    setError(null);

    try {
      const result = await window.electronAPI.setRecoveryPassword(password);
      if (result.success) {
        setShowPasswordForm(false);
        setPassword('');
        setConfirmPassword('');
        await loadBackupStatus();
      } else {
        setError(result.error || 'Failed to set recovery password');
      }
    } catch (err) {
      setError((err as Error).message);
    }
    setSettingPassword(false);
  };

  const handleUploadToGoogleDrive = async () => {
    try {
      const result = await window.electronAPI.openBackupUpload();
      if (!result.success) {
        setError(result.error || 'Failed to open backup upload');
      }
    } catch (err) {
      setError((err as Error).message);
    }
  };

  if (loading) {
    return (
      <div className="backup-container">
        <div className="loading">Loading backup status...</div>
      </div>
    );
  }

  return (
    <div className="backup-container">
      <div className="backup-header">
        <h2>Cloud Backup</h2>
        <span className="version-badge">Simple Secret v3.0.0</span>
      </div>
      <p className="subtitle">
        Protect your secrets with encrypted cloud backup. If you lose this machine,
        you can restore your secrets using your recovery password.
      </p>

      {error && <div className="error-message">{error}</div>}

      <div className="backup-status-card">
        <h3>Backup Status</h3>
        <div className="status-grid">
          <div className="status-item">
            <span className="label">Recovery Password:</span>
            <span className={`value ${status?.recoveryPasswordSet ? 'success' : 'warning'}`}>
              {status?.recoveryPasswordSet ? 'Set' : 'Not Set'}
            </span>
          </div>
          <div className="status-item">
            <span className="label">Backup Frequency:</span>
            <span className="value">{status?.frequency || 'monthly'}</span>
          </div>
          <div className="status-item">
            <span className="label">Last Backup:</span>
            <span className="value">
              {status?.lastBackup
                ? new Date(status.lastBackup).toLocaleDateString()
                : 'Never'}
            </span>
          </div>
          {status?.backupNeeded && (
            <div className="status-item warning-row">
              <span className="label">Status:</span>
              <span className="value warning">Backup Due</span>
            </div>
          )}
        </div>
      </div>

      {!status?.recoveryPasswordSet && !showPasswordForm && (
        <div className="setup-section">
          <h3>Set Up Cloud Backup</h3>
          <p>
            Create a recovery password to enable encrypted backups.
            This password is <strong>different</strong> from your vault password.
          </p>
          <button
            className="btn-primary"
            onClick={() => setShowPasswordForm(true)}
          >
            Set Recovery Password
          </button>
        </div>
      )}

      {showPasswordForm && (
        <div className="password-form">
          <h3>Create Recovery Password</h3>
          <p className="form-description">
            This password encrypts your backup. Store it somewhere safe -
            you'll need it to restore on a new machine.
          </p>
          <div className="form-group">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Recovery password (8+ characters)"
              className="form-input"
            />
          </div>
          <div className="form-group">
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm recovery password"
              className="form-input"
              onKeyPress={(e) => e.key === 'Enter' && handleSetRecoveryPassword()}
            />
          </div>
          <div className="button-group">
            <button
              className="btn-primary"
              onClick={handleSetRecoveryPassword}
              disabled={settingPassword || !password || !confirmPassword}
            >
              {settingPassword ? 'Setting...' : 'Set Password & Create Backup'}
            </button>
            <button
              className="btn-secondary"
              onClick={() => {
                setShowPasswordForm(false);
                setPassword('');
                setConfirmPassword('');
                setError(null);
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {status?.recoveryPasswordSet && (
        <div className="upload-section">
          <h3>Upload to Google Drive</h3>
          <p>
            Click the button below to open Google Drive and your backup file.
            Simply drag and drop to upload.
          </p>
          <button
            className="btn-primary btn-large"
            onClick={handleUploadToGoogleDrive}
          >
            Open Google Drive for Upload
          </button>
          <p className="help-text">
            Opens Google Drive in your browser and File Explorer with your backup file selected.
          </p>
        </div>
      )}

      <div className="info-section">
        <h3>How Simple Secret Backup Works</h3>
        <ul>
          <li>Your master key is encrypted with your recovery password</li>
          <li>The encrypted backup is safe to store in the cloud</li>
          <li>Only you can decrypt it with your recovery password</li>
          <li>Restore on any Windows machine with LLM Secrets installed</li>
        </ul>
      </div>

      <style>{`
        .backup-container {
          padding: 20px;
          max-width: 800px;
          margin: 0 auto;
        }
        .backup-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 8px;
        }
        .backup-header h2 {
          margin: 0;
        }
        .version-badge {
          background: var(--accent-color, #2563eb);
          color: white;
          padding: 4px 12px;
          border-radius: 16px;
          font-size: 12px;
          font-weight: 600;
        }
        .subtitle {
          color: var(--text-secondary, #666);
          margin-bottom: 24px;
        }
        .backup-status-card {
          background: var(--card-bg, #f5f5f5);
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 24px;
          border: 1px solid var(--border-color, #e0e0e0);
        }
        .backup-status-card h3 {
          margin-top: 0;
          margin-bottom: 16px;
          color: var(--text-primary, #1a1a1a);
        }
        .status-grid {
          display: grid;
          gap: 12px;
        }
        .status-item {
          display: flex;
          justify-content: space-between;
          padding: 10px 0;
          border-bottom: 1px solid var(--border-color, #e0e0e0);
        }
        .status-item:last-child {
          border-bottom: none;
        }
        .status-item .label {
          font-weight: 500;
          color: var(--text-primary, #1a1a1a);
        }
        .status-item .value.success {
          color: #16a34a;
          font-weight: 600;
        }
        .status-item .value.warning {
          color: #ca8a04;
          font-weight: 600;
        }
        .warning-row {
          background: rgba(202, 138, 4, 0.1);
          margin: 0 -20px;
          padding: 10px 20px !important;
          border-radius: 0;
        }
        .setup-section, .upload-section, .password-form {
          background: var(--card-bg, #f5f5f5);
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 24px;
          border: 1px solid var(--border-color, #e0e0e0);
        }
        .setup-section h3, .upload-section h3, .password-form h3 {
          margin-top: 0;
          color: var(--text-primary, #1a1a1a);
        }
        .form-description {
          color: var(--text-secondary, #666);
          margin-bottom: 16px;
        }
        .form-group {
          margin-bottom: 12px;
        }
        .form-input {
          width: 100%;
          padding: 12px 16px;
          border: 1px solid var(--border-color, #ccc);
          border-radius: 8px;
          font-size: 14px;
          box-sizing: border-box;
          background: var(--input-bg, #fff);
          color: var(--text-primary, #1a1a1a);
        }
        .form-input:focus {
          outline: none;
          border-color: var(--accent-color, #2563eb);
          box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }
        .button-group {
          display: flex;
          gap: 12px;
          margin-top: 16px;
        }
        .btn-primary {
          background: var(--accent-color, #2563eb);
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 8px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 600;
          transition: background 0.2s, transform 0.2s;
        }
        .btn-primary:hover {
          background: var(--accent-hover, #1d4ed8);
          transform: translateY(-1px);
        }
        .btn-primary:disabled {
          background: var(--disabled-bg, #ccc);
          cursor: not-allowed;
          transform: none;
        }
        .btn-secondary {
          background: transparent;
          color: var(--text-secondary, #666);
          border: 1px solid var(--border-color, #ccc);
          padding: 12px 24px;
          border-radius: 8px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
          transition: background 0.2s;
        }
        .btn-secondary:hover {
          background: var(--hover-bg, rgba(0,0,0,0.05));
        }
        .btn-large {
          padding: 16px 32px;
          font-size: 16px;
        }
        .help-text {
          color: var(--text-secondary, #666);
          font-size: 12px;
          margin-top: 12px;
        }
        .error-message {
          background: rgba(220, 38, 38, 0.1);
          color: #dc2626;
          padding: 12px 16px;
          border-radius: 8px;
          margin-bottom: 16px;
          border: 1px solid rgba(220, 38, 38, 0.2);
        }
        .info-section {
          background: var(--card-bg, #f5f5f5);
          border-radius: 12px;
          padding: 20px;
          border: 1px solid var(--border-color, #e0e0e0);
        }
        .info-section h3 {
          margin-top: 0;
          color: var(--text-primary, #1a1a1a);
        }
        .info-section ul {
          margin: 0;
          padding-left: 20px;
          color: var(--text-secondary, #666);
        }
        .info-section li {
          margin-bottom: 8px;
          line-height: 1.5;
        }
        .loading {
          text-align: center;
          padding: 40px;
          color: var(--text-secondary, #666);
        }
      `}</style>
    </div>
  );
};
