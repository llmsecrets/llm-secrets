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
    try {
      const result = await window.electronAPI.getBackupStatus();
      if (result.success) {
        setStatus(result.data);
      } else {
        setError(result.error || 'Failed to load backup status');
      }
    } catch (err) {
      setError((err as Error).message);
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
      <h2>Cloud Backup</h2>
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
        <h3>How Backup Works</h3>
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
        .backup-container h2 {
          margin-bottom: 8px;
        }
        .subtitle {
          color: #666;
          margin-bottom: 24px;
        }
        .backup-status-card {
          background: var(--card-bg, #f5f5f5);
          border-radius: 8px;
          padding: 20px;
          margin-bottom: 24px;
        }
        .backup-status-card h3 {
          margin-top: 0;
          margin-bottom: 16px;
        }
        .status-grid {
          display: grid;
          gap: 12px;
        }
        .status-item {
          display: flex;
          justify-content: space-between;
          padding: 8px 0;
          border-bottom: 1px solid var(--border-color, #e0e0e0);
        }
        .status-item:last-child {
          border-bottom: none;
        }
        .status-item .label {
          font-weight: 500;
        }
        .status-item .value.success {
          color: #28a745;
        }
        .status-item .value.warning {
          color: #ffc107;
        }
        .warning-row {
          background: #fff3cd;
          margin: 0 -20px;
          padding: 8px 20px !important;
        }
        .setup-section, .upload-section, .password-form {
          background: var(--card-bg, #f5f5f5);
          border-radius: 8px;
          padding: 20px;
          margin-bottom: 24px;
        }
        .setup-section h3, .upload-section h3, .password-form h3 {
          margin-top: 0;
        }
        .form-description {
          color: #666;
          margin-bottom: 16px;
        }
        .form-group {
          margin-bottom: 12px;
        }
        .form-input {
          width: 100%;
          padding: 12px;
          border: 1px solid var(--border-color, #ccc);
          border-radius: 4px;
          font-size: 14px;
          box-sizing: border-box;
        }
        .button-group {
          display: flex;
          gap: 12px;
          margin-top: 16px;
        }
        .btn-primary {
          background: #007bff;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 14px;
        }
        .btn-primary:hover {
          background: #0056b3;
        }
        .btn-primary:disabled {
          background: #ccc;
          cursor: not-allowed;
        }
        .btn-secondary {
          background: transparent;
          color: #666;
          border: 1px solid #ccc;
          padding: 12px 24px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 14px;
        }
        .btn-large {
          padding: 16px 32px;
          font-size: 16px;
        }
        .help-text {
          color: #666;
          font-size: 12px;
          margin-top: 8px;
        }
        .error-message {
          background: #f8d7da;
          color: #721c24;
          padding: 12px;
          border-radius: 4px;
          margin-bottom: 16px;
        }
        .info-section {
          background: var(--card-bg, #f5f5f5);
          border-radius: 8px;
          padding: 20px;
        }
        .info-section h3 {
          margin-top: 0;
        }
        .info-section ul {
          margin: 0;
          padding-left: 20px;
        }
        .info-section li {
          margin-bottom: 8px;
        }
        .loading {
          text-align: center;
          padding: 40px;
          color: #666;
        }
      `}</style>
    </div>
  );
};
