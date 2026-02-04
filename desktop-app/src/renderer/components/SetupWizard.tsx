import * as React from 'react';
import { useState, useEffect } from 'react';
import './SetupWizard.css';

type WizardStep =
  | 'welcome'
  | 'license'
  | 'validating_license'
  | 'choose_mode'
  | 'create_password'
  | 'creating_vault'
  | 'backup_key'
  | 'add_secrets'
  | 'session_settings'
  | 'encrypting'
  | 'complete'
  | 'recover'
  | 'recovering';

type SecurityMode = 'simple' | 'advanced';

type SessionDuration = '15min' | '1hour' | '2hours' | '8hours' | 'until_restart';

interface SetupWizardProps {
  onComplete: () => void;
}

export const SetupWizard: React.FC<SetupWizardProps> = ({ onComplete }) => {
  const [step, setStep] = useState<WizardStep>('welcome');
  const [securityMode, setSecurityMode] = useState<SecurityMode>('simple');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [masterKey, setMasterKey] = useState<string | null>(null);
  const [backupConfirmed, setBackupConfirmed] = useState(false);
  const [secrets, setSecrets] = useState('');
  const [sessionDuration, setSessionDuration] = useState<SessionDuration>('2hours');
  const [error, setError] = useState<string | null>(null);
  const [keyCopied, setKeyCopied] = useState(false);

  // Recovery state
  const [recoveryPath, setRecoveryPath] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');

  // License state
  const [licenseKey, setLicenseKey] = useState('');
  const [licenseEmail, setLicenseEmail] = useState('');

  // Handle Simple mode vault creation automatically
  useEffect(() => {
    if (step === 'creating_vault' && securityMode === 'simple') {
      handleCreateSimpleVault();
    }
  }, [step, securityMode]);

  // Simple mode vault creation (Touch ID on macOS, Windows Hello on Windows)
  const handleCreateSimpleVault = async () => {
    console.log('[SetupWizard] Starting createSimpleVault...');
    try {
      console.log('[SetupWizard] Calling window.electronAPI.createSimpleVault()...');
      const result = await window.electronAPI.createSimpleVault();
      console.log('[SetupWizard] createSimpleVault result:', result);
      if (result.success) {
        // On macOS, masterKey is stored in Keychain (not returned)
        // On Windows, masterKey is returned for backup
        if (result.masterKey) {
          setMasterKey(result.masterKey);
          setStep('backup_key');
        } else {
          // macOS: skip backup key step, go directly to add secrets
          setStep('add_secrets');
        }
      } else {
        console.error('[SetupWizard] createSimpleVault failed:', result.error);
        setError(result.error || 'Failed to create vault');
        setStep('welcome');
      }
    } catch (err) {
      console.error('[SetupWizard] createSimpleVault exception:', err);
      setError(`Error: ${(err as Error).message}`);
      setStep('welcome');
    }
  };

  // Screen 1: Welcome
  const renderWelcome = () => (
    <div className="wizard-screen welcome">
      <h1>Welcome to LLM Secrets</h1>
      <p className="subtitle">Let's set up your encrypted secrets vault.</p>
      <p className="time-estimate">This takes about 2 minutes.</p>

      <div className="checklist">
        <p>You'll need to:</p>
        <ul>
          <li>Authenticate with Touch ID or Windows Hello</li>
          <li>Save a backup key (keep it somewhere safe)</li>
          <li>Add your first secrets</li>
        </ul>
      </div>

      <div className="value-prop">
        <p>
          Once setup is complete, Claude Code can run commands using your
          secrets - without ever seeing the actual values.
        </p>
      </div>

      <button className="btn-primary" onClick={() => setStep('creating_vault')}>
        Get Started
      </button>

      <div className="recovery-link">
        <p>Already have secrets to recover?</p>
        <button className="btn-link" onClick={() => setStep('recover')}>
          Restore from backup
        </button>
      </div>
    </div>
  );

  // License validation handler
  const handleValidateLicense = async () => {
    if (!licenseKey.trim()) {
      setError('Please enter your license key');
      return;
    }
    if (!licenseEmail.trim()) {
      setError('Please enter the email used for purchase');
      return;
    }

    setError(null);
    setStep('validating_license');

    try {
      const result = await window.electronAPI.activateLicense(licenseKey.trim(), licenseEmail.trim());
      if (result.success) {
        setStep('choose_mode');
      } else {
        setError(result.error || 'Invalid license key or email. Please check and try again.');
        setStep('license');
      }
    } catch (err) {
      setError(`Error: ${(err as Error).message}`);
      setStep('license');
    }
  };

  // Screen: License Activation
  const renderLicense = () => (
    <div className="wizard-screen license">
      <h1>Activate Your License</h1>
      <p className="subtitle">Enter your license details to get started.</p>

      <div className="one-time-notice">
        <strong>One-time setup:</strong> You'll only need to enter this information once.
        Your license will be saved locally and won't be asked for again.
      </div>

      <div className="form-group">
        <label>License Key</label>
        <input
          type="text"
          value={licenseKey}
          onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
          placeholder="XXXX-XXXX-XXXX-XXXX"
          className="wizard-input license-key-input"
          autoFocus
          maxLength={19}
        />
        <p className="input-hint">
          Find this in your purchase confirmation email from Stripe.
        </p>
      </div>

      <div className="form-group">
        <label>Purchase Email</label>
        <input
          type="email"
          value={licenseEmail}
          onChange={(e) => setLicenseEmail(e.target.value)}
          placeholder="you@example.com"
          className="wizard-input"
          onKeyPress={(e) => e.key === 'Enter' && handleValidateLicense()}
        />
        <p className="input-hint">
          The email address you used when purchasing.
        </p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <button
        className="btn-primary"
        onClick={handleValidateLicense}
        disabled={!licenseKey || !licenseEmail}
      >
        Activate License
      </button>

      <div className="purchase-link">
        <p>Don't have a license?</p>
        <a href="https://llmsecrets.dev" target="_blank" rel="noopener noreferrer" className="btn-link">
          Purchase at llmsecrets.dev
        </a>
      </div>
    </div>
  );

  const renderValidatingLicense = () => (
    <div className="wizard-screen loading">
      <div className="spinner"></div>
      <h2>Validating license...</h2>
      <p>Checking your license key.</p>
    </div>
  );

  // Recovery Screen
  const handleRecover = async () => {
    if (!recoveryPath.trim()) {
      setError('Please enter the path to your encrypted file');
      return;
    }
    if (!recoveryKey.trim() || recoveryKey.length !== 44) {
      setError('Master key must be exactly 44 characters');
      return;
    }

    setError(null);
    setStep('recovering');

    try {
      const result = await window.electronAPI.recoverSecrets(recoveryPath, recoveryKey);
      if (result.success) {
        // Recovery successful - install Claude commands and go to complete
        await window.electronAPI.installClaudeCommands();
        setMasterKey(recoveryKey);
        setStep('complete');
      } else {
        setError(result.error || 'Recovery failed. Check your file path and master key.');
        setStep('recover');
      }
    } catch (err) {
      setError(`Error: ${(err as Error).message}`);
      setStep('recover');
    }
  };

  const renderRecover = () => (
    <div className="wizard-screen recover">
      <h1>Recover Your Secrets</h1>
      <p className="subtitle">Restore from an existing encrypted secrets file.</p>

      <div className="form-group">
        <label>Path to encrypted file (.env.encrypted)</label>
        <input
          type="text"
          value={recoveryPath}
          onChange={(e) => setRecoveryPath(e.target.value)}
          placeholder="C:\path\to\your\.env.encrypted"
          className="wizard-input"
          autoFocus
        />
        <p className="input-hint">
          Common location: C:\Users\YourName\OneDrive\Desktop\Keep Scrt\.env.encrypted
        </p>
      </div>

      <div className="form-group">
        <label>Master Key (44 characters)</label>
        <input
          type="password"
          value={recoveryKey}
          onChange={(e) => setRecoveryKey(e.target.value)}
          placeholder="Paste your 44-character backup key"
          className="wizard-input"
          maxLength={44}
          onKeyPress={(e) => e.key === 'Enter' && handleRecover()}
        />
        <p className="input-hint">
          This is the backup key you saved during initial setup.
        </p>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="button-group">
        <button
          className="btn-primary"
          onClick={handleRecover}
          disabled={!recoveryPath || !recoveryKey}
        >
          Recover Secrets
        </button>
        <button className="btn-secondary" onClick={() => {
          setError(null);
          setStep('welcome');
        }}>
          Back
        </button>
      </div>
    </div>
  );

  const renderRecovering = () => (
    <div className="wizard-screen loading">
      <div className="spinner"></div>
      <h2>Recovering your secrets...</h2>
      <p>Validating master key and restoring your vault.</p>
    </div>
  );

  // Screen 2: Choose Security Mode
  const renderChooseMode = () => (
    <div className="wizard-screen choose-mode">
      <h1>Choose Security Level</h1>
      <p className="subtitle">How do you want to protect your secrets?</p>

      {error && (
        <div className="error-message" style={{ marginBottom: '20px' }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      <div className="mode-options">
        <label
          className={`mode-option ${securityMode === 'simple' ? 'selected' : ''}`}
          onClick={() => setSecurityMode('simple')}
        >
          <input
            type="radio"
            name="securityMode"
            value="simple"
            checked={securityMode === 'simple'}
            onChange={() => setSecurityMode('simple')}
          />
          <div className="mode-content">
            <div className="mode-header">
              <strong>Simple Mode</strong>
              <span className="recommended">Recommended</span>
            </div>
            <p>Windows Hello (PIN/biometric) only</p>
            <ul>
              <li>One authentication step</li>
              <li>Master key stored with Windows encryption</li>
              <li>Best for personal machines</li>
            </ul>
          </div>
        </label>

        <label
          className={`mode-option ${securityMode === 'advanced' ? 'selected' : ''}`}
          onClick={() => setSecurityMode('advanced')}
        >
          <input
            type="radio"
            name="securityMode"
            value="advanced"
            checked={securityMode === 'advanced'}
            onChange={() => setSecurityMode('advanced')}
          />
          <div className="mode-content">
            <div className="mode-header">
              <strong>Advanced Mode</strong>
            </div>
            <p>Windows Hello + KeePass password</p>
            <ul>
              <li>Two authentication steps</li>
              <li>Master key in encrypted database</li>
              <li>Best for shared machines</li>
            </ul>
          </div>
        </label>
      </div>

      <button
        className="btn-primary"
        onClick={() => setStep(securityMode === 'simple' ? 'creating_vault' : 'create_password')}
      >
        Continue with {securityMode === 'simple' ? 'Simple' : 'Advanced'} Mode
      </button>

      <div className="recovery-link">
        <button className="btn-link" onClick={() => setStep('recover')}>
          I have existing secrets to recover
        </button>
      </div>

      <div className="step-indicator">
        {securityMode === 'simple' ? 'Step 2 of 5' : 'Step 2 of 6'}
      </div>
    </div>
  );

  // Screen 2: Create Password
  const handleCreateVault = async () => {
    if (password.length < 12) {
      setError('Password must be at least 12 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setError(null);
    setStep('creating_vault');

    try {
      const result = await window.electronAPI.createVault(password);
      if (result.success && result.masterKey) {
        setMasterKey(result.masterKey);
        setStep('backup_key');
      } else {
        setError(result.error || 'Failed to create vault');
        setStep('create_password');
      }
    } catch (err) {
      setError(`Error: ${(err as Error).message}`);
      setStep('create_password');
    }
  };

  const renderCreatePassword = () => (
    <div className="wizard-screen create-password">
      <h1>Create Your Vault Password</h1>
      <p className="subtitle">This password protects your secrets.</p>
      <p className="warning-text">There is NO recovery if you forget it.</p>

      <div className="form-group">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password (12+ characters)"
          className="wizard-input"
          autoFocus
        />
      </div>

      <div className="form-group">
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          placeholder="Confirm password"
          className="wizard-input"
          onKeyPress={(e) => e.key === 'Enter' && handleCreateVault()}
        />
      </div>

      <div className="important-box">
        <strong>IMPORTANT:</strong> Keep this password somewhere safe.
      </div>

      {error && <div className="error-message">{error}</div>}

      <button
        className="btn-primary"
        onClick={handleCreateVault}
        disabled={!password || !confirmPassword}
      >
        Create Vault
      </button>

      <div className="step-indicator">Step 2 of 6</div>
    </div>
  );

  // Loading: Creating Vault
  const renderCreatingVault = () => (
    <div className="wizard-screen loading">
      <div className="spinner"></div>
      <h2>Creating your vault...</h2>
      <p>Setting up encryption and Windows Hello authentication.</p>
      {error && (
        <div className="error-message" style={{ marginTop: '20px' }}>
          <strong>Error:</strong> {error}
        </div>
      )}
    </div>
  );

  // Screen 3: Backup Key
  const handleCopyKey = async () => {
    if (masterKey) {
      await navigator.clipboard.writeText(masterKey);
      setKeyCopied(true);
      setTimeout(() => setKeyCopied(false), 3000);
    }
  };

  const renderBackupKey = () => (
    <div className="wizard-screen backup-key">
      <h1>Save Your Backup Key</h1>
      <p className="subtitle">
        If you forget your password, this key is your only way to recover your secrets.
      </p>

      <div className="key-display">
        <code className="master-key">{masterKey}</code>
        <button
          className={`btn-copy ${keyCopied ? 'copied' : ''}`}
          onClick={handleCopyKey}
        >
          {keyCopied ? 'Copied!' : 'Copy'}
        </button>
      </div>

      <div className="important-box warning">
        <strong>IMPORTANT:</strong> Save this key somewhere safe. It will NOT be shown again.
      </div>

      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={backupConfirmed}
          onChange={(e) => setBackupConfirmed(e.target.checked)}
        />
        I have saved this key somewhere safe
      </label>

      <button
        className="btn-primary"
        onClick={() => setStep('add_secrets')}
        disabled={!backupConfirmed}
      >
        Continue
      </button>

      <div className="step-indicator">Step 1 of 3</div>
    </div>
  );

  // Screen 4: Add Secrets
  const handleEncryptSecrets = async () => {
    setStep('encrypting');

    try {
      if (secrets.trim()) {
        // Encrypt the secrets using the master key from vault creation
        const encryptResult = await window.electronAPI.encryptEnv(secrets, masterKey || '');
        if (!encryptResult.success) {
          setError(encryptResult.error || 'Failed to encrypt secrets');
          setStep('add_secrets');
          return;
        }
      }

      // Generate CLAUDE.md
      const secretNames = parseSecretNames(secrets);
      await window.electronAPI.generateClaudeMd(secretNames);

      // Install Claude Code slash commands (/secret/view, /secret/format, /secret/hide)
      await window.electronAPI.installClaudeCommands();

      // Simple mode: skip session settings (defaults to 2 hours)
      // Advanced mode: show session settings
      if (securityMode === 'simple') {
        await window.electronAPI.saveSessionSettings('2hours');
        setStep('complete');
      } else {
        setStep('session_settings');
      }
    } catch (err) {
      setError(`Error: ${(err as Error).message}`);
      setStep('add_secrets');
    }
  };

  const parseSecretNames = (content: string): string[] => {
    const names: string[] = [];
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
        const name = trimmed.split('=')[0].trim();
        if (name) names.push(name);
      }
    }
    return names;
  };

  const renderAddSecrets = () => (
    <div className="wizard-screen add-secrets">
      <h1>Add Your Secrets</h1>
      <p className="subtitle">
        Enter your API keys, tokens, and credentials.<br />
        Use KEY=value format, one per line.
      </p>

      <textarea
        className="secrets-editor"
        value={secrets}
        onChange={(e) => setSecrets(e.target.value)}
        placeholder={`# Blockchain
PRIVATE_KEY=
ALCHEMY_API_KEY=

# GitHub
GITHUB_PAT=

# Add your own...`}
        rows={12}
      />

      {error && <div className="error-message">{error}</div>}

      <div className="button-group">
        <button
          className="btn-primary"
          onClick={handleEncryptSecrets}
          disabled={!secrets.trim() || parseSecretNames(secrets).length === 0}
        >
          Encrypt & Continue
        </button>
      </div>

      {(!secrets.trim() || parseSecretNames(secrets).length === 0) && (
        <div className="validation-hint">
          Please enter at least one secret in KEY=value format to continue.
        </div>
      )}

      <div className="tip-box">
        <strong>Tip:</strong> You can add more secrets anytime in the Secrets Manager.
      </div>

      <div className="step-indicator">Step 2 of 3</div>
    </div>
  );

  // Loading: Encrypting
  const renderEncrypting = () => (
    <div className="wizard-screen loading">
      <div className="spinner"></div>
      <h2>Encrypting your secrets...</h2>
      <p>Your secrets are being secured with AES-256 encryption.</p>
    </div>
  );

  // Screen 5: Session Settings
  const handleSaveSettings = async () => {
    try {
      await window.electronAPI.saveSessionSettings(sessionDuration);
      setStep('complete');
    } catch (err) {
      setError(`Error: ${(err as Error).message}`);
    }
  };

  const renderSessionSettings = () => (
    <div className="wizard-screen session-settings">
      <h1>Configure Session Length</h1>
      <p className="subtitle">How long should your vault stay unlocked?</p>

      <div className="slider-labels">
        <span>CONVENIENT</span>
        <span>SECURE</span>
      </div>

      <div className="session-options">
        {[
          { value: '15min', label: '15 minutes', desc: 'Re-authenticate frequently' },
          { value: '1hour', label: '1 hour', desc: 'Balanced' },
          { value: '2hours', label: '2 hours', desc: 'Recommended' },
          { value: '8hours', label: '8 hours', desc: 'Full work day' },
          { value: 'until_restart', label: 'Until restart', desc: 'Most convenient' },
        ].map((option) => (
          <label
            key={option.value}
            className={`session-option ${sessionDuration === option.value ? 'selected' : ''}`}
          >
            <input
              type="radio"
              name="sessionDuration"
              value={option.value}
              checked={sessionDuration === option.value}
              onChange={() => setSessionDuration(option.value as SessionDuration)}
            />
            <div className="option-content">
              <strong>{option.label}</strong>
              <span>{option.desc}</span>
            </div>
          </label>
        ))}
      </div>

      <div className="guarantees">
        <p>No matter which setting you choose:</p>
        <ul>
          <li>Claude Code never sees your actual secrets</li>
          <li>Claude Code can inject secrets into commands</li>
          <li>Secrets exist only in memory during execution</li>
        </ul>
        <p className="note">This only controls how often YOU re-enter your password.</p>
      </div>

      <button className="btn-primary" onClick={handleSaveSettings}>
        Continue
      </button>

      <div className="step-indicator">Step 5 of 6</div>
    </div>
  );

  // Screen 6: Complete
  const renderComplete = () => (
    <div className="wizard-screen complete">
      <h1>Setup Complete</h1>
      <p className="subtitle">Your secrets vault is ready.</p>

      <div className="checklist success">
        <ul>
          <li>Vault created</li>
          <li>Backup key generated</li>
          <li>Secrets encrypted</li>
          <li>CLAUDE.md reference generated</li>
          <li>Claude Code commands installed</li>
        </ul>
      </div>

      <div className="how-it-works">
        <h3>How secrets work with Claude Code:</h3>
        <ul>
          <li>You wrap commands with <code>scrt run</code></li>
          <li>Secrets are injected as environment variables at runtime</li>
          <li>Claude Code never sees the values</li>
        </ul>

        <div className="example-box">
          <p><strong>Example:</strong></p>
          <code>scrt run forge script Deploy.s.sol --private-key $PRIVATE_KEY</code>
          <p className="example-note">PRIVATE_KEY is injected, value stays hidden</p>
        </div>

        <h3>Available Claude Code commands:</h3>
        <ul>
          <li><code>/view</code> - Decrypt and view your secrets (triggers Touch ID)</li>
          <li><code>/learn</code> - Generate CLAUDE.md so Claude knows your secrets</li>
          <li><code>/hide</code> - Verify secrets are properly hidden</li>
        </ul>
      </div>

      <div className="button-group">
        <button className="btn-primary" onClick={onComplete}>
          Open Secrets Manager
        </button>
        {securityMode === 'advanced' && (
          <button
            className="btn-secondary"
            onClick={() => window.electronAPI.openClaudeMd()}
          >
            View CLAUDE.md
          </button>
        )}
      </div>

      <p className="complete-hint">
        You can add, edit, or remove secrets anytime in the Secrets Manager.
      </p>

      <div className="step-indicator">Step 3 of 3</div>
    </div>
  );

  // Render current step
  const renderStep = () => {
    switch (step) {
      case 'welcome':
        return renderWelcome();
      case 'license':
        return renderLicense();
      case 'validating_license':
        return renderValidatingLicense();
      case 'recover':
        return renderRecover();
      case 'recovering':
        return renderRecovering();
      case 'choose_mode':
        return renderChooseMode();
      case 'create_password':
        return renderCreatePassword();
      case 'creating_vault':
        return renderCreatingVault();
      case 'backup_key':
        return renderBackupKey();
      case 'add_secrets':
        return renderAddSecrets();
      case 'encrypting':
        return renderEncrypting();
      case 'session_settings':
        return renderSessionSettings();
      case 'complete':
        return renderComplete();
      default:
        return renderWelcome();
    }
  };

  return (
    <div className="setup-wizard">
      <div className="wizard-container">
        {renderStep()}
      </div>
    </div>
  );
};
