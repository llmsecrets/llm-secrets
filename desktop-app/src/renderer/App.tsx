import * as React from 'react';
import { useState, useEffect } from 'react';
import { SecretManager } from './components/SecretManager';
import { Backup } from './components/Backup';
import { WalletTools } from './components/WalletTools';
import { Settings } from './components/Settings';
import { About } from './components/About';
import { ClaudeMd } from './components/ClaudeMd';
import { TransactionConfirm } from './components/TransactionConfirm';

// v3.2.12 - Setup wizard only on first run (no master key)

interface TransactionDetails {
  id: string;
  to: string;
  toDisplay: string;
  value: string;
  valueDisplay: string;
  gasDisplay: string;
  totalCost: string;
  network: string;
  networkName: string;
  functionName?: string;
  functionArgs?: string[];
  data?: string;
}

type AppState = 'loading' | 'setup' | 'setup-secrets' | 'ready';

export const App: React.FC = () => {
  const [appState, setAppState] = useState<AppState>('loading');
  const [activeTab, setActiveTab] = useState('secrets');
  const [theme, setTheme] = useState('light');
  const [isEditingSecrets, setIsEditingSecrets] = useState(false);
  const [setupError, setSetupError] = useState('');
  const [setupLoading, setSetupLoading] = useState(false);
  const [setupSecrets, setSetupSecrets] = useState('');
  const [pendingTransaction, setPendingTransaction] = useState<TransactionDetails | null>(null);

  useEffect(() => {
    checkSetup();
    loadTheme();

    // Listen for transaction confirmation requests from the main process
    window.electronAPI.onTxShowConfirm((data: TransactionDetails) => {
      setPendingTransaction(data);
    });
  }, []);

  const handleTransactionConfirm = async () => {
    if (!pendingTransaction) return;
    await window.electronAPI.txConfirm(pendingTransaction.id, true);
    setPendingTransaction(null);
  };

  const handleTransactionCancel = async () => {
    if (!pendingTransaction) return;
    await window.electronAPI.txConfirm(pendingTransaction.id, false);
    setPendingTransaction(null);
  };

  const checkSetup = async () => {
    try {
      const result = await window.electronAPI.checkSimpleSecretSetup();
      if (result.success && result.isSetUp) {
        setAppState('ready');
      } else if (result.success && result.hasDpapiKey) {
        // Vault exists but no encrypted env file yet — need initial secrets
        setAppState('setup-secrets');
      } else {
        setAppState('setup');
      }
    } catch {
      setAppState('setup');
    }
  };

  const handleSetup = async () => {
    setSetupLoading(true);
    setSetupError('');
    try {
      const result = await window.electronAPI.createSimpleVault();
      if (result.success) {
        setAppState('setup-secrets');
      } else {
        setSetupError(result.error || 'Setup failed');
      }
    } catch (err) {
      setSetupError((err as Error).message);
    } finally {
      setSetupLoading(false);
    }
  };

  const handleSaveInitialSecrets = async () => {
    if (!setupSecrets.trim()) {
      setSetupError('Enter at least one secret (e.g. API_KEY=your_key)');
      return;
    }
    setSetupLoading(true);
    setSetupError('');
    try {
      // Ensure we have an active session (authenticate if needed)
      const authResult = await window.electronAPI.authenticateSimple();
      if (!authResult.success) {
        setSetupError(authResult.error || 'Authentication failed');
        setSetupLoading(false);
        return;
      }
      const result = await window.electronAPI.encryptEnv(setupSecrets, '');
      if (result.success) {
        // Parse secret names and save descriptions for the Claude MD tab
        const names = setupSecrets.split('\n')
          .map(l => l.trim())
          .filter(l => l && !l.startsWith('#') && l.includes('='))
          .map(l => l.split('=')[0].trim())
          .filter(Boolean);
        if (names.length > 0) {
          const descriptions = names.map(name => ({
            name,
            category: 'other',
            purpose: 'User-defined',
            whenToUse: '',
            example: `process.env.${name}`,
          }));
          await window.electronAPI.saveSecretDescriptions(descriptions);
          await window.electronAPI.generateClaudeMdWithDescriptions(descriptions);
          await window.electronAPI.addClaudeWhitelist();
        }
        setAppState('ready');
      } else {
        setSetupError(result.error || 'Encryption failed');
      }
    } catch (err) {
      setSetupError((err as Error).message);
    } finally {
      setSetupLoading(false);
    }
  };

  const loadTheme = async () => {
    const result = await window.electronAPI.getTheme();
    if (result.success && result.data) {
      setTheme(result.data);
      document.documentElement.setAttribute('data-theme', result.data);
    }
  };

  const toggleTheme = async () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    await window.electronAPI.setTheme(newTheme);
  };

  // Loading state
  if (appState === 'loading') {
    return (
      <div className="app loading-screen">
        <div className="loading-content">
          <h1>LLM Secrets</h1>
          <div className="loading-spinner"></div>
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  // Setup state - first run, need to create vault
  if (appState === 'setup') {
    return (
      <div className="app loading-screen">
        <div className="loading-content">
          <h1>LLM Secrets</h1>
          <p style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>
            First-time setup: create your encrypted vault.
          </p>
          <p style={{ marginBottom: '1.5rem', fontSize: '14px', color: 'var(--text-secondary)' }}>
            You'll authenticate with {navigator.platform.startsWith('Mac') ? 'Touch ID or your password' : 'Windows Hello'} to generate a master key stored securely in your {navigator.platform.startsWith('Mac') ? 'Keychain' : 'Credential Manager'}.
          </p>
          <button
            className="btn-primary"
            onClick={handleSetup}
            disabled={setupLoading}
            style={{ padding: '0.75rem 2rem', fontSize: '16px' }}
          >
            {setupLoading ? 'Setting up...' : 'Create Vault'}
          </button>
          {setupError && <div className="error-message" style={{ marginTop: '1rem' }}>{setupError}</div>}
        </div>
      </div>
    );
  }

  // Setup secrets state - vault created, now enter initial secrets
  if (appState === 'setup-secrets') {
    return (
      <div className="app" style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
        <header className="app-header">
          <div className="header-content">
            <h1>LLM Secrets</h1>
            <p>Add your secrets to get started</p>
          </div>
        </header>
        <main className="app-content" style={{ padding: '2rem 2.5rem' }}>
          <div className="card">
            <h2>Add Your Secrets</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              Enter your environment variables below. These will be encrypted and stored securely.
            </p>
            <textarea
              className="code-editor"
              value={setupSecrets}
              onChange={(e) => setSetupSecrets(e.target.value)}
              placeholder={"# Add your secrets in KEY=VALUE format\nAPI_KEY=your_api_key_here\nDATABASE_URL=postgresql://...\nPRIVATE_KEY=0x..."}
              rows={12}
              style={{ width: '100%', fontFamily: 'monospace', fontSize: '14px', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--card-background)', color: 'var(--text-primary)', resize: 'vertical' }}
            />
            <div style={{ marginTop: '1.5rem', display: 'flex', gap: '1rem' }}>
              <button
                className="btn-primary"
                onClick={handleSaveInitialSecrets}
                disabled={setupLoading || !setupSecrets.trim()}
              >
                {setupLoading ? 'Encrypting...' : 'Encrypt and Save'}
              </button>
            </div>
            {setupError && <div className="error-message" style={{ marginTop: '1rem' }}>{setupError}</div>}
          </div>
        </main>
      </div>
    );
  }

  // Normal app
  return (
    <div className="app">
      <header className="app-header">
        <div className="header-content">
          <h1>LLM Secrets</h1>
          <p>{navigator.platform.startsWith('Mac') ? 'Touch ID' : 'Windows Hello'} Protected Secrets</p>
        </div>
        <div className="header-actions">
          <a
            className="github-stars-btn"
            href="#"
            onClick={(e) => {
              e.preventDefault();
              // TODO: Connect to actual repo when public
              // window.electronAPI.openExternal('https://github.com/your-org/llm-secrets');
            }}
            title="Star on GitHub"
          >
            <svg className="github-icon" viewBox="0 0 16 16" width="16" height="16" fill="currentColor">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
            </svg>
            <svg className="star-icon" viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
              <path d="M8 .25a.75.75 0 01.673.418l1.882 3.815 4.21.612a.75.75 0 01.416 1.279l-3.046 2.97.719 4.192a.75.75 0 01-1.088.791L8 12.347l-3.766 1.98a.75.75 0 01-1.088-.79l.72-4.194L.818 6.374a.75.75 0 01.416-1.28l4.21-.611L7.327.668A.75.75 0 018 .25z"/>
            </svg>
            <span className="star-count">--</span>
          </a>
          <button className="theme-toggle" onClick={toggleTheme}>
            {theme === 'light' ? '🌙' : '☀️'}
          </button>
        </div>
      </header>

      {!isEditingSecrets && (
        <nav className="tab-nav">
          <button
            className={`tab ${activeTab === 'secrets' ? 'active' : ''}`}
            onClick={() => setActiveTab('secrets')}
          >
            Secrets
          </button>
          <button
            className={`tab ${activeTab === 'backup' ? 'active' : ''}`}
            onClick={() => setActiveTab('backup')}
          >
            Backup
          </button>
          <button
            className={`tab ${activeTab === 'wallets' ? 'active' : ''}`}
            onClick={() => setActiveTab('wallets')}
          >
            Wallet Tools
          </button>
          <button
            className={`tab ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            Settings
          </button>
          <button
            className={`tab ${activeTab === 'about' ? 'active' : ''}`}
            onClick={() => setActiveTab('about')}
          >
            About
          </button>
          <button
            className={`tab ${activeTab === 'claude' ? 'active' : ''}`}
            onClick={() => setActiveTab('claude')}
          >
            Claude MD
          </button>
        </nav>
      )}

      <main className="app-content">
        {activeTab === 'secrets' && <SecretManager onEditingChange={setIsEditingSecrets} />}
        {activeTab === 'backup' && <Backup />}
        {activeTab === 'wallets' && <WalletTools />}
        {activeTab === 'settings' && <Settings />}
        {activeTab === 'about' && <About />}
        {activeTab === 'claude' && <ClaudeMd />}
      </main>

      <footer className="app-footer">
        <span>LLM Secrets v3.1.0 ({navigator.platform.startsWith('Mac') ? 'macOS' : 'Windows'})</span>
        <span>GPL-3.0 License</span>
      </footer>

      {/* Transaction Confirmation Modal */}
      <TransactionConfirm
        transaction={pendingTransaction}
        onConfirm={handleTransactionConfirm}
        onCancel={handleTransactionCancel}
      />
    </div>
  );
};
