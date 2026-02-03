import { contextBridge, ipcRenderer } from 'electron';

export interface AutoLockSettings {
  enabled: boolean;
  intervalMinutes: number;
  lastActivity: number;
  isLocked: boolean;
}

export interface ImportResult {
  success: boolean;
  imported: {
    settings: boolean;
    wallets: number;
    encryptedEnv: boolean;
  };
  errors: string[];
}

export interface ActivityLog {
  sessionId: string;
  sessionStart: string;
  appVersion: string;
  entries: Array<{
    timestamp: string;
    action: string;
    component: string;
    details?: Record<string, unknown>;
    result?: 'success' | 'failure' | 'pending';
    errorMessage?: string;
  }>;
}

export interface SecretDescription {
  name: string;
  category: string;
  purpose: string;
  whenToUse: string;
  example: string;
}

export interface AIToolsSettings {
  claudeCode: boolean;
  codexCLI: boolean;
}

export interface TransactionDetails {
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

export interface ElectronAPI {
  // Setup Wizard
  checkFirstRun: () => Promise<{success: boolean, isFirstRun: boolean, error?: string}>;
  createVault: (password: string) => Promise<{success: boolean, masterKey?: string, error?: string}>;
  saveSessionSettings: (duration: string) => Promise<{success: boolean, error?: string}>;
  generateClaudeMd: (secretNames: string[]) => Promise<{success: boolean, path?: string, error?: string}>;
  openClaudeMd: () => Promise<{success: boolean, error?: string}>;
  addClaudeWhitelist: () => Promise<{success: boolean, path?: string, error?: string}>;
  installClaudeCommands: () => Promise<{success: boolean, path?: string, error?: string}>;
  recoverSecrets: (encryptedFilePath: string, masterKey: string) => Promise<{success: boolean, error?: string}>;

  // Session Management
  checkSession: () => Promise<{success: boolean, hasSession: boolean, error?: string}>;
  createSession: (keepassPassword: string) => Promise<{success: boolean, error?: string}>;

  // Crypto
  decryptEnv: (masterKey: string) => Promise<{success: boolean, data?: string, error?: string}>;
  encryptEnv: (content: string, masterKey: string) => Promise<{success: boolean, error?: string}>;

  // Wallet
  generateWallet: (network: string) => Promise<{success: boolean, data?: any, error?: string}>;
  storeWallet: (label: string, privateKey: string) => Promise<{success: boolean, error?: string}>;
  getWalletHistory: () => Promise<{success: boolean, data?: any[], error?: string}>;
  getWalletsFromRegistry: () => Promise<{success: boolean, data?: any[], error?: string}>;
  getCurrentWalletId: () => Promise<{success: boolean, data?: number, error?: string}>;

  // Theme
  getTheme: () => Promise<{success: boolean, data?: string, error?: string}>;
  setTheme: (theme: string) => Promise<{success: boolean, error?: string}>;

  // Auto-Lock
  autolockGetSettings: () => Promise<{success: boolean, data?: AutoLockSettings, error?: string}>;
  autolockSetInterval: (minutes: number) => Promise<{success: boolean, error?: string}>;
  autolockRecordActivity: () => Promise<{success: boolean, error?: string}>;
  autolockIsLocked: () => Promise<{success: boolean, data?: boolean, error?: string}>;
  autolockUnlock: () => Promise<{success: boolean, error?: string}>;
  autolockGetTimeRemaining: () => Promise<{success: boolean, data?: number, error?: string}>;
  onAutolockTriggered: (callback: () => void) => void;

  // Backup & Restore
  backupExport: () => Promise<{success: boolean, data?: { path: string, backup: any }, error?: string}>;
  backupImport: () => Promise<{success: boolean, data?: ImportResult, error?: string}>;
  backupValidate: (filePath: string) => Promise<{success: boolean, data?: any, error?: string}>;

  // Activity Logging
  activityLogGet: () => Promise<{success: boolean, data?: ActivityLog, error?: string}>;
  activityLogExport: () => Promise<{success: boolean, data?: { path: string }, error?: string}>;
  activityLogPath: () => Promise<{success: boolean, data?: string, error?: string}>;
  logNavigation: (from: string, to: string) => Promise<{success: boolean}>;
  logClick: (buttonName: string, component: string) => Promise<{success: boolean}>;

  // LLM Secrets
  getSimpleSecretSettings: () => Promise<{success: boolean, data?: any, error?: string}>;
  checkSimpleSecretSetup: () => Promise<{success: boolean, isSetUp?: boolean, hasDpapiKey?: boolean, hasKeePass?: boolean, settings?: any, error?: string}>;
  createSimpleVault: () => Promise<{success: boolean, masterKey?: string, error?: string}>;
  authenticateSimple: () => Promise<{success: boolean, error?: string}>;
  openBackupUpload: () => Promise<{success: boolean, error?: string}>;
  getBackupStatus: () => Promise<{success: boolean, data?: any, error?: string}>;
  setRecoveryPassword: (password: string) => Promise<{success: boolean, error?: string}>;

  // Secret Descriptions
  getSecretDescriptions: () => Promise<{success: boolean, data?: SecretDescription[], error?: string}>;
  saveSecretDescriptions: (descriptions: SecretDescription[]) => Promise<{success: boolean, error?: string}>;
  generateClaudeMdWithDescriptions: (descriptions: SecretDescription[]) => Promise<{success: boolean, path?: string, generatedFiles?: string[], error?: string}>;

  // AI Tools Settings
  getAIToolsSettings: () => Promise<{success: boolean, data?: AIToolsSettings, error?: string}>;
  saveAIToolsSettings: (settings: AIToolsSettings) => Promise<{success: boolean, error?: string}>;
  openAgentsMd: () => Promise<{success: boolean, error?: string}>;

  // License
  activateLicense: (licenseKey: string, email: string) => Promise<{success: boolean, error?: string}>;
  checkLicense: () => Promise<{success: boolean, isLicensed?: boolean, email?: string, activatedAt?: string, error?: string}>;
  removeLicense: () => Promise<{success: boolean, error?: string}>;

  // WSL Daemon (when running in WSL2 environment)
  wslCheckDaemon: () => Promise<{success: boolean, available?: boolean, error?: string}>;
  wslUnlock: (ttl?: number) => Promise<{success: boolean, count?: number, error?: string}>;
  wslStatus: () => Promise<{success: boolean, active?: boolean, remaining?: number, error?: string}>;
  wslListSecrets: () => Promise<{success: boolean, names?: string[], error?: string}>;
  wslLogout: () => Promise<{success: boolean, error?: string}>;
  wslRunCommand: (command: string, workingDir?: string) => Promise<{success: boolean, exitCode?: number, output?: string, error?: string}>;

  // Transaction confirmation
  txConfirm: (txId: string, confirmed: boolean) => Promise<{success: boolean, error?: string}>;
  txGetPending: (txId: string) => Promise<{success: boolean, data?: TransactionDetails, error?: string}>;
  onTxShowConfirm: (callback: (data: TransactionDetails) => void) => void;
}

contextBridge.exposeInMainWorld('electronAPI', {
  // Setup Wizard
  checkFirstRun: () => ipcRenderer.invoke('check-first-run'),
  createVault: (password: string) => ipcRenderer.invoke('create-vault', password),
  saveSessionSettings: (duration: string) => ipcRenderer.invoke('save-session-settings', duration),
  generateClaudeMd: (secretNames: string[]) => ipcRenderer.invoke('generate-claude-md', secretNames),
  openClaudeMd: () => ipcRenderer.invoke('open-claude-md'),
  addClaudeWhitelist: () => ipcRenderer.invoke('add-claude-whitelist'),
  installClaudeCommands: () => ipcRenderer.invoke('install-claude-commands'),
  recoverSecrets: (encryptedFilePath: string, masterKey: string) => ipcRenderer.invoke('recover-secrets', encryptedFilePath, masterKey),

  // Session Management
  checkSession: () => ipcRenderer.invoke('check-session'),
  createSession: (keepassPassword: string) => ipcRenderer.invoke('create-session', keepassPassword),

  // Crypto
  decryptEnv: (masterKey: string) => ipcRenderer.invoke('decrypt-env', masterKey),
  encryptEnv: (content: string, masterKey: string) => ipcRenderer.invoke('encrypt-env', content, masterKey),

  // Wallet
  generateWallet: (network: string) => ipcRenderer.invoke('generate-wallet', network),
  storeWallet: (label: string, privateKey: string) => ipcRenderer.invoke('store-wallet', label, privateKey),
  getWalletHistory: () => ipcRenderer.invoke('get-wallet-history'),
  getWalletsFromRegistry: () => ipcRenderer.invoke('get-wallets-from-registry'),
  getCurrentWalletId: () => ipcRenderer.invoke('get-current-wallet-id'),

  // Theme
  getTheme: () => ipcRenderer.invoke('get-theme'),
  setTheme: (theme: string) => ipcRenderer.invoke('set-theme', theme),

  // Auto-Lock
  autolockGetSettings: () => ipcRenderer.invoke('autolock-get-settings'),
  autolockSetInterval: (minutes: number) => ipcRenderer.invoke('autolock-set-interval', minutes),
  autolockRecordActivity: () => ipcRenderer.invoke('autolock-record-activity'),
  autolockIsLocked: () => ipcRenderer.invoke('autolock-is-locked'),
  autolockUnlock: () => ipcRenderer.invoke('autolock-unlock'),
  autolockGetTimeRemaining: () => ipcRenderer.invoke('autolock-get-time-remaining'),
  onAutolockTriggered: (callback: () => void) => {
    ipcRenderer.on('autolock-triggered', callback);
  },

  // Backup & Restore
  backupExport: () => ipcRenderer.invoke('backup-export'),
  backupImport: () => ipcRenderer.invoke('backup-import'),
  backupValidate: (filePath: string) => ipcRenderer.invoke('backup-validate', filePath),

  // Activity Logging
  activityLogGet: () => ipcRenderer.invoke('activity-log-get'),
  activityLogExport: () => ipcRenderer.invoke('activity-log-export'),
  activityLogPath: () => ipcRenderer.invoke('activity-log-path'),
  logNavigation: (from: string, to: string) => ipcRenderer.invoke('log-navigation', from, to),
  logClick: (buttonName: string, component: string) => ipcRenderer.invoke('log-click', buttonName, component),

  // LLM Secrets
  getSimpleSecretSettings: () => ipcRenderer.invoke('get-llm-secrets-settings'),
  checkSimpleSecretSetup: () => ipcRenderer.invoke('check-llm-secrets-setup'),
  createSimpleVault: () => ipcRenderer.invoke('create-simple-vault'),
  authenticateSimple: () => ipcRenderer.invoke('authenticate-simple'),
  openBackupUpload: () => ipcRenderer.invoke('open-backup-upload'),
  getBackupStatus: () => ipcRenderer.invoke('get-backup-status'),
  setRecoveryPassword: (password: string) => ipcRenderer.invoke('set-recovery-password', password),

  // Secret Descriptions
  getSecretDescriptions: () => ipcRenderer.invoke('get-secret-descriptions'),
  saveSecretDescriptions: (descriptions: SecretDescription[]) => ipcRenderer.invoke('save-secret-descriptions', descriptions),
  generateClaudeMdWithDescriptions: (descriptions: SecretDescription[]) => ipcRenderer.invoke('generate-claude-md-with-descriptions', descriptions),

  // AI Tools Settings
  getAIToolsSettings: () => ipcRenderer.invoke('get-ai-tools-settings'),
  saveAIToolsSettings: (settings: AIToolsSettings) => ipcRenderer.invoke('save-ai-tools-settings', settings),
  openAgentsMd: () => ipcRenderer.invoke('open-agents-md'),

  // License
  activateLicense: (licenseKey: string, email: string) => ipcRenderer.invoke('activate-license', licenseKey, email),
  checkLicense: () => ipcRenderer.invoke('check-license'),
  removeLicense: () => ipcRenderer.invoke('remove-license'),

  // WSL Daemon (when running in WSL2 environment)
  wslCheckDaemon: () => ipcRenderer.invoke('wsl-check-daemon'),
  wslUnlock: (ttl?: number) => ipcRenderer.invoke('wsl-unlock', ttl),
  wslStatus: () => ipcRenderer.invoke('wsl-status'),
  wslListSecrets: () => ipcRenderer.invoke('wsl-list-secrets'),
  wslLogout: () => ipcRenderer.invoke('wsl-logout'),
  wslRunCommand: (command: string, workingDir?: string) => ipcRenderer.invoke('wsl-run-command', command, workingDir),

  // Transaction confirmation
  txConfirm: (txId: string, confirmed: boolean) => ipcRenderer.invoke('tx-confirm', txId, confirmed),
  txGetPending: (txId: string) => ipcRenderer.invoke('tx-get-pending', txId),
  onTxShowConfirm: (callback: (data: TransactionDetails) => void) => {
    ipcRenderer.on('tx-show-confirm', (_event, data) => callback(data));
  },
} as ElectronAPI);

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
