import { app, BrowserWindow, ipcMain, dialog, shell } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import { platform } from 'os';
import { WalletService } from './main/services/WalletService';
import { CryptoService } from './main/services/CryptoService';
import { AutoLockService, AutoLockInterval } from './main/services/AutoLockService';
import { BackupRestoreService } from './main/services/BackupRestoreService';
import { getActivityLogger } from './main/services/UserActivityLogger';
import { licenseService, LicenseService } from './main/services/LicenseService';
import { AuthServiceMac } from './main/services/AuthServiceMac';
import { CryptoServiceMac } from './main/services/CryptoServiceMac';
import { CryptoServiceWsl, getCryptoService as getWslCryptoService } from './main/services/CryptoServiceWsl';
// Transaction server removed - using minimal CLI instead (resources/scrt-tx.js)

const IS_MAC = platform() === 'darwin';
const IS_WIN = platform() === 'win32';
const IS_LINUX = platform() === 'linux';

// Set app name for dock/taskbar (needed in dev mode)
app.setName('LLM Secrets');

// macOS services (initialized on macOS only)
let macAuthService: AuthServiceMac | null = null;
let macCryptoService: CryptoServiceMac | null = null;

// WSL service (initialized on Linux/WSL only)
let wslCryptoService: CryptoServiceWsl | null = null;

if (IS_MAC) {
  macAuthService = new AuthServiceMac();
  macCryptoService = new CryptoServiceMac();
}

if (IS_LINUX) {
  wslCryptoService = getWslCryptoService();
}

declare const MAIN_WINDOW_WEBPACK_ENTRY: string;
declare const MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY: string;

if (require('electron-squirrel-startup')) {
  app.quit();
}

let mainWindow: BrowserWindow | null = null;
const walletService = new WalletService();
const cryptoService = new CryptoService();
const autoLockService = new AutoLockService();
const backupRestoreService = new BackupRestoreService();
const activityLogger = getActivityLogger();

// Path constants - portable paths that work on any machine
// User data goes in app.getPath('userData'), bundled resources in app's resources folder
const getResourcesPath = () => {
  // In production, resources are in the app's resources folder
  // In development, they're in the project's resources folder
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'resources');
  }
  return path.join(__dirname, '..', '..', 'resources');
};

const getUserDataPath = () => app.getPath('userData');

// These paths are computed after app is ready
let RESOURCES_PATH: string;
let USER_DATA_PATH: string;
let ENV_CRYPTO_PATH: string;
let KDBX_PATH: string;
let SETTINGS_PATH: string;
let CLAUDE_MD_PATH: string;
let AGENTS_MD_PATH: string;
let ENV_FOLDER_PATH: string;
let SECRET_DESCRIPTIONS_PATH: string;
let AI_TOOLS_SETTINGS_PATH: string;

// Helper function to recursively copy a folder
const copyFolderRecursive = (src: string, dest: string) => {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyFolderRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
};

const initializePaths = () => {
  RESOURCES_PATH = getResourcesPath();
  USER_DATA_PATH = getUserDataPath();
  ENV_CRYPTO_PATH = USER_DATA_PATH; // User data is stored in userData folder
  KDBX_PATH = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.kdbx');
  SETTINGS_PATH = path.join(ENV_CRYPTO_PATH, 'settings.json');
  CLAUDE_MD_PATH = path.join(USER_DATA_PATH, 'CLAUDE.md');
  AGENTS_MD_PATH = path.join(USER_DATA_PATH, 'AGENTS.md');
  ENV_FOLDER_PATH = path.join(USER_DATA_PATH, 'env');
  SECRET_DESCRIPTIONS_PATH = path.join(ENV_CRYPTO_PATH, 'secret-descriptions.json');
  AI_TOOLS_SETTINGS_PATH = path.join(ENV_CRYPTO_PATH, 'ai-tools-settings.json');

  // Ensure directories exist
  if (!fs.existsSync(ENV_FOLDER_PATH)) {
    fs.mkdirSync(ENV_FOLDER_PATH, { recursive: true });
  }

  // Platform-specific resource copying
  if (IS_WIN) {
    // Copy bundled module to userData if not present (for PowerShell to find it)
    const bundledModule = path.join(RESOURCES_PATH, 'EnvCrypto.psm1');
    const userModule = path.join(USER_DATA_PATH, 'EnvCrypto.psm1');
    if (fs.existsSync(bundledModule) && !fs.existsSync(userModule)) {
      fs.copyFileSync(bundledModule, userModule);
    }

    // Copy WindowsHelloAuth.exe to userData
    const bundledAuth = path.join(RESOURCES_PATH, 'WindowsHelloAuth.exe');
    const userAuth = path.join(USER_DATA_PATH, 'WindowsHelloAuth.exe');
    if (fs.existsSync(bundledAuth) && !fs.existsSync(userAuth)) {
      fs.copyFileSync(bundledAuth, userAuth);
    }

    // Copy PoShKeePass folder to userData (required by EnvCrypto.psm1)
    const bundledPoShKeePass = path.join(RESOURCES_PATH, 'PoShKeePass');
    const userPoShKeePass = path.join(USER_DATA_PATH, 'PoShKeePass');
    if (fs.existsSync(bundledPoShKeePass) && !fs.existsSync(userPoShKeePass)) {
      copyFolderRecursive(bundledPoShKeePass, userPoShKeePass);
    }
  }

  if (IS_MAC) {
    // Copy Touch ID helper to userData if needed
    const touchIdSource = path.join(RESOURCES_PATH, 'macos', 'TouchIDAuth');
    const touchIdDest = path.join(USER_DATA_PATH, 'TouchIDAuth');
    if (fs.existsSync(touchIdSource) && !fs.existsSync(touchIdDest)) {
      fs.copyFileSync(touchIdSource, touchIdDest);
      fs.chmodSync(touchIdDest, 0o755);
    }
  }

  console.log('[LLM Secrets] Paths initialized:');
  console.log('  Resources:', RESOURCES_PATH);
  console.log('  User Data:', USER_DATA_PATH);
};

// AI Tools settings interface
interface AIToolsSettings {
  claudeCode: boolean;
  codexCLI: boolean;
}

const DEFAULT_AI_TOOLS: AIToolsSettings = {
  claudeCode: true,
  codexCLI: true,
};

// Helper to get AI tools settings
function getAIToolsSettings(): AIToolsSettings {
  try {
    if (fs.existsSync(AI_TOOLS_SETTINGS_PATH)) {
      return JSON.parse(fs.readFileSync(AI_TOOLS_SETTINGS_PATH, 'utf8'));
    }
  } catch {
    // Fall through to default
  }
  return DEFAULT_AI_TOOLS;
}

// Helper to generate CLAUDE.md content
function generateClaudeMdContent(descriptions: SecretDescription[]): string {
  const categoryGroups: Record<string, SecretDescription[]> = {};
  for (const desc of descriptions) {
    const cat = desc.category || 'other';
    if (!categoryGroups[cat]) categoryGroups[cat] = [];
    categoryGroups[cat].push(desc);
  }

  let secretsSection = '';
  for (const [category, secrets] of Object.entries(categoryGroups)) {
    const categoryLabel = {
      blockchain: 'Blockchain / Web3',
      api: 'API Keys',
      database: 'Database',
      cloud: 'Cloud Services',
      git: 'Git / GitHub',
      paths: 'Local Paths',
      auth: 'Authentication',
      other: 'Other',
    }[category] || category;

    secretsSection += `\n### ${categoryLabel}\n\n`;
    secretsSection += '| Name | Purpose | When to Use | Example |\n';
    secretsSection += '|------|---------|-------------|----------|\n';
    for (const s of secrets) {
      const example = s.example ? `\`${s.example}\`` : '-';
      secretsSection += `| ${s.name} | ${s.purpose || '-'} | ${s.whenToUse || '-'} | ${example} |\n`;
    }
  }

  return `# LLM Secrets - Secret Access Reference

## How Secret Injection Works

Secrets are stored encrypted and injected at runtime as environment
variables using the \`scrt\` CLI. You NEVER see the actual values.

### Injection Mechanism

\`\`\`
+----------------+     +------------------+     +----------------+
| Your Command   | --> | scrt run ...     | --> | Command runs   |
| (no secrets)   |     | injects env vars |     | with secrets   |
+----------------+     +------------------+     +----------------+
\`\`\`

The secret value exists ONLY in the subprocess environment.
It is never written to disk or returned to the LLM.

---

## Stored Secrets
${secretsSection}
---

## How to Run Commands with Secrets

Wrap your command with \`scrt run\`. Secrets are injected as standard
environment variables. Programs read them via \`process.env.KEY\` (Node),
\`os.environ['KEY']\` (Python), \`std::env::var("KEY")\` (Rust), etc.

### Examples

**Node.js script reading from env:**
\`\`\`bash
scrt run node deploy.js
# deploy.js uses: const key = process.env.PRIVATE_KEY
\`\`\`

**Python script:**
\`\`\`bash
scrt run python3 script.py
# script.py uses: key = os.environ['API_KEY']
\`\`\`

**Verify what's injected (safe — values only in subprocess):**
\`\`\`bash
scrt run env | grep PRIVATE_KEY
\`\`\`

**Selective injection:**
\`\`\`bash
scrt run --only API_KEY,DB_URL node server.js
\`\`\`

**List available secrets:**
\`\`\`bash
scrt list
\`\`\`

---

## Adding or Editing Secrets

Open the LLM Secrets app and use the Secrets tab to add or edit secrets.
After editing, regenerate this file from the Claude MD tab.

---

## What You Can See vs. What You Cannot

| You CAN See | You CANNOT See |
|-------------|----------------|
| Secret names (e.g., PRIVATE_KEY) | Secret values (e.g., 0x7f3a...) |
| Command structure | The actual injected value |
| Transaction hashes | Private keys |
| Success/failure messages | Passwords or tokens |

---

## Security Model

**Always true, regardless of settings:**

1. **LLM never sees secrets** - Values are never returned to Claude Code
2. **LLM can use secrets** - Wrap commands with \`scrt run\`, values injected at runtime
3. **Secrets exist only in subprocess** - Isolated from main process memory
4. **Touch ID required** - Master key stored in macOS Keychain

---

## Troubleshooting

### "Could not retrieve master key"
The Keychain item may require the LLM Secrets app to be set up.
Open the app and complete the setup wizard.

### "No encrypted .env file found"
No secrets have been saved yet. Open LLM Secrets and add secrets.

### "Command failed"
Check if the command syntax is correct. The secret injection happens
transparently - if the command fails, it's likely a command issue,
not a secret issue.

---

*Generated by LLM Secrets*
`;
}

// Helper to generate AGENTS.md content for Codex CLI
function generateAgentsMdContent(descriptions: SecretDescription[]): string {
  const categoryGroups: Record<string, SecretDescription[]> = {};
  for (const desc of descriptions) {
    const cat = desc.category || 'other';
    if (!categoryGroups[cat]) categoryGroups[cat] = [];
    categoryGroups[cat].push(desc);
  }

  let secretsSection = '';
  for (const [category, secrets] of Object.entries(categoryGroups)) {
    const categoryLabel = {
      blockchain: 'Blockchain / Web3',
      api: 'API Keys',
      database: 'Database',
      cloud: 'Cloud Services',
      git: 'Git / GitHub',
      paths: 'Local Paths',
      auth: 'Authentication',
      other: 'Other',
    }[category] || category;

    secretsSection += `\n### ${categoryLabel}\n\n`;
    secretsSection += '| Name | Purpose | When to Use | Example |\n';
    secretsSection += '|------|---------|-------------|----------|\n';
    for (const s of secrets) {
      const example = s.example ? `\`${s.example}\`` : '-';
      secretsSection += `| ${s.name} | ${s.purpose || '-'} | ${s.whenToUse || '-'} | ${example} |\n`;
    }
  }

  return `# Project Agent Instructions

## Secret Management with LLM Secrets

This project uses LLM Secrets for secure credential management.
Secrets are encrypted at rest and injected at runtime via the \`scrt\` CLI.

**IMPORTANT: You NEVER see secret values. You can only use them via \`scrt run\`.**

---

## Available Secrets
${secretsSection}
---

## How to Use Secrets

Wrap your command with \`scrt run\`. Secrets are injected as standard
environment variables. Programs read them via \`process.env.KEY\` (Node),
\`os.environ['KEY']\` (Python), \`std::env::var("KEY")\` (Rust), etc.

### Examples

**Node.js script reading from env:**
\`\`\`bash
scrt run node deploy.js
# deploy.js uses: const key = process.env.PRIVATE_KEY
\`\`\`

**Python script:**
\`\`\`bash
scrt run python3 script.py
# script.py uses: key = os.environ['API_KEY']
\`\`\`

**Verify what's injected (safe — values only in subprocess):**
\`\`\`bash
scrt run env | grep PRIVATE_KEY
\`\`\`

**Selective injection:**
\`\`\`bash
scrt run --only API_KEY,DB_URL node server.js
\`\`\`

**List available secrets:**
\`\`\`bash
scrt list
\`\`\`

---

## Security Rules

1. **Never output secret values** - They should never appear in logs, output, or files
2. **Never hardcode secrets** - Always use \`scrt run\` and read from env (e.g. \`process.env.KEY\`)
3. **Never commit secrets** - The .env file is encrypted; only .env.encrypted is safe
4. **Secrets exist only at runtime** - They're injected into the subprocess environment

---

## Adding New Secrets

If you need a secret that doesn't exist:

1. Ask the user to add it via the LLM Secrets app
2. The secret becomes available as \`process.env.KEY\` when using \`scrt run\`

---

## Troubleshooting

- **Secret not found**: Check the secret name matches exactly (case-sensitive)
- **Could not retrieve master key**: LLM Secrets app needs setup
- **Command failed**: Verify command syntax; secret injection is transparent

---

*Generated by LLM Secrets*
`;
}

// Secret description interface
interface SecretDescription {
  name: string;
  category: string;
  purpose: string;
  whenToUse: string;
  example: string;
}

// Versioned env file helpers - never overwrite, always create new version
function getEnvVersions(): number[] {
  if (!fs.existsSync(ENV_FOLDER_PATH)) return [];
  const files = fs.readdirSync(ENV_FOLDER_PATH);
  const versions: number[] = [];
  for (const file of files) {
    const match = file.match(/^\.env\.encrypted\.v(\d+)$/);
    if (match) versions.push(parseInt(match[1], 10));
  }
  return versions.sort((a, b) => a - b);
}

function getHighestEnvVersion(): number {
  const versions = getEnvVersions();
  return versions.length > 0 ? versions[versions.length - 1] : 0;
}

function getNextEnvVersionPath(): string {
  if (!fs.existsSync(ENV_FOLDER_PATH)) {
    fs.mkdirSync(ENV_FOLDER_PATH, { recursive: true });
  }
  const nextVersion = getHighestEnvVersion() + 1;
  return path.join(ENV_FOLDER_PATH, `.env.encrypted.v${nextVersion}`);
}

const createWindow = (): void => {
  const iconPath = app.isPackaged
    ? path.join(process.resourcesPath, 'assets', 'icon.png')
    : path.join(app.getAppPath(), 'assets', 'icon.png');

  // Set dock icon on macOS
  if (IS_MAC && app.dock) {
    const { nativeImage } = require('electron');
    const icon = nativeImage.createFromPath(iconPath);
    if (!icon.isEmpty()) {
      app.dock.setIcon(icon);
    }
  }

  mainWindow = new BrowserWindow({
    height: 800,
    width: 1200,
    minHeight: 600,
    minWidth: 900,
    title: 'LLM Secrets',
    icon: iconPath,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);

  // Remove DevTools in production
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }
};

// IPC Handlers
ipcMain.handle('decrypt-env', async (_event, masterKey: string) => {
  activityLogger.log('decrypt_attempt', 'SecretManager', { masterKeyLength: masterKey?.length || 0 }, 'pending');

  // macOS: use Node.js crypto service
  if (IS_MAC && macCryptoService) {
    try {
      if (!macCryptoService.isSessionActive()) {
        return { success: false, error: 'Session expired. Authenticate with Touch ID.' };
      }
      const decrypted = macCryptoService.decryptEnv();
      activityLogger.logSuccess('decrypt_env', 'SecretManager', { contentLength: decrypted?.length || 0 });

      return { success: true, data: decrypted };
    } catch (error) {
      const errorMsg = (error as Error).message;
      activityLogger.logFailure('decrypt_env', 'SecretManager', errorMsg);
      return { success: false, error: errorMsg };
    }
  }

  // Windows: use PowerShell crypto service
  try {
    const decrypted = await cryptoService.decrypt(masterKey);
    activityLogger.logSuccess('decrypt_env', 'SecretManager', { contentLength: decrypted?.length || 0 });

    return { success: true, data: decrypted };
  } catch (error) {
    const errorMsg = (error as Error).message;
    activityLogger.logFailure('decrypt_env', 'SecretManager', errorMsg);
    return { success: false, error: errorMsg };
  }
});

ipcMain.handle('encrypt-env', async (_event, content: string, masterKey: string) => {
  activityLogger.log('encrypt_attempt', 'SecretManager', { contentLength: content?.length || 0 }, 'pending');

  // macOS: use Node.js crypto service for encryption
  if (IS_MAC && macCryptoService) {
    try {
      if (!macCryptoService.isSessionActive()) {
        return { success: false, error: 'Session expired. Authenticate with Touch ID.' };
      }
      macCryptoService.encryptEnv(content);
      activityLogger.logSuccess('encrypt_env', 'SecretManager');
      return { success: true };
    } catch (error) {
      const errorMsg = (error as Error).message;
      activityLogger.logFailure('encrypt_env', 'SecretManager', errorMsg);
      return { success: false, error: errorMsg };
    }
  }

  // Windows: use PowerShell crypto service
  try {
    await cryptoService.encrypt(content, masterKey);
    activityLogger.logSuccess('encrypt_env', 'SecretManager');

    // Auto-update secret descriptions with any new secrets
    try {
      // Parse secret names from content
      const secretNames: string[] = [];
      const lines = content.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        // Skip comments and empty lines
        if (!trimmed || trimmed.startsWith('#')) continue;
        // Match KEY=value pattern
        const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=/);
        if (match) {
          secretNames.push(match[1]);
        }
      }

      // Load existing descriptions
      let descriptions: SecretDescription[] = [];
      if (fs.existsSync(SECRET_DESCRIPTIONS_PATH)) {
        try {
          descriptions = JSON.parse(fs.readFileSync(SECRET_DESCRIPTIONS_PATH, 'utf8'));
        } catch {
          descriptions = [];
        }
      }

      // Add placeholder for any new secrets not already described
      const existingNames = new Set(descriptions.map(d => d.name));
      let addedNew = false;
      for (const name of secretNames) {
        if (!existingNames.has(name)) {
          descriptions.push({
            name,
            category: 'other',
            purpose: '',
            whenToUse: '',
            example: `process.env.${name}`,
          });
          addedNew = true;
        }
      }

      // Remove descriptions for secrets that no longer exist
      const currentNames = new Set(secretNames);
      descriptions = descriptions.filter(d => currentNames.has(d.name));

      // Save updated descriptions
      fs.writeFileSync(SECRET_DESCRIPTIONS_PATH, JSON.stringify(descriptions, null, 2), 'utf8');

      // Auto-generate instruction files based on AI tools settings
      if (descriptions.length > 0) {
        const aiSettings = getAIToolsSettings();

        // Generate CLAUDE.md for Claude Code
        if (aiSettings.claudeCode) {
          const claudeMdContent = generateClaudeMdContent(descriptions);
          fs.writeFileSync(CLAUDE_MD_PATH, claudeMdContent, 'utf8');
        }

        // Generate AGENTS.md for Codex CLI
        if (aiSettings.codexCLI) {
          const agentsMdContent = generateAgentsMdContent(descriptions);
          fs.writeFileSync(AGENTS_MD_PATH, agentsMdContent, 'utf8');
        }
      }
    } catch (descError) {
      // Don't fail the encryption if description update fails
      console.log('[encrypt-env] Failed to update descriptions:', (descError as Error).message);
    }

    return { success: true };
  } catch (error) {
    const errorMsg = (error as Error).message;
    activityLogger.logFailure('encrypt_env', 'SecretManager', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Session Management IPC Handlers
ipcMain.handle('check-session', async () => {
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    const modulePath = path.join(USER_DATA_PATH, 'EnvCrypto.psm1');
    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      Import-Module '${modulePath}' -Force
      $session = Get-SessionKey
      if ($session) {
        Write-Output "ACTIVE"
      } else {
        Write-Output "NONE"
      }
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
    const { stdout } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const hasSession = stdout?.trim() === 'ACTIVE';
    return { success: true, hasSession };
  } catch (error) {
    return { success: false, hasSession: false, error: (error as Error).message };
  }
});

ipcMain.handle('create-session', async (_event, keepassPassword: string) => {
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    const authExePath = path.join(USER_DATA_PATH, 'WindowsHelloAuth.exe');
    const modulePath = path.join(USER_DATA_PATH, 'EnvCrypto.psm1');

    // Step 1: Run Windows Hello authentication via PowerShell Start-Process
    console.log('[Session] Starting Windows Hello authentication...');

    const authCommand = `
      $process = Start-Process -FilePath '${authExePath}' -Wait -PassThru -NoNewWindow
      exit $process.ExitCode
    `;
    const authEncodedCommand = Buffer.from(authCommand, 'utf16le').toString('base64');

    try {
      await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${authEncodedCommand}`);
    } catch (authError: unknown) {
      const errorMessage = authError instanceof Error ? authError.message : 'Unknown error';
      console.log('[Session] Windows Hello auth failed:', errorMessage);
      return { success: false, error: 'Windows Hello authentication failed or was cancelled' };
    }
    console.log('[Session] Windows Hello authentication successful');

    // Step 2: Verify KeePass password and create session
    const escapedPassword = keepassPassword.replace(/'/g, "''");
    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force

        # Convert password to SecureString
        $securePassword = ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force

        # Verify password by trying to get master key
        $masterKey = Get-MasterKeyFromKeePass -DatabasePassword $securePassword
        if (-not $masterKey) {
          Write-Output "ERROR:Invalid KeePass password"
          return
        }

        # Cache the KeePass password (DPAPI-encrypted) for the session
        $encryptedPassword = ConvertFrom-SecureString -SecureString $securePassword

        # Store encrypted password with expiry metadata (2 hours)
        $metadata = @{
          CreatedAt = (Get-Date).ToString("o")
          ExpiresAt = (Get-Date).AddHours(2).ToString("o")
          Type = "KeePassSession"
        }

        Save-SecureCredential -Target 'EnvCrypto_SessionKey' -Value $encryptedPassword -Metadata $metadata

        Write-Output "SUCCESS"
      } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
      }
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
    const { stdout, stderr } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const output = stdout?.trim() || '';
    if (output === 'SUCCESS') {
      console.log('[Session] Session created successfully');
      return { success: true };
    } else if (output.startsWith('ERROR:')) {
      return { success: false, error: output.substring(6) };
    } else {
      return { success: false, error: stderr || 'Unknown error creating session' };
    }
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('prompt-keepass-password', async () => {
  // Show Electron dialog for KeePass password
  const result = await dialog.showMessageBox(mainWindow!, {
    type: 'question',
    title: 'KeePass Authentication',
    message: 'Enter your KeePass database password',
    detail: 'This password unlocks your encrypted master key.',
    buttons: ['Cancel'],
  });

  // For now, return that we need a custom dialog
  // The actual password input will be in the renderer
  return { success: true, needsInput: true };
});

ipcMain.handle('generate-wallet', async (_event, network: string) => {
  try {
    const wallet = await walletService.generateWallet(network);

    // Add wallet keys as secret descriptions
    const walletSecrets: SecretDescription[] = [
      {
        name: `WALLET_${wallet.walletId}_PRIVATE_KEY`,
        category: 'wallet',
        purpose: `Private key for wallet #${wallet.walletId} (${network})`,
        whenToUse: `When signing transactions on ${network}`,
        example: `process.env.WALLET_${wallet.walletId}_PRIVATE_KEY`,
      },
      {
        name: `WALLET_${wallet.walletId}_MNEMONIC`,
        category: 'wallet',
        purpose: `Recovery phrase for wallet #${wallet.walletId} (${network})`,
        whenToUse: `When recovering wallet #${wallet.walletId}`,
        example: `process.env.WALLET_${wallet.walletId}_MNEMONIC`,
      },
    ];

    // Merge with existing descriptions
    let existing: SecretDescription[] = [];
    if (fs.existsSync(SECRET_DESCRIPTIONS_PATH)) {
      try {
        existing = JSON.parse(fs.readFileSync(SECRET_DESCRIPTIONS_PATH, 'utf8'));
      } catch { /* ignore parse errors */ }
    }

    const existingNames = new Set(existing.map(d => d.name));
    for (const desc of walletSecrets) {
      if (!existingNames.has(desc.name)) {
        existing.push(desc);
      }
    }

    fs.writeFileSync(SECRET_DESCRIPTIONS_PATH, JSON.stringify(existing, null, 2), 'utf8');

    // Regenerate CLAUDE.md
    const aiSettings = getAIToolsSettings();
    if (aiSettings.claudeCode) {
      const claudeMdContent = generateClaudeMdContent(existing);
      fs.writeFileSync(CLAUDE_MD_PATH, claudeMdContent, 'utf8');
    }

    return { success: true, data: wallet };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('store-wallet', async (_event, label: string, privateKey: string) => {
  try {
    await walletService.storePrivateKey(label, privateKey);
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('get-wallet-history', async () => {
  try {
    const history = await walletService.getWalletHistory();
    return { success: true, data: history };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('get-wallets-from-registry', async () => {
  try {
    const wallets = await walletService.getWalletsFromRegistry();
    return { success: true, data: wallets };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('get-current-wallet-id', async () => {
  try {
    const currentId = await walletService.getCurrentWalletId();
    return { success: true, data: currentId };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('get-theme', async () => {
  try {
    const theme = await cryptoService.getSetting('theme', 'light');
    return { success: true, data: theme };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('set-theme', async (_event, theme: string) => {
  try {
    await cryptoService.saveSetting('theme', theme);
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Auto-Lock IPC Handlers
ipcMain.handle('autolock-get-settings', async () => {
  try {
    const settings = autoLockService.getSettings();
    return { success: true, data: settings };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('autolock-set-interval', async (_event, minutes: AutoLockInterval) => {
  try {
    await autoLockService.setInterval(minutes);
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('autolock-record-activity', async () => {
  try {
    autoLockService.recordActivity();
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('autolock-is-locked', async () => {
  try {
    const isLocked = autoLockService.isLocked();
    return { success: true, data: isLocked };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('autolock-unlock', async () => {
  try {
    autoLockService.unlock();
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('autolock-get-time-remaining', async () => {
  try {
    const remaining = autoLockService.getTimeRemaining();
    return { success: true, data: remaining };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Backup & Restore IPC Handlers
ipcMain.handle('backup-export', async () => {
  activityLogger.log('backup_export_dialog', 'Settings', {}, 'pending');
  try {
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Export LLM Secrets Backup',
      defaultPath: `scrt-backup-${new Date().toISOString().split('T')[0]}.json`,
      filters: [{ name: 'JSON Files', extensions: ['json'] }],
    });

    if (result.canceled || !result.filePath) {
      activityLogger.log('backup_export_cancelled', 'Settings', {}, 'failure', 'User cancelled');
      return { success: false, error: 'Export cancelled' };
    }

    const backup = await backupRestoreService.exportBackup(result.filePath);
    activityLogger.logSuccess('backup_export', 'Settings', {
      path: result.filePath,
      encryptedEnvIncluded: backup.metadata.encryptedEnvIncluded,
      walletCount: backup.wallets.length,
    });
    return { success: true, data: { path: result.filePath, backup } };
  } catch (error) {
    const errorMsg = (error as Error).message;
    activityLogger.logFailure('backup_export', 'Settings', errorMsg);
    return { success: false, error: errorMsg };
  }
});

ipcMain.handle('backup-import', async () => {
  activityLogger.log('backup_import_dialog', 'Settings', {}, 'pending');
  try {
    const result = await dialog.showOpenDialog(mainWindow!, {
      title: 'Import LLM Secrets Backup',
      filters: [{ name: 'JSON Files', extensions: ['json'] }],
      properties: ['openFile'],
    });

    if (result.canceled || result.filePaths.length === 0) {
      activityLogger.log('backup_import_cancelled', 'Settings', {}, 'failure', 'User cancelled');
      return { success: false, error: 'Import cancelled' };
    }

    const importResult = await backupRestoreService.importBackup(result.filePaths[0]);
    activityLogger.log('backup_import', 'Settings', {
      path: result.filePaths[0],
      settingsImported: importResult.imported.settings,
      walletsImported: importResult.imported.wallets,
      encryptedEnvImported: importResult.imported.encryptedEnv,
      errors: importResult.errors,
    }, importResult.success ? 'success' : 'failure');
    return { success: importResult.success, data: importResult };
  } catch (error) {
    const errorMsg = (error as Error).message;
    activityLogger.logFailure('backup_import', 'Settings', errorMsg);
    return { success: false, error: errorMsg };
  }
});

ipcMain.handle('backup-validate', async (_event, filePath: string) => {
  try {
    const validation = backupRestoreService.validateBackup(filePath);
    return { success: validation.valid, data: validation };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// ============================================
// LLM Secrets IPC Handlers
// ============================================

// Get LLM Secrets settings
ipcMain.handle('get-llm-secrets-settings', async () => {
  try {
    if (fs.existsSync(SETTINGS_PATH)) {
      const settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
      return { success: true, data: settings };
    } else {
      // Return default settings
      return {
        success: true,
        data: {
          securityMode: 'simple',
          masterKeyStorage: 'dpapi',
          sessionDuration: 7200,
          showSuccessDialog: true,
          advancedSecurity: { enabled: false, keepassPath: 'EnvCrypto.kdbx' },
          backup: { enabled: true, frequency: 'monthly', destination: 'google-drive', lastBackup: null as string | null, recoveryPasswordSet: false }
        }
      };
    }
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Check if LLM Secrets is set up (DPAPI key or KeePass exists)
ipcMain.handle('check-llm-secrets-setup', async () => {
  try {
    // macOS: check if master key exists in Keychain AND encrypted files exist
    if (IS_MAC && macCryptoService) {
      const hasMasterKey = await macCryptoService.hasMasterKey();
      const hasEnvFiles = macCryptoService.getLatestVersion() > 0;
      const hasSettings = fs.existsSync(SETTINGS_PATH);
      let settings = null;
      if (hasSettings) {
        settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
      }
      return {
        success: true,
        isSetUp: hasMasterKey && hasEnvFiles,
        hasDpapiKey: hasMasterKey,
        hasKeePass: false,
        settings
      };
    }

    // Windows: check DPAPI/KeePass files AND encrypted env files
    const credPath = path.join(ENV_CRYPTO_PATH, 'credentials');
    const dpapiKeyFile = path.join(credPath, 'EnvCrypto_DpapiMasterKey.dat');
    const hasDpapiKey = fs.existsSync(dpapiKeyFile);
    const hasKeePass = fs.existsSync(KDBX_PATH);
    const hasEnvFiles = getHighestEnvVersion() > 0;
    const hasSettings = fs.existsSync(SETTINGS_PATH);

    let settings = null;
    if (hasSettings) {
      settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
    }

    return {
      success: true,
      isSetUp: (hasDpapiKey || hasKeePass) && hasEnvFiles,
      hasDpapiKey,
      hasKeePass,
      settings
    };
  } catch (error) {
    return { success: false, isSetUp: false, error: (error as Error).message };
  }
});

// Create Simple mode vault (DPAPI-stored master key)
ipcMain.handle('create-simple-vault', async () => {
  console.log('[create-simple-vault] Handler called');
  console.log('[create-simple-vault] ENV_CRYPTO_PATH:', ENV_CRYPTO_PATH);
  console.log('[create-simple-vault] USER_DATA_PATH:', USER_DATA_PATH);

  // macOS: generate master key and store in Keychain
  if (IS_MAC && macCryptoService && macAuthService) {
    try {
      // Authenticate with Touch ID first
      const authResult = await macAuthService.authenticate();
      if (!authResult.success) {
        return { success: false, error: authResult.error || 'Touch ID authentication failed' };
      }

      // Generate and store master key in Keychain
      await macCryptoService.generateMasterKey();
      await macCryptoService.startSession();

      // Save settings
      const settings = {
        securityMode: 'simple',
        masterKeyStorage: 'keychain',
        sessionDuration: 7200,
        showSuccessDialog: true,
        advancedSecurity: { enabled: false },
        backup: { enabled: true, frequency: 'monthly', destination: 'icloud', lastBackup: null as string | null, recoveryPasswordSet: false }
      };
      fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2), 'utf8');

      console.log('[LLM Secrets] macOS simple vault created successfully');
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  }

  // Windows: use DPAPI + Windows Hello
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');
    const authExePath = path.join(ENV_CRYPTO_PATH, 'WindowsHelloAuth.exe');

    console.log('[create-simple-vault] modulePath:', modulePath);
    console.log('[create-simple-vault] authExePath:', authExePath);
    console.log('[create-simple-vault] Module exists:', fs.existsSync(modulePath));
    console.log('[create-simple-vault] Auth exe exists:', fs.existsSync(authExePath));

    // Step 1: Run Windows Hello authentication using PowerShell Start-Process
    // Note: We use Start-Process -Wait to properly show the Windows Hello dialog
    console.log('[LLM Secrets] Starting Windows Hello authentication...');
    console.log('[create-simple-vault] Running WindowsHelloAuth.exe via PowerShell...');

    const authCommand = `
      $process = Start-Process -FilePath '${authExePath}' -Wait -PassThru -NoNewWindow
      exit $process.ExitCode
    `;
    const authEncodedCommand = Buffer.from(authCommand, 'utf16le').toString('base64');

    try {
      await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${authEncodedCommand}`);
      console.log('[LLM Secrets] Windows Hello authentication successful');
    } catch (authError: unknown) {
      // execAsync throws on non-zero exit code
      const errorMessage = authError instanceof Error ? authError.message : 'Unknown error';
      console.log('[create-simple-vault] Windows Hello auth failed:', errorMessage);
      return { success: false, error: 'Windows Hello authentication failed or was cancelled' };
    }

    // Step 2: Generate master key and store with DPAPI
    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force
        Set-Location '${USER_DATA_PATH}'

        # Generate 256-bit master key
        $keyBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($keyBytes)
        $masterKey = [Convert]::ToBase64String($keyBytes)

        # Store with DPAPI
        Save-DpapiMasterKey -MasterKey $masterKey | Out-Null

        # Save settings
        $settings = @{
          securityMode = "simple"
          masterKeyStorage = "dpapi"
          sessionDuration = 7200
          showSuccessDialog = $true
          advancedSecurity = @{ enabled = $false; keepassPath = "EnvCrypto.kdbx" }
          backup = @{ enabled = $true; frequency = "monthly"; destination = "google-drive"; lastBackup = $null; recoveryPasswordSet = $false }
        }
        $settings | ConvertTo-Json -Depth 10 | Out-File -FilePath '${SETTINGS_PATH}' -Encoding UTF8

        Write-Output "SUCCESS:$masterKey"
      } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
      }
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
    const { stdout, stderr } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const output = stdout?.trim() || '';
    // Look for SUCCESS: anywhere in the output (may have other output before it)
    const successMatch = output.match(/SUCCESS:(.+)$/m);
    const errorMatch = output.match(/ERROR:(.+)$/m);

    if (successMatch) {
      const masterKey = successMatch[1].trim();
      console.log('[LLM Secrets] Simple vault created successfully');
      return { success: true, masterKey };
    } else if (errorMatch) {
      return { success: false, error: errorMatch[1].trim() };
    } else {
      console.log('[LLM Secrets] Unexpected output:', output);
      return { success: false, error: stderr || output || 'Unknown error creating vault' };
    }
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Authenticate with Simple mode (Windows Hello only)
ipcMain.handle('authenticate-simple', async () => {
  // macOS: use Touch ID
  if (IS_MAC && macAuthService && macCryptoService) {
    try {
      const result = await macAuthService.authenticate();
      if (result.success) {
        await macCryptoService.startSession();
        console.log('[LLM Secrets] Touch ID authentication successful');
      }
      return result;
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  }

  // Windows: use Windows Hello
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);
    const authExePath = path.join(ENV_CRYPTO_PATH, 'WindowsHelloAuth.exe');
    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');

    console.log('[LLM Secrets] Starting Windows Hello authentication...');

    // Run Windows Hello auth via PowerShell Start-Process for proper GUI dialog
    const authCommand = `
      $process = Start-Process -FilePath '${authExePath}' -Wait -PassThru -NoNewWindow
      exit $process.ExitCode
    `;
    const authEncodedCommand = Buffer.from(authCommand, 'utf16le').toString('base64');

    try {
      await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${authEncodedCommand}`);
    } catch (authError: unknown) {
      const errorMessage = authError instanceof Error ? authError.message : 'Unknown error';
      console.log('[LLM Secrets] Windows Hello auth failed:', errorMessage);
      return { success: false, error: 'Windows Hello authentication failed or was cancelled' };
    }

    // Create session marker

    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      Import-Module '${modulePath}' -Force
      $sessionMarker = "SIMPLE_MODE_SESSION_" + [guid]::NewGuid().ToString()
      $metadata = @{
        CreatedAt = (Get-Date).ToString("o")
        ExpiresAt = (Get-Date).AddHours(2).ToString("o")
        Type = "SimpleSession"
        Mode = "simple"
      }
      Save-SecureCredential -Target 'EnvCrypto_SessionKey' -Value $sessionMarker -Metadata $metadata
      Write-Output "SUCCESS"
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
    await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    console.log('[LLM Secrets] Authentication successful');
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Open backup for upload (Google Drive + File Explorer)
ipcMain.handle('open-backup-upload', async () => {
  try {
    const backupPath = path.join(ENV_CRYPTO_PATH, 'backup');
    const backupFile = path.join(backupPath, 'master-key.backup');

    if (!fs.existsSync(backupFile)) {
      return { success: false, error: 'Backup file not found. Set recovery password first.' };
    }

    // Open Google Drive first
    await shell.openExternal('https://drive.google.com/drive/u/0/recent');

    // Then show file in Finder/Explorer so it appears on top
    await new Promise(resolve => setTimeout(resolve, 1200));
    if (IS_MAC) {
      shell.showItemInFolder(backupFile);
      // Bring Finder to front with AppleScript
      await new Promise(resolve => setTimeout(resolve, 300));
      const { exec } = require('child_process');
      exec(`osascript -e 'tell application "Finder" to activate'`);
    } else {
      const { exec } = require('child_process');
      exec(`explorer.exe /select,"${backupFile}"`);
    }

    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Get backup status
ipcMain.handle('get-backup-status', async () => {
  try {
    // Read settings directly from settings.json (works on both platforms)
    if (fs.existsSync(SETTINGS_PATH)) {
      const settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
      const backup = settings.backup || {};
      const lastBackup = backup.lastBackup ? new Date(backup.lastBackup) : null;
      let backupNeeded = false;
      if (backup.enabled && lastBackup) {
        const now = new Date();
        const diffDays = (now.getTime() - lastBackup.getTime()) / (1000 * 60 * 60 * 24);
        const freqDays = backup.frequency === 'weekly' ? 7 : backup.frequency === 'daily' ? 1 : 30;
        backupNeeded = diffDays >= freqDays;
      } else if (backup.enabled && !lastBackup) {
        backupNeeded = true;
      }
      return {
        success: true,
        data: {
          enabled: backup.enabled ?? true,
          frequency: backup.frequency || 'monthly',
          lastBackup: backup.lastBackup || null,
          recoveryPasswordSet: backup.recoveryPasswordSet ?? false,
          backupNeeded,
        }
      };
    }
    // No settings file yet
    return {
      success: true,
      data: {
        enabled: true,
        frequency: 'monthly',
        lastBackup: null as string | null,
        recoveryPasswordSet: false,
        backupNeeded: true,
      }
    };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Set recovery password
ipcMain.handle('set-recovery-password', async (_event, password: string) => {
  try {
    if (IS_MAC && macCryptoService) {
      const crypto = require('crypto');
      const keytar = require('keytar');

      // Get master key from Keychain
      const masterKey = await macCryptoService.getMasterKey();

      // Encrypt master key with recovery password using PBKDF2 + AES-256-CBC
      const salt = crypto.randomBytes(16);
      const iv = crypto.randomBytes(16);
      const derivedKey = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
      const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
      let encrypted = cipher.update(masterKey);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const backupData = Buffer.concat([salt, iv, encrypted]);

      // Write backup file
      const backupPath = path.join(ENV_CRYPTO_PATH, 'backup');
      if (!fs.existsSync(backupPath)) {
        fs.mkdirSync(backupPath, { recursive: true });
      }
      const backupFile = path.join(backupPath, 'master-key.backup');
      fs.writeFileSync(backupFile, backupData);
      fs.chmodSync(backupFile, 0o600);

      // Store recovery password hash for verification
      const hash = crypto.createHash('sha256').update(password).digest('base64');
      await keytar.setPassword('LLMSecrets', 'recovery-password-hash', hash);

      // Update settings
      let settings: any = {};
      if (fs.existsSync(SETTINGS_PATH)) {
        settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
      }
      if (!settings.backup) settings.backup = {};
      settings.backup.recoveryPasswordSet = true;
      settings.backup.lastBackup = new Date().toISOString();
      fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2), 'utf8');
      return { success: true };
    }

    // Windows: use PowerShell
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);
    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');

    const escapedPassword = password.replace(/'/g, "''");
    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force
        $securePassword = ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force
        $result = Set-BackupRecoveryPassword -RecoveryPassword $securePassword
        if ($result) {
          Write-Output "SUCCESS"
        } else {
          Write-Output "ERROR:Failed to set recovery password"
        }
      } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
      }
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
    const { stdout } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const output = stdout?.trim() || '';
    if (output === 'SUCCESS') {
      return { success: true };
    } else if (output.startsWith('ERROR:')) {
      return { success: false, error: output.substring(6) };
    } else {
      return { success: false, error: 'Unknown error' };
    }
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Recover master key from backup file using recovery password
ipcMain.handle('recover-master-key', async (_event, backupFilePath: string, password: string) => {
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);
    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');

    // Verify the backup file exists
    if (!fs.existsSync(backupFilePath)) {
      return { success: false, error: 'Backup file not found at the specified path' };
    }

    const escapedPassword = password.replace(/'/g, "''");
    const escapedPath = backupFilePath.replace(/'/g, "''");

    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force
        $securePassword = ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force
        $masterKey = Restore-FromRecoveryPassword -RecoveryPassword $securePassword -BackupFile '${escapedPath}'
        if ($masterKey) {
          Write-Output "SUCCESS:$masterKey"
        } else {
          Write-Output "ERROR:Failed to decrypt backup. Check your recovery password."
        }
      } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
      }
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
    const { stdout } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const output = stdout?.trim() || '';
    if (output.startsWith('SUCCESS:')) {
      const masterKey = output.substring(8);
      return { success: true, masterKey };
    } else if (output.startsWith('ERROR:')) {
      return { success: false, error: output.substring(6) };
    } else {
      return { success: false, error: 'Unknown error during recovery' };
    }
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Activity Log IPC Handlers
ipcMain.handle('activity-log-get', async () => {
  try {
    const log = activityLogger.getSessionLog();
    return { success: true, data: log };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('activity-log-export', async () => {
  try {
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Export Activity Log',
      defaultPath: `scrt-activity-${new Date().toISOString().replace(/[:.]/g, '-')}.json`,
      filters: [{ name: 'JSON Files', extensions: ['json'] }],
    });

    if (result.canceled || !result.filePath) {
      return { success: false, error: 'Export cancelled' };
    }

    activityLogger.exportLog(result.filePath);
    return { success: true, data: { path: result.filePath } };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('activity-log-path', async () => {
  try {
    const logPath = activityLogger.getLogFilePath();
    return { success: true, data: logPath };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Log navigation events from renderer
ipcMain.handle('log-navigation', async (_event, from: string, to: string) => {
  activityLogger.logNavigation(from, to);
  return { success: true };
});

// Log user clicks from renderer
ipcMain.handle('log-click', async (_event, buttonName: string, component: string) => {
  activityLogger.logClick(buttonName, component);
  return { success: true };
});

// ============================================
// Setup Wizard IPC Handlers
// ============================================

// Check if this is a first-time run (no vault exists)
// Simple mode creates DPAPI key, Advanced mode creates KeePass database
ipcMain.handle('check-first-run', async () => {
  try {
    // macOS: check if master key exists in Keychain
    if (IS_MAC && macCryptoService) {
      const hasVault = await macCryptoService.hasSimpleModeVault();
      return { success: true, isFirstRun: !hasVault };
    }

    // Windows: check DPAPI + KeePass
    const dpapiKeyPath = path.join(ENV_CRYPTO_PATH, 'credentials', 'EnvCrypto_DpapiMasterKey.dat');
    const hasSimpleModeVault = fs.existsSync(dpapiKeyPath);
    const hasAdvancedModeVault = fs.existsSync(KDBX_PATH);
    const isFirstRun = !hasSimpleModeVault && !hasAdvancedModeVault;
    return { success: true, isFirstRun };
  } catch (error) {
    return { success: false, isFirstRun: true, error: (error as Error).message };
  }
});

// Create vault (KeePass database + master key)
ipcMain.handle('create-vault', async (_event, password: string) => {
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');
    const authExePath = path.join(ENV_CRYPTO_PATH, 'WindowsHelloAuth.exe');

    // Step 1: Run Windows Hello authentication via PowerShell Start-Process
    console.log('[Setup] Starting Windows Hello authentication...');

    const authCommand = `
      $process = Start-Process -FilePath '${authExePath}' -Wait -PassThru -NoNewWindow
      exit $process.ExitCode
    `;
    const authEncodedCommand = Buffer.from(authCommand, 'utf16le').toString('base64');

    try {
      await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${authEncodedCommand}`);
    } catch (authError: unknown) {
      const errorMessage = authError instanceof Error ? authError.message : 'Unknown error';
      console.log('[Setup] Windows Hello auth failed:', errorMessage);
      return { success: false, error: 'Windows Hello authentication failed or was cancelled' };
    }
    console.log('[Setup] Windows Hello authentication successful');

    // Step 2: Create KeePass database with the password and generate master key
    const escapedPassword = password.replace(/'/g, "''");
    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force

        # Set working directory to Keep Scrt
        Set-Location '${USER_DATA_PATH}'

        # Convert password to SecureString for KeePass
        $securePassword = ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force

        # Create new master key (this creates KeePass DB and returns master key)
        $masterKey = New-MasterKey -ExportKey -DatabasePassword $securePassword

        if (-not $masterKey) {
          Write-Output "ERROR:Failed to create master key"
          return
        }

        # Cache the KeePass password for the session
        $encryptedPassword = ConvertFrom-SecureString -SecureString $securePassword
        $metadata = @{
          CreatedAt = (Get-Date).ToString("o")
          ExpiresAt = (Get-Date).AddHours(2).ToString("o")
          Type = "KeePassSession"
        }
        Save-SecureCredential -Target 'EnvCrypto_SessionKey' -Value $encryptedPassword -Metadata $metadata

        Write-Output "SUCCESS:$masterKey"
      } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
      }
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
    const { stdout, stderr } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const output = stdout?.trim() || '';
    if (output.startsWith('SUCCESS:')) {
      const masterKey = output.substring(8);
      console.log('[Setup] Vault created successfully');
      return { success: true, masterKey };
    } else if (output.startsWith('ERROR:')) {
      return { success: false, error: output.substring(6) };
    } else {
      return { success: false, error: stderr || 'Unknown error creating vault' };
    }
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Save session duration settings
ipcMain.handle('save-session-settings', async (_event, duration: string) => {
  try {
    // Convert duration string to hours
    const durationMap: Record<string, number> = {
      '15min': 0.25,
      '1hour': 1,
      '2hours': 2,
      '8hours': 8,
      'until_restart': 24 * 365, // Effectively forever
    };

    const hours = durationMap[duration] || 2;
    await cryptoService.saveSetting('sessionDurationHours', hours.toString());
    await cryptoService.saveSetting('sessionDuration', duration);

    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Generate CLAUDE.md from secret names
ipcMain.handle('generate-claude-md', async (_event, secretNames: string[]) => {
  try {
    // Merge with existing descriptions (preserve user-enriched fields)
    let existing: SecretDescription[] = [];
    if (fs.existsSync(SECRET_DESCRIPTIONS_PATH)) {
      try {
        existing = JSON.parse(fs.readFileSync(SECRET_DESCRIPTIONS_PATH, 'utf8'));
      } catch { /* ignore parse errors */ }
    }

    const descriptions: SecretDescription[] = secretNames.map(name => {
      const prev = existing.find(e => e.name === name);
      if (prev) return prev; // keep user-enriched description
      return { name, category: 'other', purpose: 'User-defined', whenToUse: '', example: `process.env.${name}` };
    });

    const aiSettings = getAIToolsSettings();

    // Generate CLAUDE.md
    if (aiSettings.claudeCode) {
      const content = generateClaudeMdContent(descriptions);
      fs.writeFileSync(CLAUDE_MD_PATH, content, 'utf8');
    }

    // Generate AGENTS.md
    if (aiSettings.codexCLI) {
      const agentsContent = generateAgentsMdContent(descriptions);
      fs.writeFileSync(AGENTS_MD_PATH, agentsContent, 'utf8');
    }

    // Save descriptions so Claude MD tab shows them
    fs.writeFileSync(SECRET_DESCRIPTIONS_PATH, JSON.stringify(descriptions, null, 2), 'utf8');

    return { success: true, path: CLAUDE_MD_PATH };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Open CLAUDE.md in default editor
ipcMain.handle('open-claude-md', async () => {
  try {
    if (fs.existsSync(CLAUDE_MD_PATH)) {
      await shell.openPath(CLAUDE_MD_PATH);
      return { success: true };
    } else {
      return { success: false, error: 'CLAUDE.md not found' };
    }
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Get secret descriptions
ipcMain.handle('get-secret-descriptions', async () => {
  try {
    if (fs.existsSync(SECRET_DESCRIPTIONS_PATH)) {
      const content = fs.readFileSync(SECRET_DESCRIPTIONS_PATH, 'utf8');
      const descriptions = JSON.parse(content) as SecretDescription[];
      return { success: true, data: descriptions };
    }
    return { success: true, data: [] };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Save secret descriptions
ipcMain.handle('save-secret-descriptions', async (_event, descriptions: SecretDescription[]) => {
  try {
    fs.writeFileSync(SECRET_DESCRIPTIONS_PATH, JSON.stringify(descriptions, null, 2), 'utf8');
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Generate CLAUDE.md with descriptions
ipcMain.handle('generate-claude-md-with-descriptions', async (_event, descriptions: SecretDescription[]) => {
  try {
    const aiSettings = getAIToolsSettings();
    const generatedFiles: string[] = [];

    // Generate CLAUDE.md for Claude Code
    if (aiSettings.claudeCode) {
      const claudeMdContent = generateClaudeMdContent(descriptions);
      fs.writeFileSync(CLAUDE_MD_PATH, claudeMdContent, 'utf8');
      generatedFiles.push('CLAUDE.md');
    }

    // Generate AGENTS.md for Codex CLI
    if (aiSettings.codexCLI) {
      const agentsMdContent = generateAgentsMdContent(descriptions);
      fs.writeFileSync(AGENTS_MD_PATH, agentsMdContent, 'utf8');
      generatedFiles.push('AGENTS.md');
    }

    // Also save the descriptions
    fs.writeFileSync(SECRET_DESCRIPTIONS_PATH, JSON.stringify(descriptions, null, 2), 'utf8');

    return { success: true, path: CLAUDE_MD_PATH, generatedFiles };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Get AI tools settings
ipcMain.handle('get-ai-tools-settings', async () => {
  try {
    return { success: true, data: getAIToolsSettings() };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Save AI tools settings
ipcMain.handle('save-ai-tools-settings', async (_event, settings: AIToolsSettings) => {
  try {
    fs.writeFileSync(AI_TOOLS_SETTINGS_PATH, JSON.stringify(settings, null, 2), 'utf8');
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Open AGENTS.md file
ipcMain.handle('open-agents-md', async () => {
  try {
    if (fs.existsSync(AGENTS_MD_PATH)) {
      await shell.openPath(AGENTS_MD_PATH);
      return { success: true };
    }
    return { success: false, error: 'AGENTS.md not found' };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Recover secrets from existing encrypted file and master key
ipcMain.handle('recover-secrets', async (_event, encryptedFilePath: string, masterKey: string) => {
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    // Check if source file exists
    if (!fs.existsSync(encryptedFilePath)) {
      return { success: false, error: `File not found: ${encryptedFilePath}` };
    }

    // Read the encrypted file to validate it's proper JSON
    const encryptedContent = fs.readFileSync(encryptedFilePath, 'utf8');
    let parsed;
    try {
      parsed = JSON.parse(encryptedContent.replace(/^\uFEFF/, '')); // Remove BOM if present
      if (!parsed.Metadata || !parsed.Data) {
        return { success: false, error: 'Invalid encrypted file format' };
      }
    } catch {
      return { success: false, error: 'Invalid encrypted file - not valid JSON' };
    }

    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');
    const authExePath = path.join(ENV_CRYPTO_PATH, 'WindowsHelloAuth.exe');
    // Use versioned path - never overwrite existing encrypted files
    const targetPath = getNextEnvVersionPath();
    console.log(`[Recovery] Will save to versioned path: ${targetPath}`);

    // Step 1: Validate the master key by attempting to decrypt
    const validateCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force
        $content = Get-Content -Path '${encryptedFilePath.replace(/\\/g, '\\\\')}' -Raw -Encoding UTF8
        $json = $content | ConvertFrom-Json
        $encryptedData = [Convert]::FromBase64String($json.Data)
        $keyBytes = [Convert]::FromBase64String('${masterKey}')
        $iv = $encryptedData[0..15]
        $ciphertext = $encryptedData[16..($encryptedData.Length - 1)]
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $keyBytes
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        $plaintext = [System.Text.Encoding]::UTF8.GetString($decrypted)
        Write-Output "VALID"
      } catch {
        Write-Output "INVALID:$($_.Exception.Message)"
      }
    `;
    const encodedValidate = Buffer.from(validateCommand, 'utf16le').toString('base64');
    const { stdout: validateOut } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedValidate}`);

    const validateResult = validateOut?.trim() || '';
    if (validateResult !== 'VALID') {
      const errorMsg = validateResult.startsWith('INVALID:') ? validateResult.substring(8) : 'Invalid master key';
      return { success: false, error: `Decryption failed: ${errorMsg}` };
    }

    // Step 2: Run Windows Hello authentication via PowerShell Start-Process
    console.log('[Recovery] Starting Windows Hello authentication...');

    const authCommand = `
      $process = Start-Process -FilePath '${authExePath}' -Wait -PassThru -NoNewWindow
      exit $process.ExitCode
    `;
    const authEncodedCommand = Buffer.from(authCommand, 'utf16le').toString('base64');

    try {
      await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${authEncodedCommand}`);
    } catch (authError: unknown) {
      const errorMessage = authError instanceof Error ? authError.message : 'Unknown error';
      console.log('[Recovery] Windows Hello auth failed:', errorMessage);
      return { success: false, error: 'Windows Hello authentication failed or was cancelled' };
    }

    // Step 3: Copy file to expected location
    fs.copyFileSync(encryptedFilePath, targetPath);

    // Ensure credentials directory exists
    const credentialsPath = path.join(ENV_CRYPTO_PATH, 'credentials');
    if (!fs.existsSync(credentialsPath)) {
      fs.mkdirSync(credentialsPath, { recursive: true });
    }

    // Step 4: Store master key with DPAPI
    const storeCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Write-Output "STEP:Loading module..."
        Import-Module '${modulePath}' -Force
        Write-Output "STEP:Module loaded"

        Set-Location '${USER_DATA_PATH}'
        Write-Output "STEP:Working directory set"

        Write-Output "STEP:Saving master key with DPAPI..."
        Save-DpapiMasterKey -MasterKey '${masterKey}' | Out-Null
        Write-Output "STEP:Master key saved"

        # Save settings for simple mode
        $settings = @{
          securityMode = "simple"
          masterKeyStorage = "dpapi"
          sessionDuration = 7200
          showSuccessDialog = $true
          advancedSecurity = @{ enabled = $false; keepassPath = "EnvCrypto.kdbx" }
          backup = @{ enabled = $true; frequency = "monthly"; destination = "google-drive"; lastBackup = $null; recoveryPasswordSet = $false }
        }
        $settingsDir = Split-Path '${SETTINGS_PATH}' -Parent
        if (-not (Test-Path $settingsDir)) { New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null }
        $settings | ConvertTo-Json -Depth 10 | Out-File -FilePath '${SETTINGS_PATH}' -Encoding UTF8
        Write-Output "STEP:Settings saved"

        Write-Output "SUCCESS"
      } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
        Write-Output "ERRORSTACK:$($_.ScriptStackTrace)"
      }
    `;
    const encodedStore = Buffer.from(storeCommand, 'utf16le').toString('base64');
    const { stdout: storeOut, stderr: storeErr } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedStore}`);

    const storeResult = storeOut?.trim() || '';
    const storeError = storeErr?.trim() || '';
    console.log('[Recovery] Store stdout:', storeResult);
    if (storeError) console.log('[Recovery] Store stderr:', storeError);

    // Check for SUCCESS anywhere in output (may have other output before it)
    if (storeResult.includes('SUCCESS')) {
      console.log('[Recovery] Secrets recovered successfully');
      return { success: true };
    } else if (storeResult.includes('ERROR:')) {
      const errorMatch = storeResult.match(/ERROR:(.+?)(?:\r?\n|$)/);
      const stackMatch = storeResult.match(/ERRORSTACK:(.+)/s);
      console.log('[Recovery] Error details:', errorMatch?.[1], stackMatch?.[1]);
      return { success: false, error: errorMatch ? errorMatch[1].trim() : 'Unknown error during DPAPI storage' };
    } else {
      // Figure out which step failed
      const steps = storeResult.match(/STEP:([^\r\n]+)/g) || [];
      const lastStep = steps.length > 0 ? steps[steps.length - 1].replace('STEP:', '') : 'Unknown';
      console.log('[Recovery] Unexpected output. Last step:', lastStep, 'Full output:', storeResult);
      const errorDetails = storeError ? ` (${storeError})` : '';
      return { success: false, error: `Recovery stopped at: ${lastStep}${errorDetails}` };
    }
  } catch (error) {
    console.log('[Recovery] Exception:', (error as Error).message);
    return { success: false, error: `Recovery exception: ${(error as Error).message}` };
  }
});

// Install Claude Code slash commands
ipcMain.handle('install-claude-commands', async () => {
  try {
    const userProfile = process.env.USERPROFILE || '';
    const commandsDir = path.join(userProfile, '.claude', 'commands');

    // Create commands directory (root level, not in /secret/ subfolder)
    if (!fs.existsSync(commandsDir)) {
      fs.mkdirSync(commandsDir, { recursive: true });
    }

    // Use user data path for commands
    const keepScrtRoot = USER_DATA_PATH;

    // /view - Decrypt and view secrets with Windows Hello
    const viewCommand = `# /view - Temporarily View Secret Values

When the user runs /view, execute this PowerShell command immediately:

\`\`\`powershell
cd "${keepScrtRoot.replace(/\\/g, '\\\\')}" && powershell -ExecutionPolicy Bypass -Command "Import-Module '.\\\\env-crypto-test\\\\EnvCrypto.psm1' -Force; New-SessionKey; . '.\\\\Scrt\\\\while-you-sleep\\\\QA Human Feedback\\\\commands\\\\View.ps1'; Invoke-ScrtView -NoClear"
\`\`\`

This will:
1. Trigger Windows Hello authentication
2. Display decrypted secret values temporarily

If the user wants to view a specific secret:
\`\`\`powershell
cd "${keepScrtRoot.replace(/\\/g, '\\\\')}" && powershell -ExecutionPolicy Bypass -Command "Import-Module '.\\\\env-crypto-test\\\\EnvCrypto.psm1' -Force; New-SessionKey; . '.\\\\Scrt\\\\while-you-sleep\\\\QA Human Feedback\\\\commands\\\\View.ps1'; Invoke-ScrtView -Secret 'SECRET_NAME' -NoClear"
\`\`\`
`;

    // /learn - Generate CLAUDE.md so Claude learns when to use secrets
    const learnCommand = `# /learn - Learn Available Secrets

When the user runs /learn, execute this PowerShell command immediately:

\`\`\`powershell
cd "${keepScrtRoot.replace(/\\/g, '\\\\')}" && powershell -ExecutionPolicy Bypass -Command "Import-Module '.\\\\env-crypto-test\\\\EnvCrypto.psm1' -Force; New-SessionKey; . '.\\\\Scrt\\\\while-you-sleep\\\\QA Human Feedback\\\\commands\\\\Format.ps1'; Invoke-ScrtFormat"
\`\`\`

This will:
1. Trigger Windows Hello authentication
2. Read secret names from .env.encrypted
3. Generate/update CLAUDE.md so Claude learns when to use each secret

For preview only (don't write file):
\`\`\`powershell
cd "${keepScrtRoot.replace(/\\/g, '\\\\')}" && powershell -ExecutionPolicy Bypass -Command "Import-Module '.\\\\env-crypto-test\\\\EnvCrypto.psm1' -Force; New-SessionKey; . '.\\\\Scrt\\\\while-you-sleep\\\\QA Human Feedback\\\\commands\\\\Format.ps1'; Invoke-ScrtFormat -Preview"
\`\`\`
`;

    // /hide - Verify secrets are hidden and clean up
    const hideCommand = `# /hide - Verify Secrets Are Properly Hidden

When the user runs /hide, execute this PowerShell command immediately:

\`\`\`powershell
cd "${keepScrtRoot.replace(/\\/g, '\\\\')}" && powershell -ExecutionPolicy Bypass -Command "Import-Module '.\\\\env-crypto-test\\\\EnvCrypto.psm1' -Force; . '.\\\\Scrt\\\\while-you-sleep\\\\QA Human Feedback\\\\commands\\\\Hide.ps1'; Invoke-ScrtHide -VerifyOnly"
\`\`\`

This will check:
- .env.encrypted exists
- No plaintext .env exposed
- No secrets in log/temp files
- Session status

To auto-fix issues (delete exposed .env, clear clipboard):
\`\`\`powershell
cd "${keepScrtRoot.replace(/\\/g, '\\\\')}" && powershell -ExecutionPolicy Bypass -Command "Import-Module '.\\\\env-crypto-test\\\\EnvCrypto.psm1' -Force; . '.\\\\Scrt\\\\while-you-sleep\\\\QA Human Feedback\\\\commands\\\\Hide.ps1'; Invoke-ScrtHide -Cleanup"
\`\`\`
`;

    // Write command files to root commands folder
    fs.writeFileSync(path.join(commandsDir, 'view.md'), viewCommand, 'utf8');
    fs.writeFileSync(path.join(commandsDir, 'learn.md'), learnCommand, 'utf8');
    fs.writeFileSync(path.join(commandsDir, 'hide.md'), hideCommand, 'utf8');

    console.log('[Setup] Claude Code commands installed to:', commandsDir);
    return { success: true, path: commandsDir };
  } catch (error) {
    console.error('[Setup] Failed to install Claude commands:', error);
    return { success: false, error: (error as Error).message };
  }
});

// Add CLAUDE.md directory to Claude's whitelist
ipcMain.handle('add-claude-whitelist', async () => {
  try {
    const homeDir = IS_MAC ? (process.env.HOME || '') : (process.env.USERPROFILE || '');
    const settingsPath = path.join(homeDir, '.claude', 'settings.json');
    const claudeMdDir = path.dirname(CLAUDE_MD_PATH).replace(/\\/g, '/');

    // Ensure .claude directory exists
    const claudeDir = path.dirname(settingsPath);
    if (!fs.existsSync(claudeDir)) {
      fs.mkdirSync(claudeDir, { recursive: true });
    }

    // Read existing settings or create new
    let settings: Record<string, unknown> = {};
    if (fs.existsSync(settingsPath)) {
      try {
        settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
      } catch {
        // If file is corrupted, start fresh
        settings = {};
      }
    }

    // Ensure permissions structure exists
    if (!settings.permissions || typeof settings.permissions !== 'object') {
      settings.permissions = {};
    }
    const permissions = settings.permissions as Record<string, unknown>;

    if (!permissions.additionalDirectories || !Array.isArray(permissions.additionalDirectories)) {
      permissions.additionalDirectories = [];
    }
    const additionalDirs = permissions.additionalDirectories as string[];

    // Add the directory if not already present
    if (!additionalDirs.includes(claudeMdDir)) {
      additionalDirs.push(claudeMdDir);
      fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf8');
    }

    return { success: true, path: claudeMdDir };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// ============================================
// License IPC Handlers
// ============================================

// Activate license with key and email
ipcMain.handle('activate-license', async (_event, licenseKey: string, email: string) => {
  try {
    console.log('[License] Attempting to activate license for:', email);

    // Validate format first
    if (!LicenseService.validateKey(licenseKey)) {
      return { success: false, error: 'Invalid license key format' };
    }

    // Validate key matches email
    if (!LicenseService.validateKey(licenseKey, email)) {
      return { success: false, error: 'License key does not match email' };
    }

    // Save the license
    const saved = licenseService.saveLicense(licenseKey, email);
    if (!saved) {
      return { success: false, error: 'Failed to save license' };
    }

    return { success: true };
  } catch (error) {
    console.error('[License] Activation error:', error);
    return { success: false, error: (error as Error).message };
  }
});

// Check license status
ipcMain.handle('check-license', async () => {
  try {
    const info = licenseService.loadLicense();
    return {
      success: true,
      isLicensed: info.isValid,
      email: info.email,
      activatedAt: info.purchaseDate
    };
  } catch (error) {
    return { success: false, isLicensed: false, error: (error as Error).message };
  }
});

// Remove license (for testing/deactivation)
ipcMain.handle('remove-license', async () => {
  try {
    licenseService.removeLicense();
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// ============================================================
// WSL2 Daemon IPC Handlers
// ============================================================

// Check if WSL daemon is available
ipcMain.handle('wsl-check-daemon', async () => {
  try {
    if (!wslCryptoService) {
      return { success: true, available: false };
    }
    const available = wslCryptoService.isAvailable();
    return { success: true, available };
  } catch (error) {
    return { success: false, available: false, error: (error as Error).message };
  }
});

// Unlock secrets via Windows Hello (WSL)
ipcMain.handle('wsl-unlock', async (_event, ttl?: number) => {
  try {
    if (!wslCryptoService || !wslCryptoService.isAvailable()) {
      return { success: false, error: 'WSL daemon not available' };
    }
    const count = await wslCryptoService.unlock(ttl);
    return { success: true, count };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Get WSL session status
ipcMain.handle('wsl-status', async () => {
  try {
    if (!wslCryptoService || !wslCryptoService.isAvailable()) {
      return { success: false, error: 'WSL daemon not available' };
    }
    const status = await wslCryptoService.getStatus();
    return { success: true, active: status.active, remaining: status.remaining };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// List secret names (WSL)
ipcMain.handle('wsl-list-secrets', async () => {
  try {
    if (!wslCryptoService || !wslCryptoService.isAvailable()) {
      return { success: false, error: 'WSL daemon not available' };
    }
    const names = await wslCryptoService.listSecrets();
    return { success: true, names };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Logout / clear session (WSL)
ipcMain.handle('wsl-logout', async () => {
  try {
    if (!wslCryptoService || !wslCryptoService.isAvailable()) {
      return { success: false, error: 'WSL daemon not available' };
    }
    await wslCryptoService.logout();
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Run command with secrets injected (WSL)
ipcMain.handle('wsl-run-command', async (_event, command: string, workingDir?: string) => {
  try {
    if (!wslCryptoService || !wslCryptoService.isAvailable()) {
      return { success: false, error: 'WSL daemon not available' };
    }
    const result = await wslCryptoService.runWithSecrets(command, workingDir);
    return { success: true, exitCode: result.exitCode, output: result.output };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

app.on('ready', async () => {
  // Initialize paths first - must be done after app is ready
  initializePaths();
  createWindow();
  // Initialize auto-lock service
  await autoLockService.initialize();
  // Set up lock callback to notify renderer
  autoLockService.onLock(() => {
    if (mainWindow) {
      mainWindow.webContents.send('autolock-triggered');
    }
  });

});

app.on('window-all-closed', () => {
  activityLogger.endSession();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  activityLogger.endSession();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
