import { app, BrowserWindow, ipcMain, dialog, shell } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import { WalletService } from './main/services/WalletService';
import { CryptoService } from './main/services/CryptoService';
import { AutoLockService, AutoLockInterval } from './main/services/AutoLockService';
import { BackupRestoreService } from './main/services/BackupRestoreService';
import { LicenseService } from './main/services/LicenseService';
import { getActivityLogger } from './main/services/UserActivityLogger';
import { generateClaudeMdContent } from './main/templates/claudeMdTemplate';

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
const licenseService = new LicenseService();
const activityLogger = getActivityLogger();

// Path constants
const KEEP_SCRT_PATH = path.join('C:', 'Users', 'jgott', 'OneDrive', 'Desktop', 'Keep Scrt', 'Scrt');
const ENV_CRYPTO_PATH = path.join(KEEP_SCRT_PATH, 'env-crypto-test');
const KDBX_PATH = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.kdbx');
const SETTINGS_PATH = path.join(ENV_CRYPTO_PATH, 'settings.json');
const CLAUDE_MD_PATH = path.join(KEEP_SCRT_PATH, '..', 'CLAUDE.md');
const DEBUG_LOG_PATH = path.join(KEEP_SCRT_PATH, 'QA', 'simple-secret-debug.log');

// Debug logging function - writes to file with timestamps
function debugLog(context: string, message: string, data?: Record<string, unknown>): void {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] [${context}] ${message}${data ? ' ' + JSON.stringify(data) : ''}\n`;

  // Ensure QA directory exists
  const qaDir = path.dirname(DEBUG_LOG_PATH);
  if (!fs.existsSync(qaDir)) {
    fs.mkdirSync(qaDir, { recursive: true });
  }

  // Append to log file
  fs.appendFileSync(DEBUG_LOG_PATH, logEntry);
  console.log(logEntry.trim());
}

const createWindow = (): void => {
  mainWindow = new BrowserWindow({
    height: 800,
    width: 1200,
    minHeight: 600,
    minWidth: 900,
    title: 'LLM Secrets - Windows Hello Protected Secrets',
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
  debugLog('decrypt-env', 'START - Handler invoked', {
    masterKeyLength: masterKey?.length || 0,
    masterKeyProvided: !!masterKey && masterKey.trim() !== '',
    masterKeyPreview: masterKey ? masterKey.substring(0, 10) + '...' : 'EMPTY'
  });

  activityLogger.log('decrypt_attempt', 'SecretManager', { masterKeyLength: masterKey?.length || 0 }, 'pending');
  try {
    debugLog('decrypt-env', 'Calling cryptoService.decrypt...');
    const decrypted = await cryptoService.decrypt(masterKey);
    debugLog('decrypt-env', 'SUCCESS - Decryption complete', { contentLength: decrypted?.length || 0 });
    activityLogger.logSuccess('decrypt_env', 'SecretManager', { contentLength: decrypted?.length || 0 });
    return { success: true, data: decrypted };
  } catch (error) {
    const errorMsg = (error as Error).message;
    debugLog('decrypt-env', 'ERROR - Decryption failed', { error: errorMsg });
    activityLogger.logFailure('decrypt_env', 'SecretManager', errorMsg);
    return { success: false, error: errorMsg };
  }
});

ipcMain.handle('encrypt-env', async (_event, content: string, masterKey: string) => {
  activityLogger.log('encrypt_attempt', 'SecretManager', { contentLength: content?.length || 0 }, 'pending');
  try {
    await cryptoService.encrypt(content, masterKey);
    activityLogger.logSuccess('encrypt_env', 'SecretManager');
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

    const modulePath = path.join('C:', 'Users', 'jgott', 'OneDrive', 'Desktop', 'Keep Scrt', 'env-crypto-test', 'EnvCrypto.psm1');
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
    const { exec, spawn } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    const keepScrtPath = path.join('C:', 'Users', 'jgott', 'OneDrive', 'Desktop', 'Keep Scrt', 'env-crypto-test');
    const authExePath = path.join(keepScrtPath, 'WindowsHelloAuth.exe');
    const modulePath = path.join(keepScrtPath, 'EnvCrypto.psm1');

    // Step 1: Run Windows Hello authentication
    console.log('[Session] Starting Windows Hello authentication...');
    const authProcess = spawn(authExePath, [], {
      stdio: ['ignore', 'pipe', 'pipe'],  // Hide console output
      windowsHide: true,  // Hide the console window (Windows Hello dialog still shows)
      detached: false
    });

    const authResult = await new Promise<number>((resolve) => {
      authProcess.on('close', (code: number) => resolve(code ?? 0));
      authProcess.on('error', () => resolve(1));
    });

    if (authResult !== 0) {
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
      title: 'Export Scrt Backup',
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
      title: 'Import Scrt Backup',
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
ipcMain.handle('get-simple-secret-settings', async () => {
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
          backup: { enabled: true, frequency: 'monthly', destination: 'google-drive', lastBackup: null, recoveryPasswordSet: false }
        }
      };
    }
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Check if LLM Secrets is set up (DPAPI key or KeePass exists)
ipcMain.handle('check-simple-secret-setup', async () => {
  try {
    const credPath = path.join(ENV_CRYPTO_PATH, 'credentials');
    const dpapiKeyFile = path.join(credPath, 'EnvCrypto_DpapiMasterKey.dat');
    const hasDpapiKey = fs.existsSync(dpapiKeyFile);
    const hasKeePass = fs.existsSync(KDBX_PATH);
    const hasSettings = fs.existsSync(SETTINGS_PATH);

    let settings = null;
    if (hasSettings) {
      settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
    }

    return {
      success: true,
      isSetUp: hasDpapiKey || hasKeePass,
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
  try {
    const { exec, spawn } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');
    const authExePath = path.join(ENV_CRYPTO_PATH, 'WindowsHelloAuth.exe');

    // Step 1: Run Windows Hello authentication
    console.log('[LLM Secrets] Starting Windows Hello authentication...');
    const authProcess = spawn(authExePath, [], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      detached: false
    });

    const authResult = await new Promise<number>((resolve) => {
      authProcess.on('close', (code: number) => resolve(code ?? 0));
      authProcess.on('error', () => resolve(1));
    });

    if (authResult !== 0) {
      return { success: false, error: 'Windows Hello authentication failed or was cancelled' };
    }
    console.log('[LLM Secrets] Windows Hello authentication successful');

    // Step 2: Generate master key and store with DPAPI
    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force
        Set-Location '${KEEP_SCRT_PATH}'

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

// Authenticate with Simple mode (Windows Hello only) and return master key
ipcMain.handle('authenticate-simple', async () => {
  debugLog('authenticate-simple', 'START - Handler invoked');

  try {
    const { spawn, exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);
    const authExePath = path.join(ENV_CRYPTO_PATH, 'WindowsHelloAuth.exe');
    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');

    debugLog('authenticate-simple', 'Paths configured', { authExePath, modulePath });

    // Check if auth exe exists
    if (!fs.existsSync(authExePath)) {
      debugLog('authenticate-simple', 'ERROR - WindowsHelloAuth.exe not found', { authExePath });
      return { success: false, error: 'WindowsHelloAuth.exe not found' };
    }

    debugLog('authenticate-simple', 'Starting Windows Hello authentication...');
    const authProcess = spawn(authExePath, [], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      detached: false
    });

    const authResult = await new Promise<number>((resolve) => {
      authProcess.on('close', (code: number) => {
        debugLog('authenticate-simple', 'Windows Hello process closed', { exitCode: code });
        resolve(code ?? 0);
      });
      authProcess.on('error', (err: Error) => {
        debugLog('authenticate-simple', 'Windows Hello process error', { error: err.message });
        resolve(1);
      });
    });

    if (authResult !== 0) {
      debugLog('authenticate-simple', 'Windows Hello auth failed', { exitCode: authResult });
      return { success: false, error: 'Windows Hello authentication failed or was cancelled' };
    }

    debugLog('authenticate-simple', 'Windows Hello authentication successful, retrieving DPAPI key...');

    // Retrieve DPAPI master key and create session marker
    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force

        # Get the DPAPI-stored master key
        $masterKey = Get-DpapiMasterKey
        if (-not $masterKey) {
          Write-Output "ERROR:No DPAPI master key found. Please run setup first."
          return
        }

        # Create session marker
        $sessionMarker = "SIMPLE_MODE_SESSION_" + [guid]::NewGuid().ToString()
        $metadata = @{
          CreatedAt = (Get-Date).ToString("o")
          ExpiresAt = (Get-Date).AddHours(2).ToString("o")
          Type = "SimpleSession"
          Mode = "simple"
        }
        Save-SecureCredential -Target 'EnvCrypto_SessionKey' -Value $sessionMarker -Metadata $metadata

        Write-Output "SUCCESS:$masterKey"
      } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
      }
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');

    debugLog('authenticate-simple', 'Executing PowerShell to retrieve DPAPI key...');
    const { stdout, stderr } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const output = stdout?.trim() || '';
    debugLog('authenticate-simple', 'PowerShell output received', {
      stdoutLength: output.length,
      stdoutPreview: output.substring(0, 100),
      stderrLength: stderr?.length || 0,
      stderrPreview: stderr?.substring(0, 100) || ''
    });

    const successMatch = output.match(/SUCCESS:(.+)$/m);
    const errorMatch = output.match(/ERROR:(.+)$/m);

    if (successMatch) {
      const masterKey = successMatch[1].trim();
      debugLog('authenticate-simple', 'SUCCESS - Master key retrieved', {
        masterKeyLength: masterKey.length,
        masterKeyPreview: masterKey.substring(0, 10) + '...'
      });
      return { success: true, masterKey };
    } else if (errorMatch) {
      debugLog('authenticate-simple', 'ERROR from PowerShell', { error: errorMatch[1].trim() });
      return { success: false, error: errorMatch[1].trim() };
    } else {
      debugLog('authenticate-simple', 'UNEXPECTED OUTPUT', { output, stderr });
      return { success: false, error: stderr || output || 'Unknown error during authentication' };
    }
  } catch (error) {
    debugLog('authenticate-simple', 'EXCEPTION', { error: (error as Error).message });
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

    // Open Google Drive in browser
    await shell.openExternal('https://drive.google.com/drive/my-drive');

    // Small delay then open File Explorer with file selected
    await new Promise(resolve => setTimeout(resolve, 500));
    const { exec } = require('child_process');
    exec(`explorer.exe /select,"${backupFile}"`);

    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Get backup status
ipcMain.handle('get-backup-status', async () => {
  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);
    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');

    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      Import-Module '${modulePath}' -Force
      $settings = Get-Settings
      $backupNeeded = Test-BackupNeeded
      @{
        enabled = $settings.backup.enabled
        frequency = $settings.backup.frequency
        lastBackup = $settings.backup.lastBackup
        recoveryPasswordSet = $settings.backup.recoveryPasswordSet
        backupNeeded = $backupNeeded
      } | ConvertTo-Json
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
    const { stdout } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const status = JSON.parse(stdout.trim());
    return { success: true, data: status };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Set recovery password
ipcMain.handle('set-recovery-password', async (_event, password: string) => {
  debugLog('set-recovery-password', 'START - Handler invoked', { passwordLength: password?.length || 0 });

  try {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);
    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');

    // Check if Set-BackupRecoveryPassword function exists in module
    debugLog('set-recovery-password', 'Checking module path', { modulePath, exists: fs.existsSync(modulePath) });

    const escapedPassword = password.replace(/'/g, "''");
    const psCommand = `
      $ProgressPreference = 'SilentlyContinue'
      $ErrorActionPreference = 'Stop'
      try {
        Import-Module '${modulePath}' -Force

        # Check if function exists
        $funcExists = Get-Command -Name Set-BackupRecoveryPassword -ErrorAction SilentlyContinue
        if (-not $funcExists) {
          Write-Output "ERROR:Function Set-BackupRecoveryPassword not found in module"
          return
        }

        $securePassword = ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force
        $result = Set-BackupRecoveryPassword -RecoveryPassword $securePassword
        if ($result) {
          Write-Output "SUCCESS"
        } else {
          Write-Output "ERROR:Set-BackupRecoveryPassword returned false or null"
        }
      } catch {
        Write-Output "ERROR:$($_.Exception.Message)"
      }
    `;
    const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');

    debugLog('set-recovery-password', 'Executing PowerShell command...');
    const { stdout, stderr } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`);

    const output = stdout?.trim() || '';
    debugLog('set-recovery-password', 'PowerShell output received', {
      stdoutLength: output.length,
      stdout: output,
      stderrLength: stderr?.length || 0,
      stderr: stderr || ''
    });

    if (output === 'SUCCESS') {
      debugLog('set-recovery-password', 'SUCCESS');
      return { success: true };
    } else if (output.startsWith('ERROR:')) {
      const errorMsg = output.substring(6);
      debugLog('set-recovery-password', 'ERROR from PowerShell', { error: errorMsg });
      return { success: false, error: errorMsg };
    } else {
      debugLog('set-recovery-password', 'UNEXPECTED OUTPUT', { output, stderr });
      return { success: false, error: `Unexpected output: ${output || stderr || 'empty'}` };
    }
  } catch (error) {
    const errorMsg = (error as Error).message;
    debugLog('set-recovery-password', 'EXCEPTION', { error: errorMsg });
    return { success: false, error: errorMsg };
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

// Debug logging from renderer
ipcMain.handle('debug-log', async (_event, context: string, message: string, data?: Record<string, unknown>) => {
  debugLog(`renderer:${context}`, message, data);
  return { success: true };
});

// ============================================
// Setup Wizard IPC Handlers
// ============================================

// Check if this is a first-time run (no KeePass database exists)
ipcMain.handle('check-first-run', async () => {
  try {
    const isFirstRun = !fs.existsSync(KDBX_PATH);
    return { success: true, isFirstRun };
  } catch (error) {
    return { success: false, isFirstRun: true, error: (error as Error).message };
  }
});

// Create vault (KeePass database + master key)
ipcMain.handle('create-vault', async (_event, password: string) => {
  try {
    const { exec, spawn } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    const modulePath = path.join(ENV_CRYPTO_PATH, 'EnvCrypto.psm1');
    const authExePath = path.join(ENV_CRYPTO_PATH, 'WindowsHelloAuth.exe');

    // Step 1: Run Windows Hello authentication
    console.log('[Setup] Starting Windows Hello authentication...');
    const authProcess = spawn(authExePath, [], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      detached: false
    });

    const authResult = await new Promise<number>((resolve) => {
      authProcess.on('close', (code: number) => resolve(code ?? 0));
      authProcess.on('error', () => resolve(1));
    });

    if (authResult !== 0) {
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
        Set-Location '${KEEP_SCRT_PATH}'

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
    const content = generateClaudeMdContent(secretNames);
    fs.writeFileSync(CLAUDE_MD_PATH, content, 'utf8');
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

// ============================================
// License IPC Handlers
// ============================================

// Check if app is licensed
ipcMain.handle('license-check', async () => {
  try {
    const isLicensed = await licenseService.isLicensed();
    return { success: true, isLicensed };
  } catch (error) {
    return { success: false, isLicensed: false, error: (error as Error).message };
  }
});

// Get full license status
ipcMain.handle('license-status', async () => {
  try {
    const status = await licenseService.getLicenseStatus();
    return { success: true, data: status };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Validate a license key format (without activation)
ipcMain.handle('license-validate', async (_event, key: string) => {
  try {
    const isValid = licenseService.validateKeyOnly(key);
    return { success: true, isValid };
  } catch (error) {
    return { success: false, isValid: false, error: (error as Error).message };
  }
});

// Activate license with email verification
ipcMain.handle('license-activate', async (_event, key: string, email: string) => {
  activityLogger.log('license_activate_attempt', 'LicenseActivation', { keyLength: key?.length || 0 }, 'pending');
  try {
    const result = await licenseService.activateLicense(key, email);
    if (result.success) {
      activityLogger.logSuccess('license_activate', 'LicenseActivation');
    } else {
      activityLogger.logFailure('license_activate', 'LicenseActivation', result.error || 'Unknown error');
    }
    return result;
  } catch (error) {
    const errorMsg = (error as Error).message;
    activityLogger.logFailure('license_activate', 'LicenseActivation', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Activate license without email (format check only)
ipcMain.handle('license-activate-key-only', async (_event, key: string) => {
  activityLogger.log('license_activate_key_only_attempt', 'LicenseActivation', { keyLength: key?.length || 0 }, 'pending');
  try {
    const result = await licenseService.activateLicenseWithoutEmail(key);
    if (result.success) {
      activityLogger.logSuccess('license_activate_key_only', 'LicenseActivation');
    } else {
      activityLogger.logFailure('license_activate_key_only', 'LicenseActivation', result.error || 'Unknown error');
    }
    return result;
  } catch (error) {
    const errorMsg = (error as Error).message;
    activityLogger.logFailure('license_activate_key_only', 'LicenseActivation', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Deactivate license
ipcMain.handle('license-deactivate', async () => {
  try {
    await licenseService.deactivateLicense();
    activityLogger.logSuccess('license_deactivate', 'Settings');
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Open purchase page in browser
ipcMain.handle('license-open-purchase', async () => {
  try {
    // Opens the website purchase page - update this URL when Stripe is configured
    // Can be set to direct Stripe checkout link: https://buy.stripe.com/YOUR_LINK
    const purchaseUrl = process.env.PURCHASE_URL || 'https://simplescret.com/buy';
    await shell.openExternal(purchaseUrl);
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

app.on('ready', async () => {
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
