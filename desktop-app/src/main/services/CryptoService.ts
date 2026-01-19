import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import * as fs from 'fs';
import * as keytar from 'keytar';
import { app } from 'electron';

const execAsync = promisify(exec);

export class CryptoService {
  private readonly SERVICE_NAME = 'scrt-electron';
  private readonly SETTINGS_PREFIX = 'setting_';
  private readonly KEEP_SCRT_PATH: string;
  private readonly TEST_SANDBOX_PATH: string;
  private readonly envCryptoModulePath: string;
  private readonly isTestMode: boolean;
  private readonly ENV_FOLDER_NAME = 'env';

  constructor() {
    // Detect test mode from environment variable
    this.isTestMode = process.env.SCRT_TEST_MODE === 'true';

    if (this.isTestMode) {
      // Use test sandbox paths
      this.TEST_SANDBOX_PATH = path.join(__dirname, '..', '..', '..', 'test-sandbox');
      this.KEEP_SCRT_PATH = path.join(this.TEST_SANDBOX_PATH, 'crypto');
      this.envCryptoModulePath = path.join(this.KEEP_SCRT_PATH, 'EnvCrypto.psm1');
      console.log('[CryptoService] Running in TEST MODE - using sandbox');
      console.log(`[CryptoService] Sandbox: ${this.TEST_SANDBOX_PATH}`);
    } else {
<<<<<<< Updated upstream
      // Use portable userData path - works on any machine
      // EnvCrypto.psm1 and PoShKeePass are copied here at app startup from bundled resources
      this.KEEP_SCRT_PATH = app.getPath('userData');
=======
      // Use production paths - must match index.ts paths (Keep Scrt\Scrt\env-crypto-test)
      this.KEEP_SCRT_PATH = path.join('C:', 'Users', 'jgott', 'OneDrive', 'Desktop', 'Keep Scrt', 'Scrt');
>>>>>>> Stashed changes
      this.TEST_SANDBOX_PATH = '';
      this.envCryptoModulePath = path.join(this.KEEP_SCRT_PATH, 'EnvCrypto.psm1');
      console.log(`[CryptoService] Using userData path: ${this.KEEP_SCRT_PATH}`);
    }
  }

  /**
   * Get the path to the env versions folder
   */
  private getEnvFolderPath(): string {
    return path.join(this.KEEP_SCRT_PATH, this.ENV_FOLDER_NAME);
  }

  /**
   * Ensure the env folder exists
   */
  private ensureEnvFolderExists(): void {
    const envFolder = this.getEnvFolderPath();
    if (!fs.existsSync(envFolder)) {
      fs.mkdirSync(envFolder, { recursive: true });
      console.log(`[CryptoService] Created env folder: ${envFolder}`);
    }
  }

  /**
   * Get all version numbers from the env folder
   * Files are named: .env.encrypted.v1, .env.encrypted.v2, etc.
   */
  private getExistingVersions(): number[] {
    const envFolder = this.getEnvFolderPath();
    if (!fs.existsSync(envFolder)) {
      return [];
    }

    const files = fs.readdirSync(envFolder);
    const versions: number[] = [];

    for (const file of files) {
      const match = file.match(/^\.env\.encrypted\.v(\d+)$/);
      if (match) {
        versions.push(parseInt(match[1], 10));
      }
    }

    return versions.sort((a, b) => a - b);
  }

  /**
   * Get the highest version number, or 0 if no versions exist
   */
  private getHighestVersion(): number {
    const versions = this.getExistingVersions();
    return versions.length > 0 ? versions[versions.length - 1] : 0;
  }

  /**
   * Get the path to the current (highest version) encrypted file
   * Falls back to legacy .env.encrypted if no versions exist
   */
  private getCurrentEnvPath(): string {
    const highestVersion = this.getHighestVersion();

    if (highestVersion > 0) {
      return path.join(this.getEnvFolderPath(), `.env.encrypted.v${highestVersion}`);
    }

    // Fall back to legacy path for backwards compatibility
    const legacyPath = path.join(this.KEEP_SCRT_PATH, '.env.encrypted');
    if (fs.existsSync(legacyPath)) {
      console.log('[CryptoService] Using legacy .env.encrypted path');
      return legacyPath;
    }

    // No encrypted file exists yet
    return path.join(this.getEnvFolderPath(), '.env.encrypted.v1');
  }

  /**
   * Get the path for a new version (next version number)
   */
  private getNextVersionPath(): string {
    this.ensureEnvFolderExists();
    const nextVersion = this.getHighestVersion() + 1;
    return path.join(this.getEnvFolderPath(), `.env.encrypted.v${nextVersion}`);
  }

  async decrypt(masterKey?: string): Promise<string> {
    try {
      // Use PowerShell to decrypt the current (highest version) .env.encrypted
      // If no masterKey provided, use Windows Hello + KeePass to get it automatically
      const envPath = this.isTestMode
        ? path.join(this.TEST_SANDBOX_PATH, 'crypto', '.env.encrypted')
        : this.getCurrentEnvPath();

      const useWindowsHello = !masterKey || masterKey.trim() === '';
      console.log(`[CryptoService] Decrypting file: ${envPath}`);
      console.log(`[CryptoService] Module path: ${this.envCryptoModulePath}`);
      console.log(`[CryptoService] Auth method: ${useWindowsHello ? 'Windows Hello + KeePass' : 'Manual key'}`);
      if (!useWindowsHello) {
        console.log(`[CryptoService] Master key length: ${masterKey!.length}`);
      }

      // Check if file exists
      const fs = require('fs');
      if (!fs.existsSync(envPath)) {
        throw new Error(`Encrypted file not found: ${envPath}`);
      }

      if (!fs.existsSync(this.envCryptoModulePath)) {
        throw new Error(`EnvCrypto module not found: ${this.envCryptoModulePath}`);
      }

      let psCommand: string;

      if (useWindowsHello) {
        // Use Windows Hello + KeePass to get master key automatically
        // Uses Get-SessionKey to check for active session, then Get-MasterKey to retrieve key
        psCommand = `
          $ErrorActionPreference = 'Stop'
          $ProgressPreference = 'SilentlyContinue'
          try {
            Import-Module '${this.envCryptoModulePath}' -Force

            # Check if we have an active session
            $sessionKey = Get-SessionKey
            if (-not $sessionKey) {
              Write-Output "ERROR:NO_SESSION:No active session. Please run: Import-Module EnvCrypto; New-SessionKey"
              return
            }

            # Get master key from KeePass
            $masterKey = Get-MasterKey
            if (-not $masterKey) {
              Write-Output "ERROR:KEY_FAILED:Could not retrieve master key from KeePass"
              return
            }

            # Decrypt
            $decrypted = Unprotect-EnvFile -InputPath '${envPath}' -InMemory -MasterKey $masterKey
            if ($decrypted -and $decrypted -ne 'False' -and $decrypted.Length -gt 0) {
              Write-Output $decrypted
            } else {
              Write-Output "ERROR:DECRYPTION_FAILED:Decryption returned empty result"
            }
          } catch {
            Write-Output "ERROR:EXCEPTION:$($_.Exception.Message)"
          }
        `;
      } else {
        // Use manually provided master key
        const escapedMasterKey = masterKey!.replace(/'/g, "''");
        psCommand = `
          $ErrorActionPreference = 'Stop'
          $ProgressPreference = 'SilentlyContinue'
          try {
            Import-Module '${this.envCryptoModulePath}' -Force
            $masterKey = '${escapedMasterKey}'
            $decrypted = Unprotect-EnvFile -InputPath '${envPath}' -InMemory -MasterKey $masterKey -ErrorAction Stop
            if ($decrypted -and $decrypted -ne 'False' -and $decrypted -ne $false) {
              Write-Output $decrypted
            } else {
              Write-Output "ERROR:DECRYPTION_FAILED:The master key is incorrect or the file is corrupted"
            }
          } catch {
            Write-Output "ERROR:EXCEPTION:$($_.Exception.Message)"
          }
        `;
      }

      // Run PowerShell with proper settings using EncodedCommand for reliability
      // EncodedCommand accepts a base64-encoded UTF-16LE string which avoids escaping issues
      const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
      console.log(`[CryptoService] Running PowerShell with encoded command (length: ${encodedCommand.length})`);

      const { stdout, stderr } = await execAsync(
        `powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`,
        {
          windowsHide: false,
          env: process.env,
        }
      );

      const trimmedOutput = stdout?.trim() || '';
      console.log(`[CryptoService] stdout length: ${trimmedOutput.length}`);
      console.log(`[CryptoService] stdout preview: ${trimmedOutput.substring(0, 150) || 'empty'}`);
      console.log(`[CryptoService] stderr: ${stderr?.substring(0, 300) || 'none'}`);

      // Check for ERROR: prefix in stdout (our custom error format)
      if (trimmedOutput.startsWith('ERROR:')) {
        const parts = trimmedOutput.split(':');
        const errorType = parts[1] || 'UNKNOWN';
        const errorMsg = parts.slice(2).join(':') || 'Unknown error';
        console.error(`[CryptoService] PowerShell error type: ${errorType}`);
        throw new Error(errorMsg);
      }

      // Check for decryption errors in stderr
      if (stderr) {
        if (stderr.includes('Invalid key') || stderr.includes('corrupted file') || stderr.includes('Decryption failed')) {
          throw new Error('Invalid master key or corrupted file. Please verify your 44-character master key is correct.');
        }
        if (stderr.includes('Invalid master key format')) {
          throw new Error('Invalid master key format. Key must be a 44-character base64 string.');
        }
        if (!stderr.includes('WARNING') && !stderr.includes('INFO') && !stderr.includes('[INFO]')) {
          throw new Error(`PowerShell error: ${stderr.substring(0, 200)}`);
        }
      }

      // Check stdout - if empty or False, the key was wrong
      if (!trimmedOutput || trimmedOutput === 'False') {
        throw new Error('Decryption failed. The master key may be incorrect or the encrypted file is corrupted.');
      }

      return trimmedOutput;
    } catch (error) {
      console.error(`[CryptoService] Decryption error: ${(error as Error).message}`);
      throw new Error(`${(error as Error).message}`);
    }
  }

  async encrypt(content: string, masterKey: string): Promise<void> {
    try {
      // Write content to temporary .env file
      const tempEnvPath = this.isTestMode
        ? path.join(this.TEST_SANDBOX_PATH, 'crypto', '.env.test')
        : path.join(this.KEEP_SCRT_PATH, '.env');

      // Get the versioned output path (creates new version, never overwrites)
      const outputPath = this.isTestMode
        ? path.join(this.TEST_SANDBOX_PATH, 'crypto', '.env.encrypted')
        : this.getNextVersionPath();

      if (this.isTestMode) {
        console.log(`[CryptoService] Encrypting test file: ${tempEnvPath}`);
      } else {
        console.log(`[CryptoService] Creating new encrypted version: ${outputPath}`);
      }

      fs.writeFileSync(tempEnvPath, content, 'utf8');

      // Determine if using session-based or manual key encryption
      const useSessionKey = !masterKey || masterKey.trim() === '';
      console.log(`[CryptoService] Encrypting with ${useSessionKey ? 'session key' : 'manual key'}`);

      let psCommand: string;

      if (useSessionKey) {
        // Use session-based encryption (Get-MasterKey from active session)
        psCommand = `
          $ErrorActionPreference = 'Stop'
          $ProgressPreference = 'SilentlyContinue'
          try {
            Import-Module '${this.envCryptoModulePath}' -Force

            # Check for active session
            $sessionKey = Get-SessionKey
            if (-not $sessionKey) {
              Write-Output "ERROR:NO_SESSION:No active session. Please authenticate first."
              return
            }

            # Get master key and encrypt
            $mk = Get-MasterKey
            if (-not $mk) {
              Write-Output "ERROR:KEY_FAILED:Could not retrieve master key"
              return
            }

            Protect-EnvFile -InputPath '${tempEnvPath}' -OutputPath '${outputPath}' -MasterKey $mk
            Remove-Item '${tempEnvPath}' -Force -ErrorAction SilentlyContinue
            Write-Output "SUCCESS:Encrypted to ${outputPath}"
          } catch {
            Write-Output "ERROR:EXCEPTION:$($_.Exception.Message)"
          }
        `;
      } else {
        // Use manually provided master key
        const escapedMasterKey = masterKey.replace(/'/g, "''");
        psCommand = `
          $ErrorActionPreference = 'Stop'
          $ProgressPreference = 'SilentlyContinue'
          try {
            Import-Module '${this.envCryptoModulePath}' -Force
            Protect-EnvFile -InputPath '${tempEnvPath}' -OutputPath '${outputPath}' -MasterKey '${escapedMasterKey}'
            Remove-Item '${tempEnvPath}' -Force -ErrorAction SilentlyContinue
            Write-Output "SUCCESS:Encrypted to ${outputPath}"
          } catch {
            Write-Output "ERROR:EXCEPTION:$($_.Exception.Message)"
          }
        `;
      }

      // Use EncodedCommand for reliability
      const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');
      const { stdout, stderr } = await execAsync(`powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand ${encodedCommand}`, {
        windowsHide: false,
        env: process.env,
      });

      const trimmedOutput = stdout?.trim() || '';
      console.log(`[CryptoService] Encrypt stdout: ${trimmedOutput}`);
      console.log(`[CryptoService] Encrypt stderr length: ${stderr?.length || 0}`);

      // Check for our custom error format
      if (trimmedOutput.startsWith('ERROR:')) {
        const parts = trimmedOutput.split(':');
        const errorType = parts[1] || 'UNKNOWN';
        const errorMsg = parts.slice(2).join(':') || 'Unknown error';
        console.error(`[CryptoService] Encryption error type: ${errorType}`);
        throw new Error(errorMsg);
      }

      // Verify success
      if (!trimmedOutput.includes('SUCCESS')) {
        // Check stderr for actual errors (not CLIXML progress/info)
        const hasActualError = stderr &&
          !stderr.includes('CLIXML') &&
          !stderr.includes('progress') &&
          !stderr.includes('[OK]') &&
          !stderr.includes('InformationRecord');

        if (hasActualError) {
          throw new Error(`PowerShell error: ${stderr.substring(0, 300)}`);
        }
      }

      console.log('[CryptoService] Encryption successful');
    } catch (error) {
      throw new Error(`Encryption failed: ${(error as Error).message}`);
    }
  }

  async saveSetting(key: string, value: string): Promise<void> {
    await keytar.setPassword(this.SERVICE_NAME, `${this.SETTINGS_PREFIX}${key}`, value);
  }

  async getSetting(key: string, defaultValue: string = ''): Promise<string> {
    const value = await keytar.getPassword(this.SERVICE_NAME, `${this.SETTINGS_PREFIX}${key}`);
    return value || defaultValue;
  }
}
