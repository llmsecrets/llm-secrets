import * as fs from 'fs';
import * as path from 'path';
import * as keytar from 'keytar';
import { app } from 'electron';
import { WalletData } from './WalletService';

export interface BackupData {
  version: string;
  createdAt: string;
  settings: {
    theme: string;
    autoLock: {
      enabled: boolean;
      intervalMinutes: number;
    };
  };
  wallets: WalletData[];
  encryptedEnv?: string; // Base64-encoded .env.encrypted file
  metadata: {
    appVersion: string;
    exportedBy: string;
    encryptedEnvIncluded: boolean;
  };
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

export class BackupRestoreService {
  private readonly SERVICE_NAME = 'scrt-electron';
  private readonly BACKUP_VERSION = '1.0';
  private readonly isTestMode: boolean;
  private readonly TEST_SANDBOX_PATH: string;
  private readonly KEEP_SCRT_PATH: string;
  private readonly ENV_FOLDER_NAME = 'env';

  constructor() {
    this.isTestMode = process.env.SCRT_TEST_MODE === 'true';

    if (this.isTestMode) {
      this.TEST_SANDBOX_PATH = path.join(__dirname, '..', '..', '..', 'test-sandbox');
      this.KEEP_SCRT_PATH = path.join(this.TEST_SANDBOX_PATH, 'crypto');
    } else {
      this.TEST_SANDBOX_PATH = '';
      // Use portable userData path - works on any machine
      this.KEEP_SCRT_PATH = app.getPath('userData');
    }
  }

  /**
   * Get the path to the env versions folder
   */
  private getEnvFolderPath(): string {
    return path.join(this.KEEP_SCRT_PATH, this.ENV_FOLDER_NAME);
  }

  /**
   * Get all version numbers from the env folder
   */
  private getExistingVersions(): number[] {
    const envFolder = this.getEnvFolderPath();
    if (!fs.existsSync(envFolder)) return [];
    const files = fs.readdirSync(envFolder);
    const versions: number[] = [];
    for (const file of files) {
      const match = file.match(/^\.env\.encrypted\.v(\d+)$/);
      if (match) versions.push(parseInt(match[1], 10));
    }
    return versions.sort((a, b) => a - b);
  }

  /**
   * Get the highest version number
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
      return legacyPath;
    }
    return path.join(this.getEnvFolderPath(), '.env.encrypted.v1');
  }

  /**
   * Get the path for a new version
   */
  private getNextVersionPath(): string {
    const envFolder = this.getEnvFolderPath();
    if (!fs.existsSync(envFolder)) {
      fs.mkdirSync(envFolder, { recursive: true });
    }
    const nextVersion = this.getHighestVersion() + 1;
    return path.join(envFolder, `.env.encrypted.v${nextVersion}`);
  }

  /**
   * Export settings, wallet configurations, and encrypted env to a backup file
   * Note: Private keys are NOT exported for security reasons
   * The .env.encrypted file IS included (still encrypted, requires master key)
   */
  async exportBackup(outputPath: string): Promise<BackupData> {
    // Export the encrypted env file as base64 (uses current/highest version)
    const encryptedEnvPath = this.getCurrentEnvPath();
    let encryptedEnv: string | undefined;
    let encryptedEnvIncluded = false;

    if (fs.existsSync(encryptedEnvPath)) {
      try {
        const envBuffer = fs.readFileSync(encryptedEnvPath);
        encryptedEnv = envBuffer.toString('base64');
        encryptedEnvIncluded = true;
        console.log(`[BackupRestoreService] Included ${encryptedEnvPath} (${envBuffer.length} bytes)`);
      } catch (error) {
        console.error(`[BackupRestoreService] Failed to read encrypted env: ${(error as Error).message}`);
      }
    } else {
      console.warn(`[BackupRestoreService] Encrypted env not found at: ${encryptedEnvPath}`);
    }

    const backup: BackupData = {
      version: this.BACKUP_VERSION,
      createdAt: new Date().toISOString(),
      settings: await this.exportSettings(),
      wallets: await this.exportWalletConfigs(),
      encryptedEnv,
      metadata: {
        appVersion: '2.0.0',
        exportedBy: 'LLM Secrets',
        encryptedEnvIncluded,
      },
    };

    // Write to file
    fs.writeFileSync(outputPath, JSON.stringify(backup, null, 2), 'utf-8');

    console.log(`[BackupRestoreService] Backup exported to: ${outputPath}`);
    return backup;
  }

  /**
   * Import settings, wallet configurations, and encrypted env from a backup file
   */
  async importBackup(inputPath: string): Promise<ImportResult> {
    const result: ImportResult = {
      success: false,
      imported: {
        settings: false,
        wallets: 0,
        encryptedEnv: false,
      },
      errors: [],
    };

    try {
      // Read and parse backup file
      const content = fs.readFileSync(inputPath, 'utf-8');
      const backup: BackupData = JSON.parse(content);

      // Validate backup format
      if (!backup.version || !backup.settings || !backup.wallets) {
        result.errors.push('Invalid backup file format');
        return result;
      }

      // Import settings
      try {
        await this.importSettings(backup.settings);
        result.imported.settings = true;
      } catch (error) {
        result.errors.push(`Failed to import settings: ${(error as Error).message}`);
      }

      // Import wallet configurations (addresses only, not private keys)
      try {
        const importedCount = await this.importWalletConfigs(backup.wallets);
        result.imported.wallets = importedCount;
      } catch (error) {
        result.errors.push(`Failed to import wallets: ${(error as Error).message}`);
      }

      // Import encrypted env file if present (creates new version, never overwrites)
      if (backup.encryptedEnv) {
        try {
          // Always create a new version instead of overwriting
          const encryptedEnvPath = this.getNextVersionPath();
          const envBuffer = Buffer.from(backup.encryptedEnv, 'base64');

          fs.writeFileSync(encryptedEnvPath, envBuffer);
          result.imported.encryptedEnv = true;
          console.log(`[BackupRestoreService] Restored to ${encryptedEnvPath} (${envBuffer.length} bytes)`);
        } catch (error) {
          result.errors.push(`Failed to import encrypted env: ${(error as Error).message}`);
        }
      }

      result.success = result.errors.length === 0;
    } catch (error) {
      result.errors.push(`Failed to read backup file: ${(error as Error).message}`);
    }

    return result;
  }

  /**
   * Validate a backup file without importing
   */
  validateBackup(inputPath: string): { valid: boolean; errors: string[]; info?: BackupData } {
    const errors: string[] = [];

    try {
      const content = fs.readFileSync(inputPath, 'utf-8');
      const backup: BackupData = JSON.parse(content);

      // Check required fields
      if (!backup.version) {
        errors.push('Missing version field');
      }

      if (!backup.createdAt) {
        errors.push('Missing createdAt field');
      }

      if (!backup.settings) {
        errors.push('Missing settings field');
      }

      if (!Array.isArray(backup.wallets)) {
        errors.push('Invalid or missing wallets field');
      }

      if (errors.length === 0) {
        return { valid: true, errors: [], info: backup };
      }

      return { valid: false, errors };
    } catch (error) {
      return { valid: false, errors: [`Invalid JSON: ${(error as Error).message}`] };
    }
  }

  private async exportSettings(): Promise<BackupData['settings']> {
    // Get theme setting
    const theme = await keytar.getPassword(this.SERVICE_NAME, 'setting_theme') || 'light';

    // Get auto-lock settings
    const autoLockJson = await keytar.getPassword(this.SERVICE_NAME, 'autolock_settings');
    let autoLock = { enabled: false, intervalMinutes: 5 };
    if (autoLockJson) {
      try {
        autoLock = JSON.parse(autoLockJson);
      } catch {
        // Use defaults
      }
    }

    return { theme, autoLock };
  }

  private async importSettings(settings: BackupData['settings']): Promise<void> {
    // Import theme
    if (settings.theme) {
      await keytar.setPassword(this.SERVICE_NAME, 'setting_theme', settings.theme);
    }

    // Import auto-lock settings
    if (settings.autoLock) {
      await keytar.setPassword(
        this.SERVICE_NAME,
        'autolock_settings',
        JSON.stringify(settings.autoLock)
      );
    }
  }

  private async exportWalletConfigs(): Promise<WalletData[]> {
    // Read wallet registry
    const registryPath = this.isTestMode
      ? path.join(this.TEST_SANDBOX_PATH, 'wallets', 'wallet-registry.test.json')
      : path.join(this.KEEP_SCRT_PATH, 'wallet-tools', 'wallet-registry.json');

    if (!fs.existsSync(registryPath)) {
      return [];
    }

    try {
      const content = fs.readFileSync(registryPath, 'utf-8');
      const registry = JSON.parse(content);

      const wallets: WalletData[] = [];
      for (const [id, info] of Object.entries(registry.wallets || {})) {
        const walletInfo = info as { address: string; created: string; network: string };
        wallets.push({
          address: walletInfo.address,
          network: walletInfo.network,
          createdAt: walletInfo.created,
          walletId: id,
          // Note: storageLocation is intentionally omitted for security
        });
      }

      return wallets;
    } catch (error) {
      console.error('Failed to export wallet configs:', error);
      return [];
    }
  }

  private async importWalletConfigs(wallets: WalletData[]): Promise<number> {
    // Read existing registry
    const registryPath = this.isTestMode
      ? path.join(this.TEST_SANDBOX_PATH, 'wallets', 'wallet-registry.test.json')
      : path.join(this.KEEP_SCRT_PATH, 'wallet-tools', 'wallet-registry.json');

    let registry = {
      wallets: {} as Record<string, { address: string; created: string; network: string }>,
      current: 0,
      nextId: 1,
    };

    if (fs.existsSync(registryPath)) {
      try {
        const content = fs.readFileSync(registryPath, 'utf-8');
        registry = JSON.parse(content);
      } catch {
        // Use fresh registry
      }
    }

    let importedCount = 0;

    // Import wallets that don't already exist (by address)
    const existingAddresses = new Set(
      Object.values(registry.wallets).map((w) => w.address.toLowerCase())
    );

    for (const wallet of wallets) {
      if (!existingAddresses.has(wallet.address.toLowerCase())) {
        const id = registry.nextId.toString();
        registry.wallets[id] = {
          address: wallet.address,
          created: wallet.createdAt || new Date().toISOString(),
          network: wallet.network,
        };
        registry.nextId++;
        importedCount++;

        // Note: Private keys must be manually re-imported
        // This is a security feature - backups don't contain private keys
      }
    }

    // Ensure directory exists
    const registryDir = path.dirname(registryPath);
    if (!fs.existsSync(registryDir)) {
      fs.mkdirSync(registryDir, { recursive: true });
    }

    // Write updated registry
    fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2), 'utf-8');

    return importedCount;
  }
}
