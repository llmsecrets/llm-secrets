import { ethers } from 'ethers';
import * as keytar from 'keytar';
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { app } from 'electron';
import { platform } from 'os';

const execAsync = promisify(exec);
const IS_MAC = platform() === 'darwin';

export interface WalletData {
  address: string;
  network: string;
  createdAt: string;
  walletId?: string;  // ID from wallet-registry.json
  storageLocation?: string;  // Where the private key is stored
}

interface WalletRegistry {
  wallets: {
    [id: string]: {
      address: string;
      created: string;
      network: string;
    };
  };
  current: number;
  nextId: number;
}

export class WalletService {
  private readonly SERVICE_NAME = 'scrt-electron';
  private readonly HISTORY_KEY = 'wallet-history';
  private readonly KEEP_SCRT_PATH = app.getPath('userData');
  private readonly WALLET_REGISTRY_PATH = path.join(this.KEEP_SCRT_PATH, 'wallet-tools', 'wallet-registry.json');
  private readonly PSST_PATH = path.join(this.KEEP_SCRT_PATH, 'psst', 'psst.exe');

  async generateWallet(network: string): Promise<WalletData> {
    // Generate random wallet
    const wallet = ethers.Wallet.createRandom();

    // Read current registry to get next wallet ID
    let registry: WalletRegistry;
    if (fs.existsSync(this.WALLET_REGISTRY_PATH)) {
      const registryContent = fs.readFileSync(this.WALLET_REGISTRY_PATH, 'utf-8');
      registry = JSON.parse(registryContent);
    } else {
      // Initialize new registry
      registry = {
        wallets: {},
        current: 0,
        nextId: 1,
      };
    }

    const walletId = registry.nextId;
    const createdAt = new Date().toISOString();

    // Store private key and mnemonic using psst
    await this.storeToPsst(`WALLET_${walletId}_PRIVATE_KEY`, wallet.privateKey);
    await this.storeToPsst(`WALLET_${walletId}_MNEMONIC`, wallet.mnemonic?.phrase || '');

    // Add wallet to registry
    registry.wallets[walletId.toString()] = {
      address: wallet.address,
      created: createdAt,
      network,
    };
    registry.current = walletId;
    registry.nextId = walletId + 1;

    // Write updated registry
    const registryDir = path.dirname(this.WALLET_REGISTRY_PATH);
    if (!fs.existsSync(registryDir)) {
      fs.mkdirSync(registryDir, { recursive: true });
    }
    fs.writeFileSync(this.WALLET_REGISTRY_PATH, JSON.stringify(registry, null, 2), 'utf-8');

    const walletData: WalletData = {
      address: wallet.address,
      network,
      createdAt,
      walletId: walletId.toString(),
      storageLocation: `${IS_MAC ? 'macOS Keychain' : 'Windows Credential Manager'} (WALLET_${walletId}_PRIVATE_KEY)`,
    };

    return walletData;
  }

  /**
   * Store a secret in the system credential store
   */
  private async storeToPsst(key: string, value: string): Promise<void> {
    try {
      if (IS_MAC) {
        // macOS: use keytar (Keychain)
        await keytar.setPassword('scrt-wallet', key, value);
      } else {
        // Windows: use psst (Credential Manager)
        const command = `powershell.exe -Command "echo '${value}' | & '${this.PSST_PATH}' --global set ${key}"`;
        const { stderr } = await execAsync(command, { windowsHide: true });
        if (stderr && stderr.trim() && !stderr.includes('successfully')) {
          throw new Error(`psst error: ${stderr}`);
        }
      }
    } catch (error) {
      throw new Error(`Failed to store wallet key: ${(error as Error).message}`);
    }
  }

  async storePrivateKey(label: string, privateKey: string): Promise<void> {
    try {
      await keytar.setPassword(this.SERVICE_NAME, label, privateKey);
    } catch (error) {
      throw new Error(`Failed to store private key: ${(error as Error).message}`);
    }
  }

  async getPrivateKey(label: string): Promise<string | null> {
    return await keytar.getPassword(this.SERVICE_NAME, label);
  }

  async addToHistory(walletData: WalletData): Promise<void> {
    const history = await this.getWalletHistory();
    history.push(walletData);

    // Keep only last 50 wallets
    const trimmedHistory = history.slice(-50);

    const historyJson = JSON.stringify(trimmedHistory);
    await keytar.setPassword(this.SERVICE_NAME, this.HISTORY_KEY, historyJson);
  }

  async getWalletHistory(): Promise<WalletData[]> {
    try {
      const historyJson = await keytar.getPassword(this.SERVICE_NAME, this.HISTORY_KEY);
      if (!historyJson) {
        return [];
      }
      return JSON.parse(historyJson);
    } catch {
      return [];
    }
  }

  async deleteWallet(label: string): Promise<boolean> {
    return await keytar.deletePassword(this.SERVICE_NAME, label);
  }

  /**
   * Read wallets from the wallet-tools registry
   * These wallets have their private keys stored in Windows Credential Manager via psst
   */
  async getWalletsFromRegistry(): Promise<WalletData[]> {
    try {
      if (!fs.existsSync(this.WALLET_REGISTRY_PATH)) {
        return [];
      }

      const registryContent = fs.readFileSync(this.WALLET_REGISTRY_PATH, 'utf-8');
      const registry: WalletRegistry = JSON.parse(registryContent);

      const wallets: WalletData[] = [];

      for (const [id, walletInfo] of Object.entries(registry.wallets)) {
        wallets.push({
          address: walletInfo.address,
          network: walletInfo.network,
          createdAt: walletInfo.created,
          walletId: id,
          storageLocation: `${IS_MAC ? 'macOS Keychain' : 'Windows Credential Manager'} (WALLET_${id}_PRIVATE_KEY)`,
        });
      }

      // Sort by wallet ID (ascending)
      wallets.sort((a, b) => {
        const idA = parseInt(a.walletId || '0');
        const idB = parseInt(b.walletId || '0');
        return idA - idB;
      });

      return wallets;
    } catch (error) {
      console.error('Failed to read wallet registry:', error);
      return [];
    }
  }

  /**
   * Get the current active wallet ID from the registry
   */
  async getCurrentWalletId(): Promise<number | null> {
    try {
      if (!fs.existsSync(this.WALLET_REGISTRY_PATH)) {
        return null;
      }

      const registryContent = fs.readFileSync(this.WALLET_REGISTRY_PATH, 'utf-8');
      const registry: WalletRegistry = JSON.parse(registryContent);

      return registry.current;
    } catch (error) {
      console.error('Failed to read current wallet ID:', error);
      return null;
    }
  }
}
