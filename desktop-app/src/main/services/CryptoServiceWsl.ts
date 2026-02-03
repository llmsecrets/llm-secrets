/**
 * CryptoServiceWsl - WSL2 Daemon Integration for Electron
 *
 * This service communicates with the scrt-daemon running in WSL2 to handle
 * secret management operations. It's used when the Electron app detects
 * it's running in a WSL2 environment.
 *
 * The daemon provides:
 * - Windows Hello authentication via PowerShell bridge
 * - Secret decryption and in-memory storage
 * - Command execution with secret injection
 * - Output sanitization
 */

import { Socket } from 'net';
import * as path from 'path';
import * as fs from 'fs';
import { app } from 'electron';

interface DaemonResponse {
  success: boolean;
  error?: string;
  data?: {
    active?: boolean;
    remaining?: number;
    names?: string[];
    count?: number;
    exit_code?: number;
    output?: string;
    value?: string;
    available?: boolean;
  };
}

export class CryptoServiceWsl {
  private socketPath: string;
  private readonly isWsl: boolean;

  constructor() {
    // Detect WSL environment
    this.isWsl = this.detectWsl();

    // Socket path matches the daemon
    const runtimeDir = process.env.XDG_RUNTIME_DIR || `/run/user/${process.getuid?.() || 1000}`;
    this.socketPath = path.join(runtimeDir, 'scrt.sock');

    console.log(`[CryptoServiceWsl] WSL detected: ${this.isWsl}`);
    console.log(`[CryptoServiceWsl] Socket path: ${this.socketPath}`);
  }

  /**
   * Detect if running in WSL environment
   */
  private detectWsl(): boolean {
    // Check for WSL-specific indicators
    if (process.platform !== 'linux') {
      return false;
    }

    // Check /proc/version for WSL
    try {
      const version = fs.readFileSync('/proc/version', 'utf8');
      return version.toLowerCase().includes('microsoft') || version.toLowerCase().includes('wsl');
    } catch {
      return false;
    }
  }

  /**
   * Check if daemon is running
   */
  isDaemonRunning(): boolean {
    try {
      return fs.existsSync(this.socketPath);
    } catch {
      return false;
    }
  }

  /**
   * Send a request to the daemon and get the response
   */
  private async sendRequest(request: object): Promise<DaemonResponse> {
    return new Promise((resolve, reject) => {
      const socket = new Socket();
      let response = '';

      socket.setTimeout(30000); // 30 second timeout

      socket.on('connect', () => {
        socket.write(JSON.stringify(request) + '\n');
      });

      socket.on('data', (data) => {
        response += data.toString();
        // Check for complete JSON response (ends with newline)
        if (response.endsWith('\n')) {
          socket.end();
        }
      });

      socket.on('end', () => {
        try {
          const parsed = JSON.parse(response.trim()) as DaemonResponse;
          resolve(parsed);
        } catch (e) {
          reject(new Error(`Invalid response from daemon: ${response}`));
        }
      });

      socket.on('error', (err) => {
        reject(new Error(`Daemon connection failed: ${err.message}. Is scrt-daemon running?`));
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('Daemon request timed out'));
      });

      socket.connect(this.socketPath);
    });
  }

  /**
   * Check if Windows Hello is available
   */
  async checkHelloAvailable(): Promise<boolean> {
    const response = await this.sendRequest({ method: 'check_hello' });
    if (!response.success) {
      console.error(`[CryptoServiceWsl] check_hello failed: ${response.error}`);
      return false;
    }
    return response.data?.available ?? false;
  }

  /**
   * Check session status
   */
  async getStatus(): Promise<{ active: boolean; remaining: number }> {
    const response = await this.sendRequest({ method: 'status' });
    if (!response.success) {
      throw new Error(response.error || 'Failed to get status');
    }
    return {
      active: response.data?.active ?? false,
      remaining: response.data?.remaining ?? 0,
    };
  }

  /**
   * Unlock secrets via Windows Hello
   * This triggers biometric authentication and loads secrets into daemon memory
   */
  async unlock(ttl: number = 7200): Promise<number> {
    const response = await this.sendRequest({
      method: 'unlock',
      params: { ttl },
    });

    if (!response.success) {
      throw new Error(response.error || 'Unlock failed');
    }

    return response.data?.count ?? 0;
  }

  /**
   * List secret names (not values)
   */
  async listSecrets(): Promise<string[]> {
    const response = await this.sendRequest({ method: 'list' });

    if (!response.success) {
      throw new Error(response.error || 'Failed to list secrets');
    }

    return response.data?.names ?? [];
  }

  /**
   * Clear session and lock secrets
   */
  async logout(): Promise<void> {
    const response = await this.sendRequest({ method: 'clear' });

    if (!response.success) {
      throw new Error(response.error || 'Failed to clear session');
    }
  }

  /**
   * Decrypt secrets and return as string (for compatibility with CryptoService)
   * This first unlocks if not already unlocked, then retrieves secrets
   */
  async decrypt(masterKey?: string): Promise<string> {
    // Check if session is active
    const status = await this.getStatus();

    if (!status.active) {
      // Need to unlock first
      console.log('[CryptoServiceWsl] No active session, unlocking...');
      await this.unlock();
    }

    // Get list of secret names
    const names = await this.listSecrets();

    // Build .env format string
    // Note: We can't actually get the values here (by design)
    // This method is mainly for compatibility; actual secret use goes through `run`
    const envLines = names.map((name) => `${name}=[PROTECTED]`);

    return envLines.join('\n');
  }

  /**
   * Run a command with secrets injected
   * The daemon substitutes $env[NAME] patterns with actual values
   */
  async runWithSecrets(
    command: string,
    workingDir?: string
  ): Promise<{ exitCode: number; output: string }> {
    const response = await this.sendRequest({
      method: 'run',
      params: {
        command,
        working_dir: workingDir,
      },
    });

    if (!response.success) {
      throw new Error(response.error || 'Command execution failed');
    }

    return {
      exitCode: response.data?.exit_code ?? 1,
      output: response.data?.output ?? '',
    };
  }

  /**
   * Store secrets in daemon (for manual injection)
   * This is used when secrets come from a different source (e.g., manual entry)
   */
  async storeSecrets(
    secrets: Record<string, string>,
    ttl: number = 7200
  ): Promise<void> {
    // Generate random token
    const token = Buffer.from(
      Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))
    ).toString('base64');

    const response = await this.sendRequest({
      method: 'store',
      params: {
        token,
        secrets,
        ttl,
      },
    });

    if (!response.success) {
      throw new Error(response.error || 'Failed to store secrets');
    }
  }

  /**
   * Reveal a single secret (requires active session)
   * Note: This should only be used for GUI display, not for automation
   */
  async revealSecret(name: string): Promise<string> {
    const response = await this.sendRequest({
      method: 'reveal',
      params: { name },
    });

    if (!response.success) {
      throw new Error(response.error || `Failed to reveal secret: ${name}`);
    }

    return response.data?.value ?? '';
  }

  /**
   * Encrypt is not directly supported by the daemon
   * For WSL, encryption should go through the standard scrt-linux tools
   */
  async encrypt(content: string, masterKey: string): Promise<void> {
    throw new Error(
      'Direct encryption not supported in WSL mode. ' +
      'Use "scrt edit" command or the standard scrt-linux tools.'
    );
  }

  /**
   * Check if this service is usable (WSL detected and daemon running)
   */
  isAvailable(): boolean {
    return this.isWsl && this.isDaemonRunning();
  }
}

/**
 * Factory function to get the appropriate crypto service
 */
export function getCryptoService(): CryptoServiceWsl | null {
  const wslService = new CryptoServiceWsl();

  if (wslService.isAvailable()) {
    console.log('[CryptoService] Using WSL daemon service');
    return wslService;
  }

  console.log('[CryptoService] WSL daemon not available, falling back to standard service');
  return null;
}
