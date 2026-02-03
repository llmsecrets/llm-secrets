import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';
import * as keytar from 'keytar';

const KEYTAR_SERVICE = 'LLMSecrets';
const KEYTAR_MASTER_KEY_ACCOUNT = 'master-key';
const KEYTAR_SESSION_ACCOUNT = 'session-active';
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;

export class CryptoServiceMac {
  private userDataPath: string;
  private envDir: string;
  private sessionKey: Buffer | null = null;
  private sessionExpiry: number = 0;

  constructor() {
    this.userDataPath = app.getPath('userData');
    this.envDir = this.userDataPath;
    this.ensureDirectories();
  }

  private ensureDirectories(): void {
    if (!fs.existsSync(this.userDataPath)) {
      fs.mkdirSync(this.userDataPath, { recursive: true });
    }
  }

  async generateMasterKey(): Promise<void> {
    const masterKey = crypto.randomBytes(KEY_LENGTH);
    const masterKeyB64 = masterKey.toString('base64');
    await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_MASTER_KEY_ACCOUNT, masterKeyB64);
  }

  async getMasterKey(): Promise<Buffer> {
    const masterKeyB64 = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_MASTER_KEY_ACCOUNT);
    if (!masterKeyB64) {
      throw new Error('Master key not found in Keychain. Run setup first.');
    }
    return Buffer.from(masterKeyB64, 'base64');
  }

  async hasMasterKey(): Promise<boolean> {
    const key = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_MASTER_KEY_ACCOUNT);
    return key !== null;
  }

  async startSession(durationSeconds: number = 7200): Promise<void> {
    const masterKey = await this.getMasterKey();
    this.sessionKey = masterKey;
    this.sessionExpiry = Date.now() + (durationSeconds * 1000);
    await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_SESSION_ACCOUNT, 'active');
  }

  async endSession(): Promise<void> {
    this.sessionKey = null;
    this.sessionExpiry = 0;
    await keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_SESSION_ACCOUNT);
  }

  isSessionActive(): boolean {
    if (!this.sessionKey) return false;
    if (Date.now() > this.sessionExpiry) {
      this.sessionKey = null;
      this.sessionExpiry = 0;
      return false;
    }
    return true;
  }

  private getSessionKey(): Buffer {
    if (!this.isSessionActive()) {
      throw new Error('No active session. Authenticate with Touch ID first.');
    }
    return this.sessionKey!;
  }

  encryptEnv(content: string): string {
    const masterKey = this.getSessionKey();
    const salt = crypto.randomBytes(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const derivedKey = crypto.pbkdf2Sync(masterKey, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
    const cipher = crypto.createCipheriv(ALGORITHM, derivedKey, iv);
    let encrypted = cipher.update(content, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const combined = Buffer.concat([salt, iv, encrypted]);
    const outputPath = this.getNextEnvPath();
    fs.writeFileSync(outputPath, combined);
    fs.chmodSync(outputPath, 0o600);
    return outputPath;
  }

  decryptEnv(): string {
    const masterKey = this.getSessionKey();
    const envPath = this.getLatestEnvPath();
    if (!envPath || !fs.existsSync(envPath)) {
      throw new Error('No encrypted .env file found.');
    }
    const fileData = fs.readFileSync(envPath);
    const salt = fileData.subarray(0, SALT_LENGTH);
    const iv = fileData.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const ciphertext = fileData.subarray(SALT_LENGTH + IV_LENGTH);
    const derivedKey = crypto.pbkdf2Sync(masterKey, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
    const decipher = crypto.createDecipheriv(ALGORITHM, derivedKey, iv);
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  }

  addToEnv(newContent: string): string {
    let existing = '';
    try {
      existing = this.decryptEnv();
    } catch {
      // No existing file, start fresh
    }
    const merged = existing ? `${existing}\n${newContent}` : newContent;
    return this.encryptEnv(merged);
  }

  getLatestVersion(): number {
    if (!fs.existsSync(this.envDir)) return 0;
    const files = fs.readdirSync(this.envDir)
      .filter(f => f.match(/^\.env\.encrypted\.v\d+$/))
      .map(f => parseInt(f.replace('.env.encrypted.v', ''), 10))
      .sort((a, b) => a - b);
    return files.length > 0 ? files[files.length - 1] : 0;
  }

  getLatestEnvPath(): string | null {
    const version = this.getLatestVersion();
    if (version === 0) return null;
    return path.join(this.envDir, `.env.encrypted.v${version}`);
  }

  private getNextEnvPath(): string {
    const next = this.getLatestVersion() + 1;
    return path.join(this.envDir, `.env.encrypted.v${next}`);
  }

  listSecretNames(): string[] {
    try {
      const plaintext = this.decryptEnv();
      return plaintext
        .split('\n')
        .filter(line => line.trim() && !line.trim().startsWith('#'))
        .map(line => line.split('=')[0].trim())
        .filter(name => /^[A-Za-z_][A-Za-z0-9_]*$/.test(name));
    } catch {
      return [];
    }
  }

  async hasSimpleModeVault(): Promise<boolean> {
    return this.hasMasterKey();
  }
}
