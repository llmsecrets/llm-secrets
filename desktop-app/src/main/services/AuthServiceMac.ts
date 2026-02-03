import { execFile } from 'child_process';
import * as path from 'path';
import { app } from 'electron';

export class AuthServiceMac {
  private touchIdBinaryPath: string;

  constructor() {
    if (app.isPackaged) {
      this.touchIdBinaryPath = path.join(process.resourcesPath, 'macos', 'TouchIDAuth');
    } else {
      this.touchIdBinaryPath = path.join(__dirname, '..', '..', 'resources', 'macos', 'TouchIDAuth');
    }
  }

  async authenticate(): Promise<{ success: boolean; error?: string }> {
    return new Promise((resolve) => {
      execFile(this.touchIdBinaryPath, [], { timeout: 30000 }, (error, stdout, stderr) => {
        if (error) {
          const exitCode = (error as any).code;
          if (exitCode === 2) {
            resolve({ success: false, error: 'No authentication method available on this Mac.' });
          } else {
            resolve({ success: false, error: stderr.trim() || 'Touch ID authentication failed.' });
          }
          return;
        }
        resolve({ success: true });
      });
    });
  }

  async isAvailable(): Promise<boolean> {
    return new Promise((resolve) => {
      execFile(this.touchIdBinaryPath, ['--check'], { timeout: 5000 }, (error) => {
        resolve(!error);
      });
    });
  }
}
