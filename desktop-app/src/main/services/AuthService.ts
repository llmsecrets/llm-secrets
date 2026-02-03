import { platform } from 'os';

export interface AuthResult {
  success: boolean;
  error?: string;
}

export interface IAuthService {
  authenticate(): Promise<AuthResult>;
  isAvailable(): Promise<boolean>;
}

export async function createAuthService(): Promise<IAuthService> {
  const os = platform();
  if (os === 'darwin') {
    const { AuthServiceMac } = await import('./AuthServiceMac');
    return new AuthServiceMac();
  } else if (os === 'win32') {
    throw new Error('Windows auth handled by existing WindowsHelloAuth.exe flow');
  } else {
    throw new Error(`Unsupported platform for biometric auth: ${os}`);
  }
}
