/**
 * LicenseService - Offline license key validation
 *
 * Key format: XXXX-XXXX-XXXX-XXXX
 * Keys are generated from email via HMAC-SHA256
 * Matches the webhook server's algorithm for consistent validation
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

// HMAC secret - MUST match webhook server's LICENSE_HMAC_SECRET
const LICENSE_HMAC_SECRET = 'S1mple_Scrt_HMAC_Key_2024!';
const CHARSET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

export interface LicenseInfo {
  isValid: boolean;
  email?: string;
  purchaseDate?: string;
  version?: string;
}

export class LicenseService {
  private licensePath: string;
  private licenseDataPath: string;
  private cachedLicense: string | null = null;

  constructor() {
    const userDataPath = app?.getPath('userData') || process.env.APPDATA || '';
    this.licensePath = path.join(userDataPath, 'SimpleSecret', 'license.key');
    this.licenseDataPath = path.join(userDataPath, 'SimpleSecret', 'license.json');
  }

  /**
   * Generate a license key for a given email
   * This MUST match the webhook server's algorithm exactly
   */
  static generateKey(email: string): string {
    const normalizedEmail = email.toLowerCase().trim();
    const hmac = crypto.createHmac('sha256', LICENSE_HMAC_SECRET);
    hmac.update(normalizedEmail);
    const hash = hmac.digest('hex');

    let key = '';
    for (let i = 0; i < 16; i++) {
      const hexPair = hash.substring(i * 2, i * 2 + 2);
      const value = parseInt(hexPair, 16);
      key += CHARSET[value % CHARSET.length];
    }

    return `${key.substring(0, 4)}-${key.substring(4, 8)}-${key.substring(8, 12)}-${key.substring(12, 16)}`;
  }

  /**
   * Validate a license key by verifying it matches the stored email
   * Returns true if the key matches the email, or if key format is valid and we trust it
   */
  static validateKey(key: string, email?: string): boolean {
    if (!key) return false;

    // Normalize key - remove non-alphanumeric except dashes
    const normalized = key.toUpperCase().replace(/[^A-Z0-9-]/g, '');
    const parts = normalized.split('-');

    // Must have 4 parts: XXXX-XXXX-XXXX-XXXX
    if (parts.length !== 4) {
      return false;
    }

    // Each part must be 4 characters from our charset
    for (const part of parts) {
      if (part.length !== 4) return false;
      for (const char of part) {
        if (!CHARSET.includes(char)) return false;
      }
    }

    // If email provided, verify the key matches
    if (email) {
      const expectedKey = LicenseService.generateKey(email);
      return normalized === expectedKey.toUpperCase();
    }

    // If no email, just accept valid format (trust the key)
    return true;
  }

  /**
   * Save license key and email to disk
   */
  saveLicense(key: string, email: string): boolean {
    try {
      // Validate key matches email
      if (!LicenseService.validateKey(key, email)) {
        console.log('[License] Key validation failed for email:', email);
        return false;
      }

      const dir = path.dirname(this.licensePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      // Save the key
      fs.writeFileSync(this.licensePath, key, 'utf8');

      // Save license data with email
      const licenseData = {
        key,
        email: email.toLowerCase().trim(),
        activatedAt: new Date().toISOString()
      };
      fs.writeFileSync(this.licenseDataPath, JSON.stringify(licenseData, null, 2), 'utf8');

      this.cachedLicense = key;
      console.log('[License] License saved successfully');
      return true;
    } catch (error) {
      console.error('Failed to save license:', error);
      return false;
    }
  }

  /**
   * Load and validate saved license
   */
  loadLicense(): LicenseInfo {
    try {
      // Try to load license data (includes email)
      if (fs.existsSync(this.licenseDataPath)) {
        const data = JSON.parse(fs.readFileSync(this.licenseDataPath, 'utf8'));
        const isValid = LicenseService.validateKey(data.key, data.email);
        this.cachedLicense = data.key;
        return {
          isValid,
          email: data.email,
          purchaseDate: data.activatedAt
        };
      }

      // Fallback: load just the key file (for backward compatibility)
      if (fs.existsSync(this.licensePath)) {
        const key = fs.readFileSync(this.licensePath, 'utf8').trim();
        this.cachedLicense = key;
        // Without email, just validate format
        return {
          isValid: LicenseService.validateKey(key)
        };
      }

      return { isValid: false };
    } catch (error) {
      console.error('Failed to load license:', error);
      return { isValid: false };
    }
  }

  /**
   * Check if app is licensed
   */
  isLicensed(): boolean {
    return this.loadLicense().isValid;
  }

  /**
   * Get stored email (for display)
   */
  getStoredEmail(): string | null {
    try {
      if (fs.existsSync(this.licenseDataPath)) {
        const data = JSON.parse(fs.readFileSync(this.licenseDataPath, 'utf8'));
        return data.email || null;
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Remove license (for testing)
   */
  removeLicense(): void {
    try {
      if (fs.existsSync(this.licensePath)) {
        fs.unlinkSync(this.licensePath);
      }
      if (fs.existsSync(this.licenseDataPath)) {
        fs.unlinkSync(this.licenseDataPath);
      }
      this.cachedLicense = null;
    } catch (error) {
      console.error('Failed to remove license:', error);
    }
  }
}

// Export singleton
export const licenseService = new LicenseService();
