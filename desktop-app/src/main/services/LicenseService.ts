/**
 * LicenseService - License validation for LLM Secrets
 *
 * PUBLIC REPOSITORY VERSION
 *
 * This is a stub implementation for building from source.
 * When you build LLM Secrets yourself for personal use,
 * license validation is disabled.
 *
 * To purchase a license for the official build with updates
 * and support, visit: https://llmsecrets.com
 *
 * Licensed under LLM Secrets Source Available License
 * See LICENSE in root directory
 */

import * as keytar from 'keytar';

// Service name for credential storage
const KEYTAR_SERVICE = 'LLMSecrets';
const KEYTAR_ACCOUNT = 'License';

// License data structure stored in credential manager
interface StoredLicense {
  key: string;
  email: string;
  activatedAt: string;
  version: string;
}

/**
 * Validate license key format: XXXX-XXXX-XXXX-XXXX
 */
function isValidFormat(key: string): boolean {
  const normalized = key.toUpperCase().replace(/\s+/g, '').trim();
  const pattern = /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/;
  return pattern.test(normalized);
}

export class LicenseService {
  /**
   * Validate a license key against an email
   *
   * STUB: Always returns true for personal builds
   * Official builds use HMAC-SHA256 validation
   */
  validateLicenseKey(key: string, email: string): boolean {
    // Personal/development build - always valid
    console.log('[LicenseService] Running in personal build mode - validation bypassed');
    return isValidFormat(key);
  }

  /**
   * Validate a license key format only
   */
  validateKeyOnly(key: string): boolean {
    return isValidFormat(key);
  }

  /**
   * Activate a license with email verification
   *
   * STUB: Accepts any valid-format key for personal builds
   */
  async activateLicense(key: string, email: string): Promise<{ success: boolean; error?: string }> {
    try {
      const normalizedKey = key.toUpperCase().replace(/\s+/g, '').trim();

      // Validate format
      if (!isValidFormat(normalizedKey)) {
        return { success: false, error: 'Invalid license key format. Expected: XXXX-XXXX-XXXX-XXXX' };
      }

      // Store the license
      const licenseData: StoredLicense = {
        key: normalizedKey,
        email: email.toLowerCase().trim(),
        activatedAt: new Date().toISOString(),
        version: '3.0.0-personal'
      };

      await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT, JSON.stringify(licenseData));

      console.log('[LicenseService] Personal build license activated');
      return { success: true };
    } catch (error) {
      return { success: false, error: `Failed to activate license: ${(error as Error).message}` };
    }
  }

  /**
   * Activate a license without email verification
   */
  async activateLicenseWithoutEmail(key: string): Promise<{ success: boolean; error?: string }> {
    try {
      const normalizedKey = key.toUpperCase().replace(/\s+/g, '').trim();

      // Validate format
      if (!isValidFormat(normalizedKey)) {
        return { success: false, error: 'Invalid license key format. Expected: XXXX-XXXX-XXXX-XXXX' };
      }

      // Store the license without email
      const licenseData: StoredLicense = {
        key: normalizedKey,
        email: '',
        activatedAt: new Date().toISOString(),
        version: '3.0.0-personal'
      };

      await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT, JSON.stringify(licenseData));

      console.log('[LicenseService] Personal build license activated (no email)');
      return { success: true };
    } catch (error) {
      return { success: false, error: `Failed to activate license: ${(error as Error).message}` };
    }
  }

  /**
   * Get current license status
   */
  async getLicenseStatus(): Promise<{
    activated: boolean;
    email?: string;
    activatedAt?: string;
    key?: string;
  }> {
    try {
      const stored = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT);

      if (!stored) {
        return { activated: false };
      }

      const licenseData: StoredLicense = JSON.parse(stored);

      return {
        activated: true,
        email: licenseData.email || undefined,
        activatedAt: licenseData.activatedAt,
        key: licenseData.key
      };
    } catch (error) {
      console.error('Error reading license status:', error);
      return { activated: false };
    }
  }

  /**
   * Check if the app is licensed (quick check for startup)
   *
   * STUB: For personal builds, you can bypass this by entering any
   * valid-format key (XXXX-XXXX-XXXX-XXXX) in the activation screen.
   *
   * Example test keys for personal builds:
   * - TEST-TEST-TEST-TEST
   * - AAAA-BBBB-CCCC-DDDD
   */
  async isLicensed(): Promise<boolean> {
    try {
      const stored = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT);
      if (!stored) return false;

      const licenseData: StoredLicense = JSON.parse(stored);
      return isValidFormat(licenseData.key);
    } catch (error) {
      return false;
    }
  }

  /**
   * Deactivate the current license
   */
  async deactivateLicense(): Promise<void> {
    try {
      await keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT);
    } catch (error) {
      console.error('Error deactivating license:', error);
    }
  }
}
