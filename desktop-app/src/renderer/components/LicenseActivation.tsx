import * as React from 'react';
import { useState } from 'react';
import './LicenseActivation.css';

interface LicenseActivationProps {
  onActivated: () => void;
}

export const LicenseActivation: React.FC<LicenseActivationProps> = ({ onActivated }) => {
  const [licenseKey, setLicenseKey] = useState('');
  const [email, setEmail] = useState('');
  const [showEmailField, setShowEmailField] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isActivating, setIsActivating] = useState(false);

  /**
   * Format license key as user types: XXXX-XXXX-XXXX-XXXX
   */
  const formatLicenseKey = (value: string): string => {
    // Remove all non-alphanumeric characters
    const cleaned = value.toUpperCase().replace(/[^A-Z0-9]/g, '');

    // Split into groups of 4
    const groups: string[] = [];
    for (let i = 0; i < cleaned.length && i < 16; i += 4) {
      groups.push(cleaned.substring(i, Math.min(i + 4, 16)));
    }

    return groups.join('-');
  };

  const handleKeyChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const formatted = formatLicenseKey(e.target.value);
    setLicenseKey(formatted);
    setError(null);
  };

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setEmail(e.target.value);
    setError(null);
  };

  /**
   * Activate license with email verification (more secure)
   */
  const handleActivateWithEmail = async () => {
    if (!licenseKey || licenseKey.length < 19) {
      setError('Please enter a complete license key');
      return;
    }

    if (!email || !email.includes('@')) {
      setError('Please enter the email address used for purchase');
      return;
    }

    setIsActivating(true);
    setError(null);

    try {
      const result = await window.electronAPI.licenseActivate(licenseKey, email);

      if (result.success) {
        onActivated();
      } else {
        setError(result.error || 'Failed to activate license');
      }
    } catch (err) {
      setError(`Error: ${(err as Error).message}`);
    } finally {
      setIsActivating(false);
    }
  };

  /**
   * Activate license with key only (less secure, format check only)
   */
  const handleActivateKeyOnly = async () => {
    if (!licenseKey || licenseKey.length < 19) {
      setError('Please enter a complete license key');
      return;
    }

    setIsActivating(true);
    setError(null);

    try {
      const result = await window.electronAPI.licenseActivateKeyOnly(licenseKey);

      if (result.success) {
        onActivated();
      } else {
        setError(result.error || 'Failed to activate license');
      }
    } catch (err) {
      setError(`Error: ${(err as Error).message}`);
    } finally {
      setIsActivating(false);
    }
  };

  /**
   * Handle activation - uses email if provided, otherwise key-only
   */
  const handleActivate = () => {
    if (showEmailField && email) {
      handleActivateWithEmail();
    } else {
      handleActivateKeyOnly();
    }
  };

  const handlePurchase = async () => {
    try {
      await window.electronAPI.licenseOpenPurchase();
    } catch (err) {
      console.error('Error opening purchase page:', err);
    }
  };

  const isKeyComplete = licenseKey.length === 19; // XXXX-XXXX-XXXX-XXXX

  return (
    <div className="license-activation">
      <div className="license-container">
        <div className="license-screen">
          <h1>Activate Simple Secret</h1>
          <p className="subtitle">
            Enter the license key from your purchase receipt email.
          </p>

          <div className="form-group">
            <label htmlFor="license-key">License Key</label>
            <input
              id="license-key"
              type="text"
              value={licenseKey}
              onChange={handleKeyChange}
              placeholder="XXXX-XXXX-XXXX-XXXX"
              className="license-input"
              autoFocus
              disabled={isActivating}
              maxLength={19}
              onKeyPress={(e) => e.key === 'Enter' && isKeyComplete && handleActivate()}
            />
          </div>

          {showEmailField && (
            <div className="form-group">
              <label htmlFor="email">Purchase Email</label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={handleEmailChange}
                placeholder="your@email.com"
                className="license-input"
                disabled={isActivating}
                onKeyPress={(e) => e.key === 'Enter' && isKeyComplete && handleActivate()}
              />
              <p className="field-hint">
                Enter the email address you used when purchasing Simple Secret.
              </p>
            </div>
          )}

          {error && <div className="error-message">{error}</div>}

          <button
            className="btn-primary"
            onClick={handleActivate}
            disabled={!isKeyComplete || isActivating}
          >
            {isActivating ? 'Activating...' : 'Activate License'}
          </button>

          <div className="secondary-actions">
            {!showEmailField && (
              <button
                className="btn-link"
                onClick={() => setShowEmailField(true)}
              >
                Verify with email (more secure)
              </button>
            )}
          </div>

          <div className="info-box">
            <p>
              <strong>Where to find your license key:</strong><br />
              Check your email for the Stripe receipt from your Simple Secret purchase.
              The license key is included in the receipt details.
            </p>
          </div>

          <div className="purchase-section">
            <div className="divider">
              <span>Don't have a license?</span>
            </div>
            <button
              className="btn-purchase"
              onClick={handlePurchase}
            >
              Purchase License
            </button>
            <p className="purchase-hint">
              One-time purchase. Lifetime updates included.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
