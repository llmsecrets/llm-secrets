import * as React from 'react';
import { useState, useEffect } from 'react';

interface WalletData {
  address: string;
  network: string;
  createdAt: string;
  walletId?: string;
  storageLocation?: string;
}

export const WalletTools: React.FC = () => {
  const [network, setNetwork] = useState('sepolia');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<WalletData | null>(null);
  const [registryWallets, setRegistryWallets] = useState<WalletData[]>([]);
  const [currentWalletId, setCurrentWalletId] = useState<number | null>(null);

  useEffect(() => {
    loadWalletsFromRegistry();
  }, []);

  const loadWalletsFromRegistry = async () => {
    try {
      const [walletsResponse, currentIdResponse] = await Promise.all([
        window.electronAPI.getWalletsFromRegistry(),
        window.electronAPI.getCurrentWalletId(),
      ]);

      if (walletsResponse.success && walletsResponse.data) {
        setRegistryWallets(walletsResponse.data);
      }

      if (currentIdResponse.success && currentIdResponse.data !== null) {
        setCurrentWalletId(currentIdResponse.data);
      }
    } catch (err) {
      console.error('Failed to load wallets from registry:', err);
    }
  };

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await window.electronAPI.generateWallet(network);
      if (response.success && response.data) {
        setResult(response.data);
        await loadWalletsFromRegistry();
      } else {
        setError(response.error || 'Wallet generation failed');
      }
    } catch (err) {
      setError(`Error: ${(err as Error).message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="wallet-tools">
      <div className="card">
        <h2>Generate Wallet</h2>
        <p>Create a new Ethereum wallet with secure key storage</p>

        <div className="form-group">
          <label htmlFor="network">Network:</label>
          <select
            id="network"
            value={network}
            onChange={(e) => setNetwork(e.target.value)}
            disabled={loading}
          >
            <option value="sepolia">Ethereum Sepolia (Testnet)</option>
            <option value="mainnet">Ethereum Mainnet</option>
            <option value="arbitrum">Arbitrum One</option>
            <option value="polygon">Polygon</option>
          </select>
        </div>

        <button className="btn-primary" onClick={handleGenerate} disabled={loading}>
          {loading ? 'Generating...' : 'Generate Wallet'}
        </button>

        {error && <div className="error-message">{error}</div>}

        {result && (
          <div className="result-card success">
            <h3>✓ Wallet Generated!</h3>
            <div className="result-field">
              <strong>Address:</strong>
              <code>{result.address}</code>
            </div>
            <div className="result-field">
              <strong>Network:</strong>
              <span className="badge">{result.network}</span>
            </div>
            <p className="info-text">
              Private key securely stored in system keychain
            </p>
          </div>
        )}

        <div className="info-section">
          <h3>Security Notes:</h3>
          <ul>
            <li>Private keys are stored in your system keychain</li>
            <li>Keys never appear in the UI or logs</li>
            <li>Backup your keys using a secure method</li>
            <li>Test with Sepolia before using Mainnet</li>
          </ul>
        </div>
      </div>

      <div className="card">
        <h2>Your Wallets</h2>
        <p className="info-text">
          Wallets from registry. Private keys stored securely in your system keychain.
        </p>
        {registryWallets.length === 0 ? (
          <p>No wallets found in registry.</p>
        ) : (
          <div className="wallet-list">
            {registryWallets.map((wallet, index) => (
              <div
                key={index}
                className={`wallet-item ${wallet.walletId && currentWalletId === parseInt(wallet.walletId) ? 'active' : ''}`}
              >
                <div className="wallet-header">
                  <strong>Wallet #{wallet.walletId}</strong>
                  {wallet.walletId && currentWalletId === parseInt(wallet.walletId) && (
                    <span className="badge active-badge">ACTIVE</span>
                  )}
                </div>
                <div className="wallet-address">
                  <code>{wallet.address}</code>
                </div>
                <div className="wallet-meta">
                  <span className="badge">{wallet.network}</span>
                  <span className="timestamp">
                    {new Date(wallet.createdAt).toLocaleString()}
                  </span>
                </div>
                {wallet.storageLocation && (
                  <div className="storage-info">
                    <small>Storage: {wallet.storageLocation}</small>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
