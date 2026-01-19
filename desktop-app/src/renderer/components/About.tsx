import * as React from 'react';

export const About: React.FC = () => {
  return (
    <div className="about">
      <div className="card">
        <h2>About LLM Secrets</h2>
        <div className="about-content">
          <h3>Version 3.0.11</h3>
          <p>
            <strong>LLM Secrets</strong> is a Windows desktop application for secure secrets management
            designed specifically for LLM agents like Claude Code. Your secrets are protected with
            Windows Hello and never exposed to AI assistants.
          </p>

          <h3>Features</h3>
          <ul>
            <li>🔐 AES-256-CBC encryption for .env files</li>
            <li>🔑 Windows Hello integration for secure authentication</li>
            <li>🤖 LLM-safe: Agents can use secrets without seeing them</li>
            <li>💰 Ethereum wallet generation with secure key storage</li>
            <li>🌐 Support for Mainnet, Sepolia, Arbitrum, and Polygon</li>
            <li>🎨 Dark mode support</li>
            <li>🔒 Private keys stored in system keychain</li>
          </ul>

          <h3>How It Works</h3>
          <p>
            LLM Secrets injects your credentials at runtime using <code>$env:SECRET_NAME</code> syntax.
            Claude Code and other LLM agents can execute commands with your secrets without ever
            seeing the actual values.
          </p>

          <h3>Technology Stack</h3>
          <ul>
            <li>Electron 39.2.7</li>
            <li>React 19.2.3</li>
            <li>TypeScript 4.5.4</li>
            <li>ethers.js 6.16.0 (Ethereum library)</li>
            <li>keytar 7.9.0 (Secure credential storage)</li>
          </ul>

          <h3>Security</h3>
          <p>
            LLM Secrets uses industry-standard encryption and secure storage mechanisms to
            protect your secrets and private keys. All sensitive operations are isolated
            in the main process with secure IPC communication.
          </p>

          <h3>License</h3>
          <p>
            AGPL-3.0 License
            <br />
            Copyright © 2025 VestedJosh
          </p>

          <h3>Links</h3>
          <div className="link-list">
            <a href="https://github.com/VestedJosh/Scrt" target="_blank" rel="noopener noreferrer">
              GitHub Repository
            </a>
            <a href="https://github.com/VestedJosh/Scrt/issues" target="_blank" rel="noopener noreferrer">
              Report an Issue
            </a>
            <a href="https://www.electronjs.org" target="_blank" rel="noopener noreferrer">
              Electron Documentation
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};
