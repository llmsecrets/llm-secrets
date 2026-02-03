import * as React from 'react';

export const About: React.FC = () => {
  return (
    <div className="about">
      <div className="card">
        <h2>About LLM Secrets</h2>
        <div className="about-content">
          <h3>Version 3.2.12</h3>
          <p>
            <strong>LLM Secrets</strong> is a desktop application for secure secrets management
            designed specifically for LLM agents like Claude Code. Your secrets are protected with
            biometric authentication and never exposed to AI assistants.
          </p>

          <h3>How It Works</h3>
          <p>
            LLM Secrets injects your credentials at runtime using environment variable syntax.
            Claude Code and other LLM agents can execute commands with your secrets without ever
            seeing the actual values.
          </p>

          <h3>Security</h3>
          <p>
            LLM Secrets uses industry-standard encryption and secure storage mechanisms to
            protect your secrets and private keys. All sensitive operations are isolated
            in the main process with secure IPC communication.
          </p>

          <h3>License</h3>
          <p>
            GPL-3.0 License
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
          </div>
        </div>
      </div>
    </div>
  );
};
