import * as React from 'react';
import { useState } from 'react';

export const ClaudeMd: React.FC = () => {
  const [copied, setCopied] = useState(false);

  const claudeMdContent = `# Scrt - Claude Code Integration

## Security Rules (MUST FOLLOW)
- NEVER display secret values in output or logs
- NEVER store decrypted content in files
- NEVER include secrets in git commits
- ALWAYS use /scrt-run or psst for commands needing secrets
- ALWAYS prompt user before adding new secrets

## When to Prompt User
Prompt user for input when:
- A command fails due to missing API key/token
- Setting up a new service integration
- Rotating or updating existing credentials

Use: "I need to add [SECRET_NAME] to your encrypted .env.
Please use /dscrt to decrypt, add the secret, then /escrt to re-encrypt."

## ENV Structure (Secret Names Only)

### Blockchain / Web3
| Secret | Purpose | Used By |
|--------|---------|---------|
| PRIVATE_KEY | Wallet signing key | Foundry deploy scripts |
| PUBLIC_KEY | Wallet address (0x...) | Contract verification |
| ETHERSCAN_API_KEY | Contract verification | forge verify-contract |
| ALCHEMY_API_KEY | RPC access | All blockchain calls |
| ALCHEMY_RPC_URL | Mainnet RPC endpoint | forge script --rpc-url |
| ALCHEMY_SEPOLIA_RPC_URL | Testnet RPC | Testing deployments |
| ALCHEMY_ARBITRUM_RPC_URL | Arbitrum RPC | L2 deployments |

### Google Cloud / Services
| Secret | Purpose | Used By |
|--------|---------|---------|
| GOOGLE_SERVICE_ACCOUNT_PATH | Service account JSON | sheets.py, gmail.py |
| GOOGLE_SERVICE_ACCOUNT_EMAIL | SA email address | API authentication |
| GOOGLE_DELEGATED_USER | User to impersonate | Gmail sending |
| GOOGLE_PROJECT_ID | GCP project | All GCP services |
| GCP_INSTANCE_NAME | VM instance name | gcp-ssh.ps1 |
| GCP_ZONE | VM zone | SSH connections |
| GCP_EXTERNAL_IP | Server IP | Direct connections |

### GitHub
| Secret | Purpose | Used By |
|--------|---------|---------|
| GITHUB_PAT | Personal access token | git push, API calls |
| GITHUB_USERNAME | Account name | Repository operations |

### Local Paths
| Secret | Purpose | Used By |
|--------|---------|---------|
| KEEP_SCRT_PATH | Secrets folder location | All scripts |
| LENDVEST_PROJECT_PATH | Foundry project | deploy.ps1 |
| NYC_CODE_PATH | Backend project | API deployments |
| CHROME_PROFILE_PATH | MetaMask profile | Browser automation |
| CHROME_DEFAULT_PROFILE_PATH | Default profile | Google auth |

## Available Tools

### /dscrt - Decrypt ENV
Decrypts .env.encrypted for manual editing.
Requires: Windows Hello + KeePass password
Use when: Adding/modifying secrets

### /escrt - Encrypt ENV
Re-encrypts .env after editing.
Requires: Active session
Use when: Done editing secrets

### psst - CLI Secrets Manager
Command-line tool using Windows Credential Manager.
Use: psst --global run <command>
Use: psst --global PRIVATE_KEY ALCHEMY_API_KEY -- <command>

## Common Workflows

### Deploy Smart Contract
psst --global run forge script script/Deploy.s.sol --rpc-url mainnet --broadcast --verify

### Send Email via Gmail
python gmail.py send "recipient@example.com" "Subject" "Body"

### SSH to GCP Server
.\\gcp-ssh.ps1

### Push to GitHub (with PAT)
git push origin main`;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(claudeMdContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <div className="claude-md">
      <div className="card">
        <div className="claude-md-header">
          <h2>Claude Code Integration</h2>
          <button
            className={`btn-secondary copy-btn ${copied ? 'copied' : ''}`}
            onClick={handleCopy}
          >
            {copied ? 'Copied!' : 'Copy to Clipboard'}
          </button>
        </div>

        <p className="claude-md-intro">
          This reference document tells Claude Code how to work with Scrt securely.
          Copy this content to your project's CLAUDE.md file.
        </p>

        <div className="claude-md-content">
          <section className="claude-section">
            <h3>Security Rules (MUST FOLLOW)</h3>
            <ul className="security-rules">
              <li><span className="rule-icon">🚫</span> NEVER display secret values in output or logs</li>
              <li><span className="rule-icon">🚫</span> NEVER store decrypted content in files</li>
              <li><span className="rule-icon">🚫</span> NEVER include secrets in git commits</li>
              <li><span className="rule-icon">✅</span> ALWAYS use psst for commands needing secrets</li>
              <li><span className="rule-icon">✅</span> ALWAYS prompt user before adding new secrets</li>
            </ul>
          </section>

          <section className="claude-section">
            <h3>When to Prompt User</h3>
            <p>Prompt user for input when:</p>
            <ul>
              <li>A command fails due to missing API key/token</li>
              <li>Setting up a new service integration</li>
              <li>Rotating or updating existing credentials</li>
            </ul>
            <div className="code-example">
              <code>
                "I need to add [SECRET_NAME] to your encrypted .env.<br/>
                Please use /dscrt to decrypt, add the secret, then /escrt to re-encrypt."
              </code>
            </div>
          </section>

          <section className="claude-section">
            <h3>ENV Structure (Secret Names Only)</h3>

            <h4>Blockchain / Web3</h4>
            <table className="env-table">
              <thead>
                <tr><th>Secret</th><th>Purpose</th><th>Used By</th></tr>
              </thead>
              <tbody>
                <tr><td>PRIVATE_KEY</td><td>Wallet signing key</td><td>Foundry deploy scripts</td></tr>
                <tr><td>PUBLIC_KEY</td><td>Wallet address (0x...)</td><td>Contract verification</td></tr>
                <tr><td>ETHERSCAN_API_KEY</td><td>Contract verification</td><td>forge verify-contract</td></tr>
                <tr><td>ALCHEMY_API_KEY</td><td>RPC access</td><td>All blockchain calls</td></tr>
                <tr><td>ALCHEMY_RPC_URL</td><td>Mainnet RPC endpoint</td><td>forge script --rpc-url</td></tr>
                <tr><td>ALCHEMY_SEPOLIA_RPC_URL</td><td>Testnet RPC</td><td>Testing deployments</td></tr>
                <tr><td>ALCHEMY_ARBITRUM_RPC_URL</td><td>Arbitrum RPC</td><td>L2 deployments</td></tr>
              </tbody>
            </table>

            <h4>Google Cloud / Services</h4>
            <table className="env-table">
              <thead>
                <tr><th>Secret</th><th>Purpose</th><th>Used By</th></tr>
              </thead>
              <tbody>
                <tr><td>GOOGLE_SERVICE_ACCOUNT_PATH</td><td>Service account JSON</td><td>sheets.py, gmail.py</td></tr>
                <tr><td>GOOGLE_SERVICE_ACCOUNT_EMAIL</td><td>SA email address</td><td>API authentication</td></tr>
                <tr><td>GOOGLE_DELEGATED_USER</td><td>User to impersonate</td><td>Gmail sending</td></tr>
                <tr><td>GOOGLE_PROJECT_ID</td><td>GCP project</td><td>All GCP services</td></tr>
                <tr><td>GCP_INSTANCE_NAME</td><td>VM instance name</td><td>gcp-ssh.ps1</td></tr>
                <tr><td>GCP_ZONE</td><td>VM zone</td><td>SSH connections</td></tr>
                <tr><td>GCP_EXTERNAL_IP</td><td>Server IP</td><td>Direct connections</td></tr>
              </tbody>
            </table>

            <h4>GitHub</h4>
            <table className="env-table">
              <thead>
                <tr><th>Secret</th><th>Purpose</th><th>Used By</th></tr>
              </thead>
              <tbody>
                <tr><td>GITHUB_PAT</td><td>Personal access token</td><td>git push, API calls</td></tr>
                <tr><td>GITHUB_USERNAME</td><td>Account name</td><td>Repository operations</td></tr>
              </tbody>
            </table>

            <h4>Local Paths</h4>
            <table className="env-table">
              <thead>
                <tr><th>Secret</th><th>Purpose</th><th>Used By</th></tr>
              </thead>
              <tbody>
                <tr><td>KEEP_SCRT_PATH</td><td>Secrets folder location</td><td>All scripts</td></tr>
                <tr><td>LENDVEST_PROJECT_PATH</td><td>Foundry project</td><td>deploy.ps1</td></tr>
                <tr><td>NYC_CODE_PATH</td><td>Backend project</td><td>API deployments</td></tr>
                <tr><td>CHROME_PROFILE_PATH</td><td>MetaMask profile</td><td>Browser automation</td></tr>
                <tr><td>CHROME_DEFAULT_PROFILE_PATH</td><td>Default profile</td><td>Google auth</td></tr>
              </tbody>
            </table>
          </section>

          <section className="claude-section">
            <h3>Available Tools</h3>

            <div className="tool-card">
              <h4>/dscrt - Decrypt ENV</h4>
              <p>Decrypts .env.encrypted for manual editing.</p>
              <p><strong>Requires:</strong> Windows Hello + KeePass password</p>
              <p><strong>Use when:</strong> Adding/modifying secrets</p>
            </div>

            <div className="tool-card">
              <h4>/escrt - Encrypt ENV</h4>
              <p>Re-encrypts .env after editing.</p>
              <p><strong>Requires:</strong> Active session</p>
              <p><strong>Use when:</strong> Done editing secrets</p>
            </div>

            <div className="tool-card">
              <h4>psst - CLI Secrets Manager</h4>
              <p>Command-line tool using Windows Credential Manager.</p>
              <div className="code-example">
                <code>psst --global run &lt;command&gt;</code>
                <code>psst --global PRIVATE_KEY ALCHEMY_API_KEY -- &lt;command&gt;</code>
              </div>
            </div>
          </section>

          <section className="claude-section">
            <h3>Common Workflows</h3>

            <div className="workflow-item">
              <h4>Deploy Smart Contract</h4>
              <div className="code-example">
                <code>psst --global run forge script script/Deploy.s.sol --rpc-url mainnet --broadcast --verify</code>
              </div>
            </div>

            <div className="workflow-item">
              <h4>Send Email via Gmail</h4>
              <div className="code-example">
                <code>python gmail.py send "recipient@example.com" "Subject" "Body"</code>
              </div>
            </div>

            <div className="workflow-item">
              <h4>SSH to GCP Server</h4>
              <div className="code-example">
                <code>.\gcp-ssh.ps1</code>
              </div>
            </div>

            <div className="workflow-item">
              <h4>Push to GitHub</h4>
              <div className="code-example">
                <code>git push origin main</code>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};
