import * as React from 'react';
import { useState, useEffect } from 'react';

interface SecretDescription {
  id?: string;  // Stable identifier for UI
  name: string;
  category: string;
  purpose: string;
  whenToUse: string;
  example: string;
}

interface AIToolsSettings {
  claudeCode: boolean;
  codexCLI: boolean;
}

const CATEGORIES = [
  { value: 'blockchain', label: 'Blockchain' },
  { value: 'api', label: 'API' },
  { value: 'database', label: 'Database' },
  { value: 'cloud', label: 'Cloud' },
  { value: 'other', label: 'Other' },
];

// Generate a unique ID
const generateId = () => `secret_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

// Ensure all secrets have IDs
const ensureIds = (secrets: SecretDescription[]): SecretDescription[] => {
  return secrets.map(s => ({
    ...s,
    id: s.id || generateId()
  }));
};

export const ClaudeMd: React.FC = () => {
  const [secrets, setSecrets] = useState<SecretDescription[]>([]);
  const [aiTools, setAiTools] = useState<AIToolsSettings>({ claudeCode: true, codexCLI: true });
  const [expandedSecrets, setExpandedSecrets] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [descriptionsResult, settingsResult] = await Promise.all([
        window.electronAPI.getSecretDescriptions(),
        window.electronAPI.getAIToolsSettings(),
      ]);

      if (descriptionsResult.success && descriptionsResult.data) {
        setSecrets(ensureIds(descriptionsResult.data));
      }

      if (settingsResult.success && settingsResult.data) {
        setAiTools(settingsResult.data);
      }
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleSecretExpanded = (id: string) => {
    setExpandedSecrets(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const updateSecret = (id: string, field: keyof SecretDescription, value: string) => {
    setSecrets(prev => prev.map(s =>
      s.id === id ? { ...s, [field]: value } : s
    ));
  };

  const addSecret = () => {
    const newId = generateId();
    const newSecret: SecretDescription = {
      id: newId,
      name: 'NEW_SECRET',
      category: 'other',
      purpose: '',
      whenToUse: '',
      example: '',
    };
    setSecrets(prev => [...prev, newSecret]);
    setExpandedSecrets(prev => new Set(prev).add(newId));
  };

  const removeSecret = (id: string) => {
    setSecrets(prev => prev.filter(s => s.id !== id));
    setExpandedSecrets(prev => {
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
  };

  const getFilledFieldCount = (secret: SecretDescription): number => {
    let count = 0;
    if (secret.purpose?.trim()) count++;
    if (secret.whenToUse?.trim()) count++;
    if (secret.example?.trim()) count++;
    return count;
  };

  const handleSaveDescriptions = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const result = await window.electronAPI.saveSecretDescriptions(secrets);
      if (result.success) {
        setMessage({ type: 'success', text: 'Descriptions saved!' });
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to save' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: (error as Error).message });
    } finally {
      setSaving(false);
      setTimeout(() => setMessage(null), 3000);
    }
  };

  const handleSaveAITools = async (newSettings: AIToolsSettings) => {
    setAiTools(newSettings);
    try {
      await window.electronAPI.saveAIToolsSettings(newSettings);
    } catch (error) {
      console.error('Failed to save AI tools settings:', error);
    }
  };

  const handleGenerateFiles = async () => {
    setGenerating(true);
    setMessage(null);
    try {
      // Save descriptions first
      await window.electronAPI.saveSecretDescriptions(secrets);
      // Generate files
      const result = await window.electronAPI.generateClaudeMdWithDescriptions(secrets);
      if (result.success) {
        setMessage({ type: 'success', text: 'Files generated successfully!' });
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to generate files' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: (error as Error).message });
    } finally {
      setGenerating(false);
      setTimeout(() => setMessage(null), 3000);
    }
  };

  const handleViewClaudeMd = async () => {
    try {
      await window.electronAPI.openClaudeMd();
    } catch (error) {
      console.error('Failed to open CLAUDE.md:', error);
    }
  };

  const handleViewAgentsMd = async () => {
    try {
      await window.electronAPI.openAgentsMd();
    } catch (error) {
      console.error('Failed to open AGENTS.md:', error);
    }
  };

  if (loading) {
    return (
      <div className="claude-md">
        <div className="card">
          <div className="loading-state">Loading...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="claude-md">
      <div className="card ai-tools-card">
        {/* Header */}
        <div className="ai-tools-header">
          <div className="ai-tools-title">
            <h2>AI Tool Integration</h2>
            <p className="ai-tools-subtitle">
              Configure which AI coding tools to generate instruction files for.
              Describe your secrets so AI assistants know when and how to use them.
            </p>
          </div>
          <div className="ai-tools-actions">
            <button className="btn-outline" onClick={handleViewClaudeMd}>
              View CLAUDE.md
            </button>
            <button className="btn-outline" onClick={handleViewAgentsMd}>
              View AGENTS.md
            </button>
          </div>
        </div>

        {/* AI Tool Selection */}
        <div className="ai-tool-selection">
          <label
            className={`ai-tool-option ${aiTools.claudeCode ? 'selected' : ''}`}
            onClick={() => handleSaveAITools({ ...aiTools, claudeCode: !aiTools.claudeCode })}
          >
            <input
              type="checkbox"
              checked={aiTools.claudeCode}
              onChange={() => {}}
            />
            <span className="ai-tool-name">Claude Code</span>
            <span className="ai-tool-file">CLAUDE.md</span>
          </label>
          <label
            className={`ai-tool-option ${aiTools.codexCLI ? 'selected' : ''}`}
            onClick={() => handleSaveAITools({ ...aiTools, codexCLI: !aiTools.codexCLI })}
          >
            <input
              type="checkbox"
              checked={aiTools.codexCLI}
              onChange={() => {}}
            />
            <span className="ai-tool-name">Codex CLI</span>
            <span className="ai-tool-file">AGENTS.md</span>
          </label>
        </div>

        {/* Secrets List */}
        <div className="secrets-description-list">
          {secrets.map((secret) => {
            const secretId = secret.id || secret.name;
            const isExpanded = expandedSecrets.has(secretId);
            return (
              <div
                key={secretId}
                className={`secret-item ${isExpanded ? 'expanded' : ''}`}
              >
                <div
                  className="secret-header"
                  onClick={() => toggleSecretExpanded(secretId)}
                >
                  <span className="expand-icon">{isExpanded ? '▼' : '▶'}</span>
                  <span className="secret-name">{secret.name}</span>
                  <span className="secret-category">{secret.category?.toUpperCase() || 'OTHER'}</span>
                  <span className="secret-field-count">{getFilledFieldCount(secret)}/3</span>
                </div>

                {isExpanded && (
                  <div className="secret-details">
                    <div className="form-row">
                      <label>Name</label>
                      <input
                        type="text"
                        value={secret.name}
                        onChange={(e) => updateSecret(secretId, 'name', e.target.value)}
                        placeholder="SECRET_NAME"
                      />
                    </div>
                    <div className="form-row">
                      <label>Category</label>
                      <select
                        value={secret.category}
                        onChange={(e) => updateSecret(secretId, 'category', e.target.value)}
                      >
                        {CATEGORIES.map(cat => (
                          <option key={cat.value} value={cat.value}>{cat.label}</option>
                        ))}
                      </select>
                    </div>
                    <div className="form-row">
                      <label>Purpose</label>
                      <input
                        type="text"
                        value={secret.purpose}
                        onChange={(e) => updateSecret(secretId, 'purpose', e.target.value)}
                        placeholder="What this secret is for"
                      />
                    </div>
                    <div className="form-row">
                      <label>When to Use</label>
                      <input
                        type="text"
                        value={secret.whenToUse}
                        onChange={(e) => updateSecret(secretId, 'whenToUse', e.target.value)}
                        placeholder="When the AI should use this secret"
                      />
                    </div>
                    <div className="form-row">
                      <label>Example Usage</label>
                      <input
                        type="text"
                        value={secret.example}
                        onChange={(e) => updateSecret(secretId, 'example', e.target.value)}
                        placeholder="process.env.SECRET_NAME"
                      />
                    </div>
                    <button
                      className="btn-danger btn-small"
                      onClick={() => removeSecret(secretId)}
                    >
                      Remove
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Action Buttons */}
        <div className="ai-tools-buttons">
          <button className="btn-outline" onClick={addSecret}>
            + Add Secret
          </button>
          <button
            className="btn-outline"
            onClick={handleSaveDescriptions}
            disabled={saving}
          >
            {saving ? 'Saving...' : 'Save Descriptions'}
          </button>
          <button
            className="btn-primary btn-generate"
            onClick={handleGenerateFiles}
            disabled={generating}
          >
            {generating ? 'Generating...' : 'Generate Files'}
          </button>
        </div>

        {/* Message */}
        {message && (
          <div className={`ai-tools-message ${message.type}`}>
            {message.text}
          </div>
        )}

        {/* Supported AI Tools Info */}
        <div className="supported-ai-tools">
          <h3>Supported AI Tools</h3>
          <div className="ai-tools-info-grid">
            <div className="ai-tool-info">
              <strong>Claude Code (Anthropic)</strong>
              <p>Uses CLAUDE.md for project instructions. Supports /dscrt and /escrt commands for secret management.</p>
            </div>
            <div className="ai-tool-info">
              <strong>Codex CLI (OpenAI)</strong>
              <p>Uses AGENTS.md for agent instructions. The file is automatically discovered in your project root.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
