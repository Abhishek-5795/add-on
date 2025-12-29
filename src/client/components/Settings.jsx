import React, { useState, useEffect } from 'react';

/**
 * Settings component - developer configuration panel
 */
const Settings = () => {
  const [config, setConfig] = useState(null);
  const [availableColumns, setAvailableColumns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [message, setMessage] = useState(null);

  // Load configuration on mount
  useEffect(() => {
    loadConfiguration();
    loadAvailableColumns();
  }, []);

  const loadConfiguration = () => {
    setLoading(true);
    google.script.run
      .withSuccessHandler((result) => {
        if (result.success) {
          setConfig(result.config);
        } else {
          setMessage({ type: 'error', text: result.error });
        }
        setLoading(false);
      })
      .withFailureHandler((error) => {
        setMessage({ type: 'error', text: error.message });
        setLoading(false);
      })
      .getConfiguration();
  };

  const loadAvailableColumns = () => {
    google.script.run
      .withSuccessHandler((result) => {
        if (result.success) {
          setAvailableColumns(result.columns);
        }
      })
      .withFailureHandler((error) => {
        console.error('Error loading columns:', error);
      })
      .getAvailableColumns();
  };

  const handleSave = () => {
    setSaving(true);
    setMessage(null);
    
    google.script.run
      .withSuccessHandler((result) => {
        if (result.success) {
          setMessage({ type: 'success', text: result.message });
        } else {
          setMessage({ type: 'error', text: result.error });
        }
        setSaving(false);
      })
      .withFailureHandler((error) => {
        setMessage({ type: 'error', text: error.message });
        setSaving(false);
      })
      .saveConfiguration(config);
  };

  const handleTest = () => {
    setTestResult(null);
    setMessage({ type: 'info', text: 'Testing webhook connection...' });
    
    google.script.run
      .withSuccessHandler((result) => {
        setTestResult(result);
        setMessage({
          type: result.success ? 'success' : 'error',
          text: result.message
        });
      })
      .withFailureHandler((error) => {
        setTestResult({ success: false, message: error.message });
        setMessage({ type: 'error', text: error.message });
      })
      .testWebhookFromSettings();
  };

  const handleColumnToggle = (columnName) => {
    const triggerColumns = config.triggerColumns || [];
    const index = triggerColumns.indexOf(columnName);
    
    let newColumns;
    if (index > -1) {
      // Remove column
      newColumns = triggerColumns.filter(col => col !== columnName);
    } else {
      // Add column
      newColumns = [...triggerColumns, columnName];
    }
    
    setConfig({
      ...config,
      triggerColumns: newColumns
    });
  };

  if (loading) {
    return <div className="loading">Loading configuration...</div>;
  }

  if (!config) {
    return <div className="empty-state">Unable to load configuration</div>;
  }

  return (
    <div className="container">
      {/* Message Display */}
      {message && (
        <div className={`section ${message.type === 'error' ? 'error-item' : ''}`} 
             style={{
               backgroundColor: message.type === 'success' ? '#e6f4ea' : 
                               message.type === 'error' ? '#fce8e6' : '#e8f0fe',
               borderLeft: `3px solid ${message.type === 'success' ? '#34a853' : 
                                       message.type === 'error' ? '#ea4335' : '#1967d2'}`
             }}>
          {message.text}
        </div>
      )}

      {/* Webhook URL */}
      <div className="section">
        <div className="section-title">Webhook URL</div>
        <div className="config-item">
          <input
            type="text"
            value={config.webhookUrl || ''}
            onChange={(e) => setConfig({ ...config, webhookUrl: e.target.value })}
            placeholder="https://example.com/webhook"
            style={{
              width: '100%',
              padding: '8px',
              borderRadius: '4px',
              border: '1px solid #dadce0',
              fontSize: '13px'
            }}
          />
          <div style={{ fontSize: '12px', color: '#5f6368', marginTop: '4px' }}>
            Enter the webhook endpoint URL where data will be sent
          </div>
        </div>
        <button 
          className="button button-secondary" 
          onClick={handleTest}
          disabled={!config.webhookUrl || config.webhookUrl === 'https://example.com/webhook'}
        >
          Test Connection
        </button>
      </div>

      {/* Trigger Columns */}
      <div className="section">
        <div className="section-title">Trigger Columns</div>
        <div className="config-label" style={{ marginBottom: '8px' }}>
          Select which columns should trigger webhooks when edited:
        </div>
        
        {availableColumns.length > 0 ? (
          <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
            {availableColumns.map((column, idx) => (
              <div key={idx} style={{ marginBottom: '8px' }}>
                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={config.triggerColumns?.includes(column) || false}
                    onChange={() => handleColumnToggle(column)}
                    style={{ marginRight: '8px' }}
                  />
                  <span>{column}</span>
                </label>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            No columns found. Please add headers to your sheet first.
          </div>
        )}
      </div>

      {/* Debounce Settings */}
      <div className="section">
        <div className="section-title">Debounce Settings</div>
        <div className="config-item">
          <div className="config-label">Debounce Delay (milliseconds):</div>
          <input
            type="number"
            value={config.debounceDelay || 5000}
            onChange={(e) => setConfig({ ...config, debounceDelay: parseInt(e.target.value, 10) })}
            min="1000"
            max="60000"
            step="1000"
            style={{
              width: '100%',
              padding: '8px',
              borderRadius: '4px',
              border: '1px solid #dadce0',
              fontSize: '13px'
            }}
          />
          <div style={{ fontSize: '12px', color: '#5f6368', marginTop: '4px' }}>
            Time to wait before sending changes (groups rapid edits)
          </div>
        </div>
      </div>

      {/* Retry Settings */}
      <div className="section">
        <div className="section-title">Retry Settings</div>
        <div className="config-item">
          <div className="config-label">Retry Attempts:</div>
          <input
            type="number"
            value={config.retryAttempts || 3}
            onChange={(e) => setConfig({ ...config, retryAttempts: parseInt(e.target.value, 10) })}
            min="1"
            max="10"
            style={{
              width: '100%',
              padding: '8px',
              borderRadius: '4px',
              border: '1px solid #dadce0',
              fontSize: '13px'
            }}
          />
          <div style={{ fontSize: '12px', color: '#5f6368', marginTop: '8px' }}>
            Current retry delays: {config.retryDelays?.join('ms, ')}ms (exponential backoff)
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="section">
        <button 
          className="button" 
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? 'Saving...' : 'Save Configuration'}
        </button>
        <button 
          className="button button-secondary" 
          onClick={() => google.script.host.close()}
        >
          Close
        </button>
      </div>
    </div>
  );
};

export default Settings;
