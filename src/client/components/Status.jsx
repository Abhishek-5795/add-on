import React from 'react';

/**
 * Status component - displays sync status and errors
 */
const Status = ({ status, onRefresh, onClearErrors }) => {
  if (!status) {
    return (
      <div className="loading">
        Loading status...
      </div>
    );
  }

  const { lastSync, errorHistory, config } = status;

  // Determine status indicator
  let statusClass = 'status-pending';
  let statusText = 'No sync yet';
  
  if (lastSync) {
    if (lastSync.status === 'success') {
      statusClass = 'status-success';
      statusText = 'Success';
    } else if (lastSync.status === 'error') {
      statusClass = 'status-error';
      statusText = 'Error';
    }
  }

  // Format timestamp
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    try {
      const date = new Date(timestamp);
      return date.toLocaleString();
    } catch (e) {
      return timestamp;
    }
  };

  return (
    <div className="container">
      {/* Last Sync Status */}
      <div className="section">
        <div className="section-title">Last Sync Status</div>
        
        <div className="status-row">
          <span className={`status-indicator ${statusClass}`}></span>
          <span className="value">{statusText}</span>
        </div>
        
        {lastSync && (
          <>
            <div className="status-row">
              <span className="label">Timestamp:</span>
              <span className="value">{formatTimestamp(lastSync.timestamp)}</span>
            </div>
            
            {lastSync.operationType && (
              <div className="status-row">
                <span className="label">Operation:</span>
                <span className="value">{lastSync.operationType}</span>
              </div>
            )}
            
            {lastSync.rowNumber && (
              <div className="status-row">
                <span className="label">Row:</span>
                <span className="value">{lastSync.rowNumber}</span>
              </div>
            )}
            
            {lastSync.error && (
              <div className="status-row">
                <span className="label">Error:</span>
                <span className="value" style={{ color: '#d93025' }}>{lastSync.error}</span>
              </div>
            )}
          </>
        )}
        
        {!lastSync && (
          <div className="empty-state">
            No webhook calls yet. Edit a monitored column to trigger a sync.
          </div>
        )}
      </div>

      {/* Configuration Summary */}
      <div className="section">
        <div className="section-title">Configuration</div>
        
        <div className="config-item">
          <div className="config-label">Webhook URL:</div>
          <div className="config-value">
            {config?.webhookUrl || 'Not configured'}
          </div>
        </div>
        
        <div className="config-item">
          <div className="config-label">Monitored Columns:</div>
          <div className="config-value">
            {config?.triggerColumns && config.triggerColumns.length > 0 ? (
              config.triggerColumns.map((col, idx) => (
                <span key={idx} className="badge">{col}</span>
              ))
            ) : (
              <span>None</span>
            )}
          </div>
        </div>
        
        <div className="config-item">
          <div className="config-label">Debounce Delay:</div>
          <div className="config-value">
            {config?.debounceDelay ? `${config.debounceDelay}ms` : 'N/A'}
          </div>
        </div>
      </div>

      {/* Error History */}
      {errorHistory && errorHistory.length > 0 && (
        <div className="section">
          <div className="section-title">Error History ({errorHistory.length})</div>
          
          <div className="error-list">
            {errorHistory.map((error, idx) => (
              <div key={idx} className="error-item">
                <div className="error-time">{formatTimestamp(error.timestamp)}</div>
                <div className="error-message">{error.message}</div>
              </div>
            ))}
          </div>
          
          <button className="button button-secondary" onClick={onClearErrors}>
            Clear Error History
          </button>
        </div>
      )}

      {/* Actions */}
      <div className="section">
        <button className="button" onClick={onRefresh}>
          Refresh Status
        </button>
        <button className="button button-secondary" onClick={() => {
          google.script.host.close();
        }}>
          Close
        </button>
      </div>
    </div>
  );
};

export default Status;
