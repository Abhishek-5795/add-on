import React, { useState, useEffect } from 'react';
import Status from './Status';

/**
 * Sidebar component - main sidebar layout
 */
const Sidebar = () => {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Load status on mount
  useEffect(() => {
    loadStatus();
    
    // Refresh status every 10 seconds
    const interval = setInterval(() => {
      loadStatus();
    }, 10000);
    
    return () => clearInterval(interval);
  }, []);

  const loadStatus = () => {
    setLoading(true);
    setError(null);
    
    google.script.run
      .withSuccessHandler((result) => {
        if (result.success) {
          setStatus(result);
          setError(null);
        } else {
          setError(result.error);
        }
        setLoading(false);
      })
      .withFailureHandler((error) => {
        setError(error.message);
        setLoading(false);
      })
      .getStatus();
  };

  const handleClearErrors = () => {
    google.script.run
      .withSuccessHandler((result) => {
        if (result.success) {
          loadStatus(); // Reload to show cleared errors
        }
      })
      .withFailureHandler((error) => {
        setError(error.message);
      })
      .clearErrorHistoryFromSidebar();
  };

  if (loading && !status) {
    return (
      <div className="loading">
        Loading status...
      </div>
    );
  }

  if (error) {
    return (
      <div className="container">
        <div className="section error-item">
          <div className="section-title">Error</div>
          <div className="error-message">{error}</div>
          <button className="button" onClick={loadStatus}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <Status 
      status={status} 
      onRefresh={loadStatus}
      onClearErrors={handleClearErrors}
    />
  );
};

export default Sidebar;
