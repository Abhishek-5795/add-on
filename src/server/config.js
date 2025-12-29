/**
 * Configuration management for the add-on
 * Uses Script Properties for persistent storage
 */

// Default configuration values
// Note: This is intentionally duplicated in src/shared/constants.js for reference.
// Google Apps Script doesn't support ES6 imports, so each file defines its own constants.
const DEFAULT_CONFIG = {
  webhookUrl: 'https://example.com/webhook',
  triggerColumns: ['phoneNumber'],
  debounceDelay: 5000,
  retryAttempts: 3,
  retryDelays: [1000, 2000, 4000],
  maxErrorHistory: 10
};

/**
 * Initialize configuration with default values
 */
function initializeConfig() {
  const props = PropertiesService.getScriptProperties();
  
  // Only set defaults if not already configured
  if (!props.getProperty('webhookUrl')) {
    props.setProperty('webhookUrl', DEFAULT_CONFIG.webhookUrl);
  }
  
  if (!props.getProperty('triggerColumns')) {
    props.setProperty('triggerColumns', JSON.stringify(DEFAULT_CONFIG.triggerColumns));
  }
  
  if (!props.getProperty('debounceDelay')) {
    props.setProperty('debounceDelay', DEFAULT_CONFIG.debounceDelay.toString());
  }
  
  if (!props.getProperty('retryAttempts')) {
    props.setProperty('retryAttempts', DEFAULT_CONFIG.retryAttempts.toString());
  }
  
  if (!props.getProperty('retryDelays')) {
    props.setProperty('retryDelays', JSON.stringify(DEFAULT_CONFIG.retryDelays));
  }
  
  if (!props.getProperty('errorHistory')) {
    props.setProperty('errorHistory', JSON.stringify([]));
  }
}

/**
 * Get configuration value
 * @param {string} key - Configuration key
 * @returns {*} Configuration value
 */
function getConfig(key) {
  const props = PropertiesService.getScriptProperties();
  const value = props.getProperty(key);
  
  if (!value) {
    return DEFAULT_CONFIG[key];
  }
  
  // Parse JSON values
  if (key === 'triggerColumns' || key === 'retryDelays' || key === 'errorHistory') {
    try {
      return JSON.parse(value);
    } catch (e) {
      Logger.log(`Error parsing ${key}: ${e.message}`);
      return DEFAULT_CONFIG[key];
    }
  }
  
  // Parse numeric values
  if (key === 'debounceDelay' || key === 'retryAttempts') {
    return parseInt(value, 10);
  }
  
  return value;
}

/**
 * Set configuration value
 * @param {string} key - Configuration key
 * @param {*} value - Configuration value
 */
function setConfig(key, value) {
  const props = PropertiesService.getScriptProperties();
  
  // Stringify arrays and objects
  if (typeof value === 'object') {
    props.setProperty(key, JSON.stringify(value));
  } else {
    props.setProperty(key, value.toString());
  }
}

/**
 * Get all configuration
 * @returns {Object} All configuration values
 */
function getAllConfig() {
  return {
    webhookUrl: getConfig('webhookUrl'),
    triggerColumns: getConfig('triggerColumns'),
    debounceDelay: getConfig('debounceDelay'),
    retryAttempts: getConfig('retryAttempts'),
    retryDelays: getConfig('retryDelays')
  };
}

/**
 * Update configuration
 * @param {Object} config - Configuration object
 */
function updateConfig(config) {
  if (config.webhookUrl !== undefined) {
    setConfig('webhookUrl', config.webhookUrl);
  }
  
  if (config.triggerColumns !== undefined) {
    setConfig('triggerColumns', config.triggerColumns);
  }
  
  if (config.debounceDelay !== undefined) {
    setConfig('debounceDelay', config.debounceDelay);
  }
  
  if (config.retryAttempts !== undefined) {
    setConfig('retryAttempts', config.retryAttempts);
  }
  
  if (config.retryDelays !== undefined) {
    setConfig('retryDelays', config.retryDelays);
  }
}

/**
 * Test webhook connection
 * @returns {Object} Test result
 */
function testWebhookConnection() {
  try {
    const webhookUrl = getConfig('webhookUrl');
    
    if (!webhookUrl || webhookUrl === 'https://example.com/webhook') {
      return {
        success: false,
        message: 'Please configure a valid webhook URL'
      };
    }
    
    const testPayload = {
      test: true,
      timestamp: new Date().toISOString(),
      message: 'Test connection from Google Sheets Add-on'
    };
    
    const options = {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify(testPayload),
      muteHttpExceptions: true
    };
    
    const response = UrlFetchApp.fetch(webhookUrl, options);
    const responseCode = response.getResponseCode();
    
    if (responseCode >= 200 && responseCode < 300) {
      return {
        success: true,
        message: `Connection successful (Status: ${responseCode})`
      };
    } else {
      return {
        success: false,
        message: `Connection failed (Status: ${responseCode})`
      };
    }
  } catch (error) {
    return {
      success: false,
      message: `Error: ${error.message}`
    };
  }
}
