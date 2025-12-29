/**
 * Utility functions for the add-on
 */

/**
 * Get the current user's email
 * @returns {string} User email
 */
function getCurrentUserEmail() {
  try {
    return Session.getActiveUser().getEmail();
  } catch (error) {
    Logger.log('Error getting user email: ' + error.message);
    return 'unknown@example.com';
  }
}

/**
 * Get column headers from a sheet
 * @param {Sheet} sheet - The sheet object
 * @returns {Array<string>} Array of column headers
 */
function getColumnHeaders(sheet) {
  try {
    const lastColumn = sheet.getLastColumn();
    if (lastColumn === 0) {
      return [];
    }
    
    const headers = sheet.getRange(1, 1, 1, lastColumn).getValues()[0];
    return headers.map(header => header.toString().trim());
  } catch (error) {
    Logger.log('Error getting column headers: ' + error.message);
    return [];
  }
}

/**
 * Get row data as an object with column headers as keys
 * @param {Sheet} sheet - The sheet object
 * @param {number} rowNumber - Row number (1-indexed)
 * @returns {Object} Row data object
 */
function getRowData(sheet, rowNumber) {
  try {
    const headers = getColumnHeaders(sheet);
    const lastColumn = sheet.getLastColumn();
    
    if (lastColumn === 0 || headers.length === 0) {
      return {};
    }
    
    const values = sheet.getRange(rowNumber, 1, 1, lastColumn).getValues()[0];
    const rowData = {};
    
    headers.forEach((header, index) => {
      if (header) {
        rowData[header] = values[index] !== undefined ? values[index] : '';
      }
    });
    
    return rowData;
  } catch (error) {
    Logger.log(`Error getting row data for row ${rowNumber}: ${error.message}`);
    return {};
  }
}

/**
 * Validate data before sending to webhook
 * @param {Object} data - Data to validate
 * @returns {boolean} True if valid
 */
function validateData(data) {
  if (!data || typeof data !== 'object') {
    return false;
  }
  
  // Check required fields
  if (!data.sheetName || !data.operationType || !data.timestamp) {
    return false;
  }
  
  // Check operation type
  if (data.operationType !== 'UPDATE' && data.operationType !== 'INSERT') {
    return false;
  }
  
  return true;
}

/**
 * Sanitize data to prevent XSS and injection attacks
 * Strategy: Remove dangerous content and encode remaining special characters
 * @param {*} value - Value to sanitize
 * @returns {*} Sanitized value
 */
function sanitizeValue(value) {
  if (typeof value === 'string') {
    // Step 1: Remove script tags and dangerous content
    let sanitized = value
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
      .replace(/<[^>]*>/g, '') // Remove all HTML tags
      .replace(/javascript:/gi, '') // Remove javascript: URLs
      .replace(/on\w+\s*=/gi, '') // Remove event handlers like onclick=
      .trim();
    
    // Step 2: Encode special characters for additional safety
    // Using HTML entities for quotes to maintain readability in webhook payloads
    sanitized = sanitized
      .replace(/[<>]/g, '') // Remove any remaining angle brackets
      .replace(/['"]/g, match => match === '"' ? '&quot;' : '&#39;'); // Encode quotes as entities
    
    return sanitized;
  }
  return value;
}

/**
 * Sanitize an entire object
 * @param {Object} obj - Object to sanitize
 * @returns {Object} Sanitized object
 */
function sanitizeObject(obj) {
  const sanitized = {};
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      sanitized[key] = sanitizeValue(obj[key]);
    }
  }
  return sanitized;
}

/**
 * Add error to history
 * @param {string} message - Error message
 * @param {Object} details - Error details
 */
function addErrorToHistory(message, details) {
  try {
    const props = PropertiesService.getScriptProperties();
    let errorHistory = [];
    
    try {
      const historyJson = props.getProperty('errorHistory');
      if (historyJson) {
        errorHistory = JSON.parse(historyJson);
      }
    } catch (e) {
      Logger.log('Error parsing error history: ' + e.message);
    }
    
    const errorEntry = {
      timestamp: new Date().toISOString(),
      message: message,
      details: details
    };
    
    errorHistory.unshift(errorEntry);
    
    // Keep only last 10 errors
    const maxErrors = getConfig('maxErrorHistory') || 10;
    if (errorHistory.length > maxErrors) {
      errorHistory = errorHistory.slice(0, maxErrors);
    }
    
    props.setProperty('errorHistory', JSON.stringify(errorHistory));
  } catch (error) {
    Logger.log('Error adding to error history: ' + error.message);
  }
}

/**
 * Get error history
 * @returns {Array} Error history
 */
function getErrorHistory() {
  try {
    const props = PropertiesService.getScriptProperties();
    const historyJson = props.getProperty('errorHistory');
    
    if (!historyJson) {
      return [];
    }
    
    return JSON.parse(historyJson);
  } catch (error) {
    Logger.log('Error getting error history: ' + error.message);
    return [];
  }
}

/**
 * Clear error history
 */
function clearErrorHistory() {
  try {
    const props = PropertiesService.getScriptProperties();
    props.setProperty('errorHistory', JSON.stringify([]));
  } catch (error) {
    Logger.log('Error clearing error history: ' + error.message);
  }
}

/**
 * Generate unique key for change tracking
 * @param {string} sheetName - Sheet name
 * @param {number} rowNumber - Row number
 * @returns {string} Unique key
 */
function generateChangeKey(sheetName, rowNumber) {
  return `${sheetName}_${rowNumber}`;
}

/**
 * Check if a column should trigger webhook
 * @param {string} columnName - Column name
 * @returns {boolean} True if column should trigger webhook
 */
function shouldTriggerWebhook(columnName) {
  const triggerColumns = getConfig('triggerColumns') || [];
  return triggerColumns.includes(columnName);
}
