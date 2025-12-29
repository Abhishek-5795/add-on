/**
 * Main entry point for Google Sheets Webhook Add-on
 * 
 * This add-on monitors sheet changes and sends data to a webhook endpoint
 * with debouncing, retry logic, and proper error handling.
 */

/**
 * Called when the add-on is installed
 * @param {Object} e - Install event
 */
function onInstall(e) {
  onOpen(e);
  initializeConfig();
}

/**
 * Called when the spreadsheet is opened
 * Creates custom menu items
 * @param {Object} e - Open event
 */
function onOpen(e) {
  try {
    const ui = SpreadsheetApp.getUi();
    
    ui.createAddonMenu()
      .addItem('Show Status', 'showSidebar')
      .addSeparator()
      .addItem('Settings', 'showSettings')
      .addItem('Test Webhook', 'testWebhook')
      .addSeparator()
      .addItem('Clear Error History', 'clearErrors')
      .addToUi();
    
    // Initialize configuration if needed
    initializeConfig();
    
  } catch (error) {
    Logger.log('Error in onOpen: ' + error.message);
  }
}

/**
 * Called when a cell is edited
 * @param {Object} e - Edit event
 */
function onEdit(e) {
  try {
    handleEdit(e);
  } catch (error) {
    Logger.log('Error in onEdit: ' + error.message);
    addErrorToHistory('Error in onEdit trigger', {
      error: error.message,
      stack: error.stack
    });
  }
}

/**
 * Show the status sidebar
 */
function showSidebar() {
  try {
    const html = HtmlService.createHtmlOutputFromFile('sidebar')
      .setTitle('Webhook Status')
      .setWidth(300);
    
    SpreadsheetApp.getUi().showSidebar(html);
  } catch (error) {
    Logger.log('Error showing sidebar: ' + error.message);
    SpreadsheetApp.getUi().alert('Error showing sidebar: ' + error.message);
  }
}

/**
 * Show the settings dialog
 */
function showSettings() {
  try {
    const html = HtmlService.createHtmlOutputFromFile('settings')
      .setWidth(500)
      .setHeight(600);
    
    SpreadsheetApp.getUi().showModalDialog(html, 'Webhook Settings');
  } catch (error) {
    Logger.log('Error showing settings: ' + error.message);
    SpreadsheetApp.getUi().alert('Error showing settings: ' + error.message);
  }
}

/**
 * Test webhook connection
 */
function testWebhook() {
  try {
    const result = testWebhookConnection();
    const ui = SpreadsheetApp.getUi();
    
    if (result.success) {
      ui.alert('Success', result.message, ui.ButtonSet.OK);
    } else {
      ui.alert('Error', result.message, ui.ButtonSet.OK);
    }
  } catch (error) {
    Logger.log('Error testing webhook: ' + error.message);
    SpreadsheetApp.getUi().alert('Error testing webhook: ' + error.message);
  }
}

/**
 * Clear error history
 */
function clearErrors() {
  try {
    clearErrorHistory();
    SpreadsheetApp.getUi().alert('Error history cleared successfully');
  } catch (error) {
    Logger.log('Error clearing errors: ' + error.message);
    SpreadsheetApp.getUi().alert('Error clearing errors: ' + error.message);
  }
}

// ==================================================
// API functions for client-side calls
// These functions are called from the React sidebar
// ==================================================

/**
 * Get current status for sidebar
 * @returns {Object} Status information
 */
function getStatus() {
  try {
    const lastSync = getLastSync();
    const errorHistory = getErrorHistory();
    const config = getAllConfig();
    
    return {
      success: true,
      lastSync: lastSync,
      errorHistory: errorHistory,
      config: config
    };
  } catch (error) {
    Logger.log('Error getting status: ' + error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Get configuration for settings panel
 * @returns {Object} Configuration
 */
function getConfiguration() {
  try {
    return {
      success: true,
      config: getAllConfig()
    };
  } catch (error) {
    Logger.log('Error getting configuration: ' + error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Save configuration from settings panel
 * @param {Object} config - Configuration object
 * @returns {Object} Result
 */
function saveConfiguration(config) {
  try {
    updateConfig(config);
    return {
      success: true,
      message: 'Configuration saved successfully'
    };
  } catch (error) {
    Logger.log('Error saving configuration: ' + error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Test webhook from settings panel
 * @returns {Object} Test result
 */
function testWebhookFromSettings() {
  try {
    return testWebhookConnection();
  } catch (error) {
    Logger.log('Error testing webhook: ' + error.message);
    return {
      success: false,
      message: error.message
    };
  }
}

/**
 * Clear error history from sidebar
 * @returns {Object} Result
 */
function clearErrorHistoryFromSidebar() {
  try {
    clearErrorHistory();
    return {
      success: true,
      message: 'Error history cleared'
    };
  } catch (error) {
    Logger.log('Error clearing error history: ' + error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Get available columns from active sheet
 * @returns {Object} Columns array or error
 */
function getAvailableColumns() {
  try {
    const sheet = SpreadsheetApp.getActiveSheet();
    const headers = getColumnHeaders(sheet);
    
    return {
      success: true,
      columns: headers.filter(h => h !== '')
    };
  } catch (error) {
    Logger.log('Error getting available columns: ' + error.message);
    return {
      success: false,
      error: error.message,
      columns: []
    };
  }
}

/**
 * Manual trigger to process pending changes immediately
 * Useful for testing
 */
function triggerProcessNow() {
  try {
    processPendingChanges();
    return {
      success: true,
      message: 'Processing triggered'
    };
  } catch (error) {
    Logger.log('Error triggering process: ' + error.message);
    return {
      success: false,
      error: error.message
    };
  }
}
