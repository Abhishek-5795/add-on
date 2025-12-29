/**
 * Trigger handling with debouncing and duplicate prevention
 */

/**
 * Handle edit events with debouncing
 * @param {Object} e - Edit event object
 */
function handleEdit(e) {
  try {
    // Get event information
    const range = e.range;
    const sheet = range.getSheet();
    const sheetName = sheet.getName();
    const row = range.getRow();
    const column = range.getColumn();
    
    // Skip header row
    if (row === 1) {
      Logger.log('Skipping header row edit');
      return;
    }
    
    // Get column header
    const headers = getColumnHeaders(sheet);
    const columnName = headers[column - 1];
    
    if (!columnName) {
      Logger.log('Column has no header, skipping');
      return;
    }
    
    Logger.log(`Edit detected: Sheet="${sheetName}", Row=${row}, Column="${columnName}"`);
    
    // Check if this column should trigger webhook
    if (!shouldTriggerWebhook(columnName)) {
      Logger.log(`Column "${columnName}" is not a trigger column, skipping`);
      return;
    }
    
    // Get the full row data
    const rowData = getRowData(sheet, row);
    
    // Create change object
    const changeData = {
      sheetName: sheetName,
      user: getCurrentUserEmail(),
      operationType: 'UPDATE',
      timestamp: new Date().toISOString(),
      rowNumber: row,
      data: rowData
    };
    
    // Add to pending changes with debouncing
    addPendingChange(changeData);
    
  } catch (error) {
    Logger.log(`Error in handleEdit: ${error.message}`);
    addErrorToHistory('Error handling edit', {
      error: error.message,
      stack: error.stack
    });
  }
}

/**
 * Detect new row additions
 * Check if the last row has data and hasn't been processed
 */
function detectNewRows() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheets = ss.getSheets();
    
    sheets.forEach(sheet => {
      const lastRow = sheet.getLastRow();
      
      // Skip if only header row or empty
      if (lastRow <= 1) {
        return;
      }
      
      const sheetName = sheet.getName();
      // Use base64 encoding to safely encode sheet name in key
      // Handle encoding errors gracefully
      let encodedSheetName;
      try {
        encodedSheetName = Utilities.base64Encode(sheetName);
      } catch (e) {
        // Fallback: use sanitized sheet name if encoding fails
        encodedSheetName = sheetName.replace(/[^a-zA-Z0-9]/g, '_');
      }
      const processedKey = `processed_${encodedSheetName}_${lastRow}`;
      
      // Check if this row has already been processed
      const props = PropertiesService.getScriptProperties();
      if (props.getProperty(processedKey)) {
        return;
      }
      
      // Get row data
      const rowData = getRowData(sheet, lastRow);
      
      // Check if row has any data
      const hasData = Object.values(rowData).some(value => value !== '' && value !== null && value !== undefined);
      
      if (!hasData) {
        return;
      }
      
      Logger.log(`New row detected: Sheet="${sheetName}", Row=${lastRow}`);
      
      // Create change object for INSERT
      const changeData = {
        sheetName: sheetName,
        user: getCurrentUserEmail(),
        operationType: 'INSERT',
        timestamp: new Date().toISOString(),
        rowNumber: lastRow,
        data: rowData
      };
      
      // Add to pending changes
      addPendingChange(changeData);
      
      // Mark as processed
      props.setProperty(processedKey, 'true');
    });
    
  } catch (error) {
    Logger.log(`Error in detectNewRows: ${error.message}`);
    addErrorToHistory('Error detecting new rows', {
      error: error.message
    });
  }
}

/**
 * Add change to pending queue with debouncing
 * @param {Object} changeData - Change data
 */
function addPendingChange(changeData) {
  try {
    const props = PropertiesService.getScriptProperties();
    const changeKey = generateChangeKey(changeData.sheetName, changeData.rowNumber);
    
    // Get pending changes
    let pendingChanges = {};
    try {
      const pendingJson = props.getProperty('pendingChanges');
      if (pendingJson) {
        pendingChanges = JSON.parse(pendingJson);
      }
    } catch (e) {
      Logger.log('Error parsing pending changes: ' + e.message);
    }
    
    // Add or update change
    pendingChanges[changeKey] = changeData;
    
    // Save pending changes
    props.setProperty('pendingChanges', JSON.stringify(pendingChanges));
    
    Logger.log(`Added pending change: ${changeKey}`);
    
    // Schedule debounced processing
    scheduleDebounceProcessing();
    
  } catch (error) {
    Logger.log(`Error adding pending change: ${error.message}`);
    addErrorToHistory('Error adding pending change', {
      error: error.message,
      changeData: changeData
    });
  }
}

/**
 * Schedule debounced processing of pending changes
 */
function scheduleDebounceProcessing() {
  try {
    const props = PropertiesService.getScriptProperties();
    const existingTriggerId = props.getProperty('debounceTrigger');
    
    // Delete existing trigger if any using stored ID
    if (existingTriggerId) {
      const triggers = ScriptApp.getProjectTriggers();
      for (let i = 0; i < triggers.length; i++) {
        if (triggers[i].getUniqueId() === existingTriggerId) {
          ScriptApp.deleteTrigger(triggers[i]);
          break; // Exit loop once found
        }
      }
    }
    
    // Create new trigger with debounce delay
    const debounceDelay = getConfig('debounceDelay') || 5000;
    const triggerTime = new Date(Date.now() + debounceDelay);
    
    const trigger = ScriptApp.newTrigger('processPendingChanges')
      .timeBased()
      .at(triggerTime)
      .create();
    
    // Store trigger ID for efficient deletion
    props.setProperty('debounceTrigger', trigger.getUniqueId());
    
    Logger.log(`Scheduled processing at ${triggerTime.toISOString()}`);
    
  } catch (error) {
    Logger.log(`Error scheduling debounce: ${error.message}`);
    // If trigger creation fails, process immediately
    processPendingChanges();
  }
}

/**
 * Process all pending changes
 * This function is called after debounce delay
 */
function processPendingChanges() {
  try {
    Logger.log('Processing pending changes...');
    
    const props = PropertiesService.getScriptProperties();
    
    // Get pending changes
    let pendingChanges = {};
    try {
      const pendingJson = props.getProperty('pendingChanges');
      if (pendingJson) {
        pendingChanges = JSON.parse(pendingJson);
      }
    } catch (e) {
      Logger.log('Error parsing pending changes: ' + e.message);
      return;
    }
    
    // Check if there are any changes
    const changeKeys = Object.keys(pendingChanges);
    if (changeKeys.length === 0) {
      Logger.log('No pending changes to process');
      return;
    }
    
    Logger.log(`Processing ${changeKeys.length} pending change(s)`);
    
    // Process each change
    let successCount = 0;
    let errorCount = 0;
    
    changeKeys.forEach(key => {
      const changeData = pendingChanges[key];
      const result = processWebhook(changeData);
      
      if (result.success) {
        successCount++;
      } else {
        errorCount++;
      }
    });
    
    Logger.log(`Processed: ${successCount} successful, ${errorCount} errors`);
    
    // Clear pending changes
    props.setProperty('pendingChanges', JSON.stringify({}));
    
    // Clean up trigger using stored ID
    const triggerId = props.getProperty('debounceTrigger');
    if (triggerId) {
      const triggers = ScriptApp.getProjectTriggers();
      for (let i = 0; i < triggers.length; i++) {
        if (triggers[i].getUniqueId() === triggerId) {
          ScriptApp.deleteTrigger(triggers[i]);
          break;
        }
      }
      props.deleteProperty('debounceTrigger');
    }
    
  } catch (error) {
    Logger.log(`Error processing pending changes: ${error.message}`);
    addErrorToHistory('Error processing pending changes', {
      error: error.message
    });
  }
}

/**
 * Clean up old processed row markers
 * Should be called periodically to prevent property storage bloat
 */
function cleanupProcessedMarkers() {
  try {
    const props = PropertiesService.getScriptProperties();
    const allProps = props.getProperties();
    
    let cleanedCount = 0;
    for (const key in allProps) {
      if (key.startsWith('processed_')) {
        props.deleteProperty(key);
        cleanedCount++;
      }
    }
    
    Logger.log(`Cleaned up ${cleanedCount} processed markers`);
  } catch (error) {
    Logger.log(`Error cleaning up markers: ${error.message}`);
  }
}
