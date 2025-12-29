/**
 * Webhook functionality with retry logic and exponential backoff
 */

/**
 * Send data to webhook with retry logic
 * @param {Object} payload - Data to send
 * @returns {Object} Result object with success status
 */
function sendToWebhook(payload) {
  const webhookUrl = getConfig('webhookUrl');
  const retryAttempts = getConfig('retryAttempts') || 3;
  const retryDelays = getConfig('retryDelays') || [1000, 2000, 4000];
  
  // Validate webhook URL
  if (!webhookUrl || webhookUrl === 'https://example.com/webhook') {
    const error = 'Webhook URL not configured';
    Logger.log(error);
    addErrorToHistory(error, { payload });
    return {
      success: false,
      error: error,
      attempts: 0
    };
  }
  
  // Validate payload
  if (!validateData(payload)) {
    const error = 'Invalid payload data';
    Logger.log(error);
    addErrorToHistory(error, { payload });
    return {
      success: false,
      error: error,
      attempts: 0
    };
  }
  
  // Sanitize payload data
  const sanitizedPayload = {
    ...payload,
    data: sanitizeObject(payload.data)
  };
  
  let lastError = null;
  
  // Attempt to send with retries
  for (let attempt = 1; attempt <= retryAttempts; attempt++) {
    try {
      Logger.log(`Webhook attempt ${attempt} of ${retryAttempts}`);
      
      const options = {
        method: 'post',
        contentType: 'application/json',
        payload: JSON.stringify(sanitizedPayload),
        muteHttpExceptions: true
      };
      
      const response = UrlFetchApp.fetch(webhookUrl, options);
      const responseCode = response.getResponseCode();
      const responseText = response.getContentText();
      
      Logger.log(`Webhook response: ${responseCode}`);
      
      // Success status codes (2xx)
      if (responseCode >= 200 && responseCode < 300) {
        Logger.log('Webhook sent successfully');
        updateLastSync({
          status: 'success',
          timestamp: new Date().toISOString(),
          rowNumber: payload.rowNumber,
          operationType: payload.operationType
        });
        return {
          success: true,
          attempts: attempt,
          statusCode: responseCode,
          response: responseText
        };
      }
      
      // Server error or rate limit - retry
      if (responseCode >= 500 || responseCode === 429) {
        lastError = `Server error: ${responseCode}`;
        Logger.log(`${lastError} - will retry`);
      } else {
        // Client error - don't retry
        lastError = `Client error: ${responseCode} - ${responseText}`;
        Logger.log(lastError);
        addErrorToHistory('Webhook failed', {
          statusCode: responseCode,
          response: responseText,
          payload: sanitizedPayload
        });
        return {
          success: false,
          error: lastError,
          attempts: attempt,
          statusCode: responseCode
        };
      }
      
    } catch (error) {
      lastError = error.message;
      Logger.log(`Webhook attempt ${attempt} failed: ${lastError}`);
    }
    
    // Wait before retry (except after last attempt)
    if (attempt < retryAttempts) {
      // Use the delay for this attempt, or the last delay if out of bounds
      const delayIndex = Math.min(attempt - 1, retryDelays.length - 1);
      const delay = retryDelays[delayIndex];
      Logger.log(`Waiting ${delay}ms before retry...`);
      Utilities.sleep(delay);
    }
  }
  
  // All retries failed
  const finalError = `Webhook failed after ${retryAttempts} attempts: ${lastError}`;
  Logger.log(finalError);
  addErrorToHistory(finalError, {
    payload: sanitizedPayload,
    attempts: retryAttempts
  });
  
  updateLastSync({
    status: 'error',
    timestamp: new Date().toISOString(),
    error: finalError,
    rowNumber: payload.rowNumber,
    operationType: payload.operationType
  });
  
  return {
    success: false,
    error: lastError,
    attempts: retryAttempts
  };
}

/**
 * Update last sync status
 * @param {Object} syncInfo - Sync information
 */
function updateLastSync(syncInfo) {
  try {
    const props = PropertiesService.getScriptProperties();
    props.setProperty('lastSync', JSON.stringify(syncInfo));
  } catch (error) {
    Logger.log('Error updating last sync: ' + error.message);
  }
}

/**
 * Get last sync status
 * @returns {Object} Last sync information
 */
function getLastSync() {
  try {
    const props = PropertiesService.getScriptProperties();
    const lastSyncJson = props.getProperty('lastSync');
    
    if (!lastSyncJson) {
      return null;
    }
    
    return JSON.parse(lastSyncJson);
  } catch (error) {
    Logger.log('Error getting last sync: ' + error.message);
    return null;
  }
}

/**
 * Process and send webhook for a change
 * @param {Object} changeData - Change data object
 */
function processWebhook(changeData) {
  try {
    const payload = {
      sheetName: changeData.sheetName,
      user: changeData.user,
      operationType: changeData.operationType,
      timestamp: changeData.timestamp,
      rowNumber: changeData.rowNumber,
      data: changeData.data
    };
    
    Logger.log(`Processing webhook for ${changeData.operationType} on row ${changeData.rowNumber}`);
    
    // Send to webhook (non-blocking)
    const result = sendToWebhook(payload);
    
    if (!result.success) {
      Logger.log(`Webhook failed but continuing: ${result.error}`);
    }
    
    return result;
  } catch (error) {
    Logger.log(`Error processing webhook: ${error.message}`);
    addErrorToHistory('Error processing webhook', {
      error: error.message,
      changeData: changeData
    });
    return {
      success: false,
      error: error.message
    };
  }
}
