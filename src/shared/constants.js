/**
 * Shared constants used across the add-on
 */

// Default configuration values
const DEFAULT_CONFIG = {
  webhookUrl: 'https://example.com/webhook',
  triggerColumns: ['phoneNumber'],
  debounceDelay: 5000,
  retryAttempts: 3,
  retryDelays: [1000, 2000, 4000],
  maxErrorHistory: 10
};

// Operation types
const OPERATION_TYPES = {
  UPDATE: 'UPDATE',
  INSERT: 'INSERT'
};

// Configuration keys for Script Properties
const CONFIG_KEYS = {
  WEBHOOK_URL: 'webhookUrl',
  TRIGGER_COLUMNS: 'triggerColumns',
  DEBOUNCE_DELAY: 'debounceDelay',
  RETRY_ATTEMPTS: 'retryAttempts',
  RETRY_DELAYS: 'retryDelays',
  ERROR_HISTORY: 'errorHistory',
  PENDING_CHANGES: 'pendingChanges',
  LAST_SYNC: 'lastSync'
};

// Status messages
const STATUS = {
  SUCCESS: 'success',
  ERROR: 'error',
  PENDING: 'pending'
};
