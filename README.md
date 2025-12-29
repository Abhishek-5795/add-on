# Google Sheets Webhook Add-on

A production-level Google Sheets Add-on that monitors sheet changes and sends modified data to webhook endpoints with debouncing, retry logic, and comprehensive error handling.

## Features

✨ **Smart Change Detection**
- Monitors specific columns for edits (configurable)
- Detects new row additions automatically
- 5-second debouncing to group rapid edits
- Prevents duplicate sends within debounce window

🔄 **Robust Webhook Integration**
- Configurable webhook URL
- 3 retry attempts with exponential backoff (1s, 2s, 4s)
- Comprehensive error logging
- Non-blocking operation (doesn't interfere with sheet functionality)

🎨 **React-based User Interface**
- Real-time status sidebar showing sync information
- Developer configuration panel
- Error history with timestamps
- Clean, minimal design following Google's Material Design

🔧 **Developer-Friendly Configuration**
- Easy webhook URL replacement
- Configurable trigger columns via UI
- Test webhook connection functionality
- Script Properties for persistent storage

## Technical Stack

- **Platform**: Google Apps Script
- **Frontend**: React 18 (via CDN)
- **Backend**: Google Apps Script (JavaScript ES6+)
- **Deployment**: Clasp for local development
- **Authentication**: OAuth with minimal required scopes

## Prerequisites

1. **Node.js** (v14 or higher)
   ```bash
   node --version
   ```

2. **Clasp** (Google Apps Script CLI)
   ```bash
   npm install -g @google/clasp
   ```

3. **Google Account** with access to Google Sheets

4. **Google Cloud Project** (for OAuth configuration)

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Abhishek-5795/add-on.git
cd add-on
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Clasp

First, login to Clasp:

```bash
clasp login
```

Create a new Google Apps Script project:

```bash
clasp create --type sheets --title "Webhook Add-on"
```

This will create a `.clasp.json` file with your script ID.

Alternatively, copy the example file and add your script ID:

```bash
cp .clasp.json.example .clasp.json
```

Edit `.clasp.json` and replace `YOUR_SCRIPT_ID_HERE` with your Apps Script project ID.

### 4. Configure Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the following APIs:
   - Google Sheets API
   - Google Apps Script API
4. Configure OAuth consent screen:
   - Go to "APIs & Services" > "OAuth consent screen"
   - Choose "Internal" or "External" based on your needs
   - Fill in the required information
5. Link your Apps Script project:
   - Open your Apps Script project
   - Go to "Project Settings" (gear icon)
   - Under "Google Cloud Platform (GCP) Project", click "Change project"
   - Enter your GCP project number

### 5. Deploy the Add-on

Push the code to Google Apps Script:

```bash
npm run push
```

Or push manually with clasp:

```bash
clasp push
```

### 6. Open the Script in Apps Script Editor

```bash
clasp open
```

This opens your project in the Apps Script web editor.

### 7. Test the Add-on

1. Open a Google Sheets document
2. Refresh the page if needed
3. You should see a new menu item: "Add-ons" or the add-on name
4. Click on the add-on menu to access features

## Configuration

### Setting up the Webhook URL

#### Method 1: Via UI (Recommended for Users)

1. Open your Google Sheet
2. Go to **Extensions** > **Webhook Add-on** > **Settings**
3. Enter your webhook URL
4. Click "Test Connection" to verify
5. Click "Save Configuration"

#### Method 2: Hardcode in Source (For Developers)

Edit `src/server/config.js` and change the default webhook URL:

```javascript
const DEFAULT_CONFIG = {
  webhookUrl: 'https://your-api-endpoint.com/webhook',  // Change this
  triggerColumns: ['phoneNumber'],
  debounceDelay: 5000,
  retryAttempts: 3,
  retryDelays: [1000, 2000, 4000],
  maxErrorHistory: 10
};
```

Then redeploy:

```bash
npm run push
```

### Configuring Trigger Columns

1. Open **Settings** from the add-on menu
2. Select which columns should trigger webhooks when edited
3. Default is "phoneNumber" - add more as needed
4. Click "Save Configuration"

### Webhook Payload Format

#### For Updated Rows (UPDATE)

```json
{
  "sheetName": "Sheet1",
  "user": "user@example.com",
  "operationType": "UPDATE",
  "timestamp": "2025-12-29T10:30:00.000Z",
  "rowNumber": 5,
  "data": {
    "column1": "value1",
    "column2": "value2",
    "phoneNumber": "updated value",
    "column4": "value4"
  }
}
```

#### For New Rows (INSERT)

```json
{
  "sheetName": "Sheet1",
  "user": "user@example.com",
  "operationType": "INSERT",
  "timestamp": "2025-12-29T10:30:00.000Z",
  "rowNumber": 10,
  "data": {
    "column1": "value1",
    "column2": "value2",
    "phoneNumber": "123456789",
    "column4": "value4"
  }
}
```

## Usage

### Opening the Status Sidebar

1. Go to **Extensions** > **Webhook Add-on** > **Show Status**
2. View real-time sync status
3. See error history if any
4. Status auto-refreshes every 10 seconds

### Testing the Webhook

1. Go to **Extensions** > **Webhook Add-on** > **Test Webhook**
2. Or use the "Test Connection" button in Settings
3. Verify that your endpoint receives the test payload

### Monitoring Changes

1. Add headers to your sheet (row 1)
2. Configure trigger columns in Settings
3. Edit any cell in a monitored column
4. Changes are debounced (5 seconds) and then sent to webhook
5. Check Status sidebar for sync results

### Clearing Error History

Option 1: Via Menu
- Go to **Extensions** > **Webhook Add-on** > **Clear Error History**

Option 2: Via Sidebar
- Open the Status sidebar
- Click "Clear Error History" button

## Project Structure

```
/
├── src/
│   ├── server/              # Google Apps Script backend
│   │   ├── Code.js          # Main entry point and menu handlers
│   │   ├── config.js        # Configuration management
│   │   ├── webhook.js       # Webhook logic with retry
│   │   ├── triggers.js      # Edit triggers and debouncing
│   │   ├── utils.js         # Helper functions
│   │   ├── sidebar.html     # Sidebar UI (React)
│   │   ├── settings.html    # Settings UI (React)
│   │   └── styles.html      # Shared CSS styles
│   ├── client/              # React components (reference)
│   │   ├── components/
│   │   │   ├── Sidebar.jsx
│   │   │   ├── Status.jsx
│   │   │   └── Settings.jsx
│   │   ├── App.jsx
│   │   └── index.html
│   └── shared/
│       └── constants.js     # Shared constants
├── appsscript.json          # Apps Script manifest
├── .clasp.json.example      # Clasp configuration template
├── package.json             # Node dependencies
├── webpack.config.js        # Webpack configuration
└── README.md                # This file
```

## Development

### Local Development Workflow

1. Make changes to files in `src/`
2. Push to Apps Script:
   ```bash
   npm run push
   ```
3. Refresh your Google Sheet to test changes
4. View logs in Apps Script Editor (Ctrl+Enter or View > Logs)

### Debugging

#### View Logs

1. Open Apps Script Editor: `clasp open`
2. Go to **View** > **Logs** or **Executions**
3. View real-time execution logs and errors

#### Enable Stackdriver Logging

Logs are automatically sent to Stackdriver (configured in `appsscript.json`).

View logs at: [Google Cloud Logging](https://console.cloud.google.com/logs)

#### Common Issues

**Issue**: "Authorization required"
- Solution: Run any function from Apps Script Editor to trigger OAuth flow

**Issue**: "Webhook URL not configured"
- Solution: Set webhook URL in Settings panel

**Issue**: "No columns found"
- Solution: Add headers to row 1 of your sheet

**Issue**: Changes not triggering webhook
- Solution: Ensure edited column is in trigger columns list

## Testing

### Manual Testing Checklist

- [ ] Install add-on and open menu
- [ ] Configure webhook URL in Settings
- [ ] Test webhook connection
- [ ] Add headers to sheet (including "phoneNumber")
- [ ] Configure "phoneNumber" as trigger column
- [ ] Edit a cell in the "phoneNumber" column
- [ ] Wait 5 seconds (debounce period)
- [ ] Check Status sidebar for success
- [ ] Verify webhook endpoint received payload
- [ ] Add a new row with data
- [ ] Verify INSERT operation sent to webhook
- [ ] Test error handling (use invalid webhook URL)
- [ ] Verify errors appear in sidebar
- [ ] Clear error history

### Mock Webhook for Testing

Use [Webhook.site](https://webhook.site/) or [RequestBin](https://requestbin.com/) to create a temporary webhook endpoint for testing.

1. Go to webhook.site
2. Copy your unique URL
3. Paste into Settings > Webhook URL
4. Make changes to your sheet
5. View incoming requests on webhook.site

## Security & Best Practices

### Security Features

- ✅ Input sanitization (HTML tags removed)
- ✅ Data validation before sending
- ✅ OAuth with minimal required scopes
- ✅ No sensitive data in logs
- ✅ Rate limit handling with retries
- ✅ Secure credential storage via Script Properties

### Best Practices

1. **Use HTTPS endpoints only** for webhooks
2. **Implement authentication** on your webhook endpoint
3. **Validate payloads** on the receiving end
4. **Monitor error logs** regularly
5. **Test with mock data** before production use
6. **Set appropriate debounce delays** for your use case
7. **Limit trigger columns** to essential fields only

## Performance Optimization

- ✅ **Debouncing**: Groups rapid edits within 5-second window
- ✅ **Efficient Reads**: Minimizes API calls to Google Sheets
- ✅ **Non-blocking**: Webhook failures don't block sheet operations
- ✅ **Caching**: Column headers cached during operations
- ✅ **Smart Triggers**: Only monitored columns trigger webhooks

## Troubleshooting

### Logs Not Showing Up

Check Apps Script executions:
```bash
clasp open
```
Then go to **View** > **Executions**

### Webhook Not Receiving Data

1. Verify webhook URL is correct and accessible
2. Check if endpoint accepts POST requests
3. Test connection using "Test Webhook" feature
4. Check error history in Status sidebar
5. Verify trigger columns are configured

### Permission Errors

Re-authorize the add-on:
1. Open Apps Script Editor
2. Run any function manually
3. Follow OAuth authorization prompts
4. Grant required permissions

### Deployment Issues

If clasp push fails:
```bash
clasp logout
clasp login
clasp push
```

## Advanced Configuration

### Custom Retry Logic

Edit `src/server/config.js`:

```javascript
const DEFAULT_CONFIG = {
  retryAttempts: 5,  // Increase retry attempts
  retryDelays: [1000, 2000, 4000, 8000, 16000],  // Custom delays
};
```

### Custom Debounce Delay

Change via Settings UI or edit `src/server/config.js`:

```javascript
const DEFAULT_CONFIG = {
  debounceDelay: 10000,  // 10 seconds
};
```

### Periodic Cleanup

Add a time-based trigger to clean up old markers:

1. Open Apps Script Editor
2. Go to **Triggers** (clock icon)
3. Click **Add Trigger**
4. Function: `cleanupProcessedMarkers`
5. Event source: Time-driven
6. Type: Day timer
7. Time: Select preferred time

## API Reference

### Server-Side Functions (Apps Script)

#### `getStatus()`
Returns current status, last sync info, and error history.

#### `getConfiguration()`
Returns current configuration.

#### `saveConfiguration(config)`
Saves configuration to Script Properties.

#### `testWebhookConnection()`
Tests webhook URL with sample payload.

#### `getAvailableColumns()`
Returns column headers from active sheet.

#### `clearErrorHistoryFromSidebar()`
Clears stored error history.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - feel free to use and modify for your needs.

## Support

For issues, questions, or contributions:
- GitHub Issues: [Create an issue](https://github.com/Abhishek-5795/add-on/issues)
- Documentation: This README

## Changelog

### Version 1.0.0 (2025-12-29)
- Initial release
- Core webhook functionality
- React-based UI
- Debouncing and retry logic
- Error handling and logging
- Developer configuration panel

## Acknowledgments

- Built with Google Apps Script
- UI powered by React
- Follows Google Workspace Add-on best practices