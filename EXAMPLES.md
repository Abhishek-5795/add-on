# Example Usage & Test Data

This file provides example data and usage scenarios for testing the Google Sheets Webhook Add-on.

## Example Sheet Structure

### Headers (Row 1)
```
| Name | Email | phoneNumber | Status | Notes |
```

### Sample Data Rows
```
| John Doe | john@example.com | 555-1234 | Active | Sales lead |
| Jane Smith | jane@example.com | 555-5678 | Pending | Follow up needed |
| Bob Johnson | bob@example.com | 555-9012 | Active | VIP customer |
```

## Test Scenarios

### Scenario 1: Edit phoneNumber Column (UPDATE Operation)

**Steps:**
1. Create a sheet with the headers above
2. Configure "phoneNumber" as a trigger column in Settings
3. Edit the phoneNumber in row 2: change "555-1234" to "555-9999"
4. Wait 5 seconds (debounce period)
5. Check Status sidebar

**Expected Webhook Payload:**
```json
{
  "sheetName": "Sheet1",
  "user": "your-email@example.com",
  "operationType": "UPDATE",
  "timestamp": "2025-12-29T10:30:00.000Z",
  "rowNumber": 2,
  "data": {
    "Name": "John Doe",
    "Email": "john@example.com",
    "phoneNumber": "555-9999",
    "Status": "Active",
    "Notes": "Sales lead"
  }
}
```

### Scenario 2: Add New Row (INSERT Operation)

**Steps:**
1. Add a new row with data:
   - Name: "Alice Brown"
   - Email: "alice@example.com"
   - phoneNumber: "555-1111"
   - Status: "New"
   - Notes: "Referral"
2. Wait 5 seconds
3. Check Status sidebar

**Expected Webhook Payload:**
```json
{
  "sheetName": "Sheet1",
  "user": "your-email@example.com",
  "operationType": "INSERT",
  "timestamp": "2025-12-29T10:35:00.000Z",
  "rowNumber": 5,
  "data": {
    "Name": "Alice Brown",
    "Email": "alice@example.com",
    "phoneNumber": "555-1111",
    "Status": "New",
    "Notes": "Referral"
  }
}
```

### Scenario 3: Multiple Rapid Edits (Debouncing Test)

**Steps:**
1. Quickly edit phoneNumber in row 2: "555-2222"
2. Immediately edit phoneNumber in row 3: "555-3333"
3. Immediately edit phoneNumber in row 4: "555-4444"
4. Wait 5 seconds
5. Check Status sidebar

**Expected Behavior:**
- All three changes are grouped together
- Three separate webhook calls are made (one for each row)
- All sent after the 5-second debounce period
- No duplicate sends

### Scenario 4: Edit Non-Trigger Column (Should Not Trigger)

**Steps:**
1. Configure only "phoneNumber" as trigger column
2. Edit the "Status" column in any row
3. Wait 10 seconds
4. Check Status sidebar

**Expected Behavior:**
- No webhook call is made
- Status sidebar shows previous sync (if any)
- No new entries in error history

### Scenario 5: Error Handling Test

**Steps:**
1. Set webhook URL to an invalid endpoint: "https://invalid-endpoint-12345.com/webhook"
2. Edit a phoneNumber cell
3. Wait 5 seconds + time for retries (~10 seconds total)
4. Check Status sidebar

**Expected Behavior:**
- Webhook attempts fail
- 3 retry attempts with exponential backoff
- Error appears in Error History section
- Last Sync Status shows "Error"
- Sheet operations continue normally (non-blocking)

## Mock Webhook Endpoints for Testing

### Using Webhook.site
1. Go to https://webhook.site/
2. Copy your unique URL (e.g., `https://webhook.site/your-unique-id`)
3. Paste in Settings > Webhook URL
4. Make changes to your sheet
5. View incoming requests in real-time on webhook.site

### Using RequestBin
1. Go to https://requestbin.com/
2. Click "Create a RequestBin"
3. Copy the endpoint URL
4. Use in Settings > Webhook URL
5. View requests in the RequestBin interface

### Using Local Server (for Advanced Users)
```javascript
// Simple Node.js webhook receiver
const express = require('express');
const app = express();

app.use(express.json());

app.post('/webhook', (req, res) => {
  console.log('Received webhook:');
  console.log(JSON.stringify(req.body, null, 2));
  res.status(200).json({ success: true });
});

app.listen(3000, () => {
  console.log('Webhook receiver running on http://localhost:3000');
});
```

Then use ngrok to expose it:
```bash
ngrok http 3000
```

## Testing Checklist

- [ ] Install add-on successfully
- [ ] Menu items appear in Extensions menu
- [ ] Settings panel opens and loads configuration
- [ ] Webhook URL can be set and saved
- [ ] Test Connection button works
- [ ] Available columns load correctly
- [ ] Trigger columns can be selected/deselected
- [ ] Status sidebar opens and shows status
- [ ] Edit trigger column sends UPDATE webhook
- [ ] Payload includes all columns correctly
- [ ] Add new row sends INSERT webhook
- [ ] Debouncing works (multiple rapid edits grouped)
- [ ] Edit non-trigger column doesn't send webhook
- [ ] Invalid webhook URL shows errors
- [ ] Retry logic executes (check logs)
- [ ] Error history displays errors
- [ ] Clear error history works
- [ ] Status sidebar auto-refreshes
- [ ] Configuration persists after page refresh

## Expected Performance

- **Debounce Delay**: 5 seconds default
- **First Retry**: 1 second after initial failure
- **Second Retry**: 2 seconds after first retry
- **Third Retry**: 4 seconds after second retry
- **Total Time for Failed Request**: ~7 seconds (3 attempts + delays)
- **Status Refresh**: Every 10 seconds in sidebar

## Common Test Data Issues

### Issue: Webhook not triggered
**Possible Causes:**
- Column not configured as trigger column
- Header row missing or empty
- Webhook URL not set
- OAuth permissions not granted

### Issue: Wrong data in payload
**Possible Causes:**
- Header names have changed
- Extra spaces in headers
- Empty cells not handled as expected

### Issue: Multiple webhooks for single edit
**Possible Causes:**
- Debounce delay too short
- Multiple columns edited simultaneously
- Script execution overlapping

## Sample Webhook Response Handlers

### Python (Flask)
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    print(f"Received {data['operationType']} for row {data['rowNumber']}")
    print(f"Data: {data['data']}")
    return jsonify({'status': 'success'}), 200

if __name__ == '__main__':
    app.run(port=5000)
```

### Node.js (Express)
```javascript
const express = require('express');
const app = express();

app.use(express.json());

app.post('/webhook', (req, res) => {
  const { operationType, rowNumber, data } = req.body;
  console.log(`Received ${operationType} for row ${rowNumber}`);
  console.log('Data:', data);
  res.json({ status: 'success' });
});

app.listen(5000);
```

## Advanced Testing

### Load Testing
1. Create a sheet with 100+ rows
2. Use a script to rapidly edit multiple cells
3. Monitor performance and error rates
4. Verify all changes are captured

### Concurrent Edit Testing
1. Have multiple users edit the same sheet
2. Verify all changes trigger webhooks
3. Check for race conditions
4. Verify debouncing works correctly

### Network Failure Testing
1. Temporarily disable network
2. Make edits to sheet
3. Re-enable network
4. Verify error handling and recovery

## Debugging Tips

1. **Enable Detailed Logging**: Open Apps Script Editor and view Execution log
2. **Check Script Properties**: Apps Script Editor > File > Project properties > Script properties
3. **View Trigger History**: Apps Script Editor > Triggers (clock icon)
4. **Monitor API Usage**: Google Cloud Console > APIs & Services > Dashboard
5. **Test Individual Functions**: Apps Script Editor > Select function > Run

## Support Resources

- **Documentation**: README.md
- **Issue Tracker**: GitHub Issues
- **Apps Script Docs**: https://developers.google.com/apps-script
- **Sheets API Docs**: https://developers.google.com/sheets/api
