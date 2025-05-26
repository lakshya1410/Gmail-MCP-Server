# Gmail MCP Server 📧

A Model Context Protocol (MCP) server that connects to Gmail API to fetch, analyze, and categorize emails automatically. This server helps you quickly identify important emails, ignore routine messages, and spot deletable promotional content.

## Features ✨

- **Gmail Integration**: Secure OAuth2 authentication with Gmail API
- **Smart Email Analysis**: Automatically categorizes emails into:
  - 🔴 **Important**: Urgent emails requiring attention
  - 🟡 **Ignorable**: Regular emails that can wait
  - 🟢 **Deletable**: Promotional/spam emails safe to delete
- **Flexible Fetching**: Get unread emails or recent messages
- **MCP Compatible**: Works with Claude Desktop and other MCP clients

## Setup 🚀

### 1. Prerequisites
- Python 3.12+
- Google Cloud Console project with Gmail API enabled
- Gmail account

### 2. Google Cloud Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Gmail API
4. Create OAuth 2.0 credentials (Desktop Application)
5. Download the credentials as `credentials.json`

### 3. Installation
```bash
# Clone or download the server files
# Ensure credentials.json is in the project directory

# Install dependencies
pip install google>=3.0.0 google-api-python-client>=2.170.0 google-auth>=2.40.2 google-auth-oauthlib>=1.2.2 mcp>=1.9.1

# or with uv:
uv add google>=3.0.0 google-api-python-client>=2.170.0 google-auth>=2.40.2 google-auth-oauthlib>=1.2.2 mcp>=1.9.1
```

### 4. Test Authentication
```bash
python gmail_auth_test.py
```
This will open your browser for Gmail OAuth approval and save authentication tokens.

## Usage 💻

### Add to Claude Desktop

Add the following to your Claude Desktop configuration file:

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Mac**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "gmail-analyzer": {
      "command": "python",
      "args": ["path/to/your/main.py"],
      "env": {}
    }
  }
}
```

Replace `path/to/your/main.py` with the actual path to your server files.

### Standalone Testing
```bash
# Test the email analyzer directly
python gmail_analyzer.py

# Test authentication
python gmail_auth_test.py
```

### MCP Server
```bash
# Run the MCP server
python main.py
```

### Available Tools

#### `test_connection`
Test if the MCP server is working correctly.

#### `fetch_and_analyze_gmail`
Fetch emails from Gmail and analyze them automatically.
- `max_emails` (int): Maximum emails to fetch (default: 5)
- `unread_only` (bool): Only fetch unread emails (default: true)

#### `analyze_emails`
Analyze provided email content and categorize them.
- `emails` (array): List of email contents to analyze

## File Structure 📁

```
├── main.py                 # MCP server implementation
├── gmail_analyzer.py       # Standalone email analyzer
├── gmail_auth_test.py      # Authentication testing script
├── credentials.json        # Google OAuth credentials (you provide)
├── token.json             # Generated authentication tokens
├── pyproject.toml         # Project dependencies
└── README.md              # This file
```

## Email Categorization Logic 🧠

**Important Emails** contain keywords like:
- `urgent`, `asap`, `important`, `critical`, `deadline`
- `meeting`, `schedule`, `follow up`, `action required`
- `boss`, `manager`, `client`, `customer`

**Deletable Emails** contain keywords like:
- `unsubscribe`, `newsletter`, `promotion`, `deal`
- `sale`, `discount`, `marketing`, `advertisement`

**Ignorable Emails** are everything else that doesn't fall into the above categories.

## Security & Privacy 🔒

- Uses OAuth2 for secure Gmail authentication
- Only requests read-only access to Gmail (`gmail.readonly` scope)
- Credentials are stored locally in `token.json`
- No email content is stored permanently or sent to external services

## Troubleshooting 🔧

### Common Issues

**"Credentials file not found"**
- Ensure `credentials.json` is in the same directory as the Python files

**"Authentication failed"**
- Run `python gmail_auth_test.py` to reset authentication
- Check that Gmail API is enabled in Google Cloud Console

**"No emails found"**
- Try setting `unread_only: false` to fetch recent emails instead
- Check your Gmail account has emails

### Getting Help
1. Run the authentication test script first
2. Check the Google Cloud Console for API quotas and permissions
3. Ensure your OAuth consent screen is properly configured

## Dependencies 📦

- `google-api-python-client`: Gmail API client
- `google-auth`: Google authentication
- `google-auth-oauthlib`: OAuth2 flow
- `mcp`: Model Context Protocol framework

  Build by Lakshya Tripathi 
