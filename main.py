import asyncio
import os
import json
import base64
import re
import sys
from typing import Any, Sequence

# MCP imports
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Google API imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class GmailManager:
    def __init__(self):
        self.service = None
        # Use absolute paths
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.credentials_path = os.path.join(current_dir, "credentials.json")
        self.token_path = os.path.join(current_dir, "token.json")
        self.authenticated = False
    
    def authenticate(self):
        """Authenticate with Gmail API"""
        try:
            creds = None
            
            # Check if token.json exists (stored credentials)
            if os.path.exists(self.token_path):
                try:
                    creds = Credentials.from_authorized_user_file(self.token_path, SCOPES)
                except Exception as e:
                    # If token file is corrupted, delete it
                    os.remove(self.token_path)
                    creds = None
            
            # If no valid credentials, run OAuth flow
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    try:
                        creds.refresh(Request())
                    except Exception as refresh_error:
                        # Token refresh failed, need to re-authenticate
                        if os.path.exists(self.token_path):
                            os.remove(self.token_path)
                        creds = None
                
                if not creds:
                    if not os.path.exists(self.credentials_path):
                        raise FileNotFoundError(f"credentials.json not found at {self.credentials_path}")
                    
                    flow = InstalledAppFlow.from_client_secrets_file(self.credentials_path, SCOPES)
                    creds = flow.run_local_server(port=0)
                
                # Save credentials for next run
                with open(self.token_path, 'w') as token:
                    token.write(creds.to_json())
            
            self.service = build('gmail', 'v1', credentials=creds)
            self.authenticated = True
            return True
            
        except Exception as e:
            raise Exception(f"Gmail authentication failed: {str(e)}")
    
    def get_emails(self, max_results: int = 10, label_ids: list = None, query: str = None):
        """Fetch emails from Gmail"""
        try:
            if not self.authenticated:
                self.authenticate()
            
            # Build query parameters
            request_params = {
                'userId': 'me',
                'maxResults': max_results
            }
            
            if label_ids:
                request_params['labelIds'] = label_ids
            if query:
                request_params['q'] = query
            
            # Get list of emails
            results = self.service.users().messages().list(**request_params).execute()
            messages = results.get('messages', [])
            
            if not messages:
                return []
            
            emails = []
            for message in messages:
                try:
                    # Get full message details
                    msg = self.service.users().messages().get(
                        userId='me', 
                        id=message['id'],
                        format='full'
                    ).execute()
                    
                    email_data = self._parse_email(msg)
                    emails.append(email_data)
                except Exception as e:
                    # Skip this email if there's an error
                    continue
            
            return emails
            
        except HttpError as error:
            raise Exception(f'Gmail API error: {error}')
        except Exception as e:
            raise Exception(f'Error fetching emails: {str(e)}')
    
    def _parse_email(self, message):
        """Parse Gmail message into readable format"""
        headers = message['payload'].get('headers', [])
        
        # Extract headers
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), '')
        
        # Extract body
        body = self._extract_body(message['payload'])
        
        return {
            'id': message['id'],
            'subject': subject,
            'sender': sender,
            'date': date,
            'body': body,
            'content': f"{subject}\n{body}"  # Combined for analysis
        }
    
    def _extract_body(self, payload):
        """Extract email body from payload"""
        body = ""
        
        try:
            if 'parts' in payload:
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                        data = part['body']['data']
                        body = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')
                        break
                    elif part['mimeType'] == 'text/html' and 'data' in part['body']:
                        # If no plain text, use HTML (strip HTML tags)
                        data = part['body']['data']
                        html_body = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')
                        # Simple HTML tag removal
                        body = re.sub('<.*?>', '', html_body)
                        break
            else:
                if payload['body'].get('data'):
                    body = base64.urlsafe_b64decode(
                        payload['body']['data'].encode('ASCII')
                    ).decode('utf-8')
        except Exception as e:
            body = f"Error extracting body: {str(e)}"
        
        return body.strip()

# Initialize Gmail manager
gmail_manager = GmailManager()

def categorize_email(content: str) -> str:
    """
    Categorize email based on content
    """
    content = content.lower()
    
    # Important keywords
    important_keywords = [
        "urgent", "asap", "important", "critical", "deadline", 
        "meeting", "schedule", "follow up", "action required",
        "boss", "manager", "client", "customer"
    ]
    
    # Deletable keywords (promotions, newsletters)
    deletable_keywords = [
        "unsubscribe", "newsletter", "promotion", "deal", "offer",
        "sale", "discount", "marketing", "advertisement", "spam"
    ]
    
    if any(keyword in content for keyword in important_keywords):
        return "important"
    elif any(keyword in content for keyword in deletable_keywords):
        return "deletable"
    else:
        return "ignorable"

# Create the server
server = Server("EmailAnalyzer")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools"""
    return [
        types.Tool(
            name="test_connection",
            description="Test if the MCP server is working",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        types.Tool(
            name="fetch_and_analyze_gmail",
            description="Fetch emails from Gmail and analyze them automatically",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_emails": {
                        "type": "integer",
                        "description": "Maximum number of emails to fetch",
                        "default": 5
                    },
                    "unread_only": {
                        "type": "boolean",
                        "description": "Only fetch unread emails",
                        "default": True
                    }
                },
                "required": []
            }
        ),
        types.Tool(
            name="analyze_emails",
            description="Analyze provided email content and categorize them",
            inputSchema={
                "type": "object",
                "properties": {
                    "emails": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of email contents to analyze"
                    }
                },
                "required": ["emails"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent]:
    """Handle tool execution"""
    if arguments is None:
        arguments = {}
    
    try:
        if name == "test_connection":
            return [types.TextContent(
                type="text", 
                text="✅ MCP Server is working correctly! Gmail API connection will be tested when fetching emails."
            )]
        
        elif name == "analyze_emails":
            emails = arguments.get("emails", [])
            if not emails:
                return [types.TextContent(
                    type="text",
                    text="No emails provided for analysis."
                )]
            
            categorized = {
                "important": [],
                "ignorable": [],
                "deletable": []
            }

            for email in emails:
                category = categorize_email(email)
                categorized[category].append({
                    "content": email[:200] + "..." if len(email) > 200 else email,
                    "category": category
                })

            result = {
                "status": "success",
                "total_emails": len(emails),
                "categorized": categorized,
                "summary": {
                    "important": len(categorized["important"]),
                    "ignorable": len(categorized["ignorable"]),
                    "deletable": len(categorized["deletable"])
                }
            }
            
            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "fetch_and_analyze_gmail":
            max_emails = arguments.get("max_emails", 5)
            unread_only = arguments.get("unread_only", True)
            
            try:
                # Test authentication first
                if not gmail_manager.authenticated:
                    gmail_manager.authenticate()
                
                # Build query
                query = "is:unread" if unread_only else None
                
                # Fetch emails from Gmail
                emails_data = gmail_manager.get_emails(
                    max_results=max_emails,
                    query=query
                )
                
                if not emails_data:
                    result = {
                        "status": "success",
                        "message": "No emails found matching your criteria",
                        "total_emails": 0,
                        "categorized": {"important": [], "ignorable": [], "deletable": []},
                        "summary": {"important": 0, "ignorable": 0, "deletable": 0}
                    }
                    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
                
                # Categorize emails
                categorized = {
                    "important": [],
                    "ignorable": [],
                    "deletable": []
                }
                
                for email_data in emails_data:
                    category = categorize_email(email_data['content'])
                    
                    email_summary = {
                        "subject": email_data['subject'],
                        "sender": email_data['sender'],
                        "date": email_data['date'],
                        "category": category,
                        "preview": email_data['body'][:150] + "..." if len(email_data['body']) > 150 else email_data['body']
                    }
                    
                    categorized[category].append(email_summary)
                
                result = {
                    "status": "success",
                    "total_emails": len(emails_data),
                    "categorized": categorized,
                    "summary": {
                        "important": len(categorized["important"]),
                        "ignorable": len(categorized["ignorable"]),
                        "deletable": len(categorized["deletable"])
                    }
                }
                
                return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
                
            except FileNotFoundError as e:
                result = {
                    "status": "error",
                    "error": "Credentials file not found",
                    "message": "Please ensure credentials.json is in the same directory as this script",
                    "details": str(e)
                }
                return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
                
            except Exception as e:
                result = {
                    "status": "error",
                    "error": "Gmail API Error",
                    "message": str(e),
                    "suggestion": "Try running the authentication flow manually or check your credentials"
                }
                return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
        
        else:
            return [types.TextContent(
                type="text",
                text=f"Unknown tool: {name}"
            )]
    
    except Exception as e:
        return [types.TextContent(
            type="text",
            text=f"Error executing tool {name}: {str(e)}"
        )]

async def main():
    """Run the MCP server"""
    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="EmailAnalyzer",
                    server_version="0.1.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())