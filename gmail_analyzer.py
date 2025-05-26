import os
import pickle
import base64
import re
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import json
from datetime import datetime

# Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class EmailAnalyzer:
    def __init__(self):
        self.service = None
        self.authenticate()
    
    def authenticate(self):
        """Handle Gmail API authentication"""
        creds = None
        
        # The file token.json stores the user's access and refresh tokens
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        
        # If there are no (valid) credentials available, let the user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        
        self.service = build('gmail', 'v1', credentials=creds)
        print("✅ Successfully authenticated with Gmail!")
    
    def get_message_content(self, message_id):
        """Extract content from a Gmail message"""
        try:
            message = self.service.users().messages().get(
                userId='me', id=message_id, format='full').execute()
            
            # Extract basic info
            headers = message['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
            
            # Extract body
            body = self.extract_body(message['payload'])
            
            return {
                'id': message_id,
                'subject': subject,
                'sender': sender,
                'date': date,
                'body': body,
                'snippet': message.get('snippet', '')
            }
        except Exception as e:
            print(f"Error getting message {message_id}: {str(e)}")
            return None
    
    def extract_body(self, payload):
        """Extract body text from email payload"""
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
                elif part['mimeType'] == 'text/html':
                    data = part['body']['data']
                    html_body = base64.urlsafe_b64decode(data).decode('utf-8')
                    # Simple HTML to text conversion
                    body = re.sub('<[^<]+?>', '', html_body)
                    break
        else:
            if payload['mimeType'] == 'text/plain':
                data = payload['body']['data']
                body = base64.urlsafe_b64decode(data).decode('utf-8')
            elif payload['mimeType'] == 'text/html':
                data = payload['body']['data']
                html_body = base64.urlsafe_b64decode(data).decode('utf-8')
                body = re.sub('<[^<]+?>', '', html_body)
        
        return body.strip()
    
    def fetch_emails(self, max_emails=5, unread_only=True):
        """Fetch emails from Gmail"""
        try:
            # Build query
            query = 'is:unread' if unread_only else ''
            
            # Get list of messages
            results = self.service.users().messages().list(
                userId='me', q=query, maxResults=max_emails).execute()
            
            messages = results.get('messages', [])
            
            if not messages:
                print("No emails found.")
                return []
            
            print(f"📧 Found {len(messages)} emails. Fetching details...")
            
            emails = []
            for msg in messages:
                email_data = self.get_message_content(msg['id'])
                if email_data:
                    emails.append(email_data)
            
            return emails
            
        except Exception as e:
            print(f"❌ Error fetching emails: {str(e)}")
            return []
    
    def analyze_emails(self, emails):
        """Analyze and display email information"""
        if not emails:
            print("No emails to analyze.")
            return
        
        print(f"\n📊 ANALYZING {len(emails)} EMAILS")
        print("=" * 50)
        
        for i, email in enumerate(emails, 1):
            print(f"\n📧 EMAIL {i}")
            print(f"Subject: {email['subject']}")
            print(f"From: {email['sender']}")
            print(f"Date: {email['date']}")
            print(f"Snippet: {email['snippet'][:100]}...")
            
            # Basic analysis
            body_length = len(email['body'])
            word_count = len(email['body'].split())
            
            print(f"Body Length: {body_length} characters")
            print(f"Word Count: {word_count} words")
            print("-" * 30)

def main():
    """Main function to run the email analyzer"""
    try:
        print("🚀 Starting Gmail Email Analyzer...")
        
        # Create analyzer instance
        analyzer = EmailAnalyzer()
        
        # Fetch emails
        emails = analyzer.fetch_emails(max_emails=10, unread_only=True)
        
        # Analyze emails
        analyzer.analyze_emails(emails)
        
        print("\n✅ Analysis complete!")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        print("Make sure you have:")
        print("1. credentials.json file in the same directory")
        print("2. Proper internet connection")
        print("3. Gmail API enabled in Google Cloud Console")

if __name__ == "__main__":
    main()