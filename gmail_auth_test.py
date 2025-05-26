#!/usr/bin/env python3
"""
Test script to verify Gmail API authentication and basic functionality
Run this before testing the MCP server
"""

import os
import json
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def test_authentication():
    """Test Gmail API authentication"""
    print("🔐 Testing Gmail API Authentication...")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    credentials_path = os.path.join(current_dir, "credentials.json")
    token_path = os.path.join(current_dir, "token.json")
    
    # Check if credentials.json exists
    if not os.path.exists(credentials_path):
        print(f"❌ credentials.json not found at: {credentials_path}")
        print("Please download it from Google Cloud Console")
        return False
    
    print(f"✅ Found credentials.json at: {credentials_path}")
    
    try:
        creds = None
        
        # Check existing token
        if os.path.exists(token_path):
            print(f"📄 Found existing token.json")
            try:
                creds = Credentials.from_authorized_user_file(token_path, SCOPES)
                print("✅ Successfully loaded existing credentials")
            except Exception as e:
                print(f"⚠️  Error loading token: {e}")
                print("🗑️  Removing invalid token file...")
                os.remove(token_path)
                creds = None
        
        # Authenticate if needed
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                print("🔄 Refreshing expired token...")
                try:
                    creds.refresh(Request())
                    print("✅ Token refreshed successfully")
                except Exception as e:
                    print(f"❌ Token refresh failed: {e}")
                    print("🔄 Starting new authentication flow...")
                    os.remove(token_path)
                    creds = None
            
            if not creds:
                print("🌐 Starting OAuth flow...")
                flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
                creds = flow.run_local_server(port=0)
                print("✅ OAuth completed successfully")
            
            # Save new credentials
            print("💾 Saving credentials...")
            with open(token_path, 'w') as token:
                token.write(creds.to_json())
            print(f"✅ Credentials saved to: {token_path}")
        
        # Test API connection
        print("🔌 Testing Gmail API connection...")
        service = build('gmail', 'v1', credentials=creds)
        
        # Get user profile
        profile = service.users().getProfile(userId='me').execute()
        print(f"✅ Connected to Gmail account: {profile['emailAddress']}")
        print(f"📧 Total messages: {profile['messagesTotal']}")
        
        return True, service
        
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        return False, None

def test_fetch_emails(service, max_emails=3):
    """Test fetching emails"""
    print(f"\n📬 Testing email fetch (max {max_emails} emails)...")
    
    try:
        # Get unread emails
        results = service.users().messages().list(
            userId='me', 
            q='is:unread',
            maxResults=max_emails
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            print("📭 No unread emails found")
            
            # Try getting any recent emails
            print("🔍 Trying to fetch recent emails instead...")
            results = service.users().messages().list(
                userId='me',
                maxResults=max_emails
            ).execute()
            messages = results.get('messages', [])
        
        if not messages:
            print("📭 No emails found at all")
            return True
        
        print(f"✅ Found {len(messages)} emails")
        
        # Get details for first email
        if messages:
            print("\n📧 Testing email parsing...")
            msg = service.users().messages().get(
                userId='me',
                id=messages[0]['id'],
                format='full'
            ).execute()
            
            headers = msg['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            
            print(f"✅ Sample email parsed:")
            print(f"   Subject: {subject[:50]}...")
            print(f"   From: {sender[:50]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Email fetch failed: {e}")
        return False

def main():
    """Main test function"""
    print("=" * 60)
    print("🧪 GMAIL API AUTHENTICATION TEST")
    print("=" * 60)
    
    # Test authentication
    auth_success, service = test_authentication()
    
    if not auth_success:
        print("\n❌ Authentication test failed")
        print("\nNext steps:")
        print("1. Make sure credentials.json is in the same directory")
        print("2. Check your Google Cloud Console project settings")
        print("3. Ensure Gmail API is enabled")
        return
    
    # Test email fetching
    fetch_success = test_fetch_emails(service)
    
    print("\n" + "=" * 60)
    if auth_success and fetch_success:
        print("🎉 ALL TESTS PASSED!")
        print("Your Gmail API setup is working correctly.")
        print("You can now test your MCP server.")
    else:
        print("⚠️  SOME TESTS FAILED")
        print("Please fix the issues above before using the MCP server.")
    print("=" * 60)

if __name__ == "__main__":
    main()