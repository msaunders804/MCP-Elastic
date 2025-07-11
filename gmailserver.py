#!/usr/bin/env python3
"""
Gmail-to-Tasks MCP Server
Extracts tasks from Gmail emails and creates them in Google Tasks
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence
import re

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio


# Required OAuth scopes
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/tasks'
]

# File to store OAuth credentials
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'credentials.json'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GmailTaskExtractor:
    """Handles Gmail authentication and task extraction"""
    
    def __init__(self):
        self.gmail_service = None
        self.tasks_service = None
        self.creds = None
        
    async def authenticate(self):
        """Handle Google OAuth authentication"""
        self.creds = None
        
        # Load existing token
        if os.path.exists(TOKEN_FILE):
            self.creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        
        # If no valid credentials, request authorization
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    CREDENTIALS_FILE, SCOPES)
                self.creds = flow.run_local_server(port=0)
            
            # Save credentials for next run
            with open(TOKEN_FILE, 'w') as token:
                token.write(self.creds.to_json())
        
        # Build service objects
        self.gmail_service = build('gmail', 'v1', credentials=self.creds)
        self.tasks_service = build('tasks', 'v1', credentials=self.creds)
        
        logger.info("Successfully authenticated with Google services")
    
    async def search_emails(self, query: str, max_results: int = 10) -> List[Dict]:
        """Search Gmail messages based on query"""
        try:
            result = self.gmail_service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            email_data = []
            
            for message in messages:
                msg = self.gmail_service.users().messages().get(
                    userId='me',
                    id=message['id']
                ).execute()
                
                email_data.append(self._parse_email(msg))
            
            return email_data
            
        except HttpError as error:
            logger.error(f"Gmail API error: {error}")
            return []
    
    def _parse_email(self, message: Dict) -> Dict:
        """Parse Gmail message into structured data"""
        headers = message['payload'].get('headers', [])
        header_dict = {h['name']: h['value'] for h in headers}
        
        # Extract body text
        body = self._extract_body(message['payload'])
        
        return {
            'id': message['id'],
            'subject': header_dict.get('Subject', ''),
            'from': header_dict.get('From', ''),
            'date': header_dict.get('Date', ''),
            'body': body,
            'snippet': message.get('snippet', '')
        }
    
    def _extract_body(self, payload: Dict) -> str:
        """Extract text body from email payload"""
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
        elif payload['mimeType'] == 'text/plain':
            data = payload['body']['data']
            body = base64.urlsafe_b64decode(data).decode('utf-8')
        
        return body
    
    def extract_tasks_from_text(self, text: str, subject: str = "") -> List[Dict]:
        """Extract potential tasks from email text using pattern matching"""
        tasks = []
        
        # Common task patterns
        patterns = [
            r'(?i)(?:please|can you|could you|need to|remember to|don\'t forget to|action item:?)\s*(.+?)(?:\.|$|\n)',
            r'(?i)(?:to do|todo|task):?\s*(.+?)(?:\.|$|\n)',
            r'(?i)(?:follow up|follow-up)\s*(?:on|with)?\s*(.+?)(?:\.|$|\n)',
            r'(?i)(?:deadline|due)\s*(?:by|on)?\s*(.+?)(?:\.|$|\n)',
            r'(?i)(?:schedule|book|arrange)\s*(.+?)(?:\.|$|\n)',
            r'(?i)(?:review|check|verify|confirm)\s*(.+?)(?:\.|$|\n)',
            r'(?i)(?:send|email|call|contact)\s*(.+?)(?:\.|$|\n)',
            r'(?i)(?:prepare|create|draft|write)\s*(.+?)(?:\.|$|\n)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.MULTILINE)
            for match in matches:
                task_text = match.strip()
                if len(task_text) > 5 and len(task_text) < 200:  # Reasonable task length
                    tasks.append({
                        'title': task_text,
                        'source': 'email_body',
                        'context': f"From email: {subject}"
                    })
        
        # Also check for numbered lists or bullet points
        list_patterns = [
            r'(?i)^\s*[-*•]\s*(.+?)$',  # Bullet points
            r'(?i)^\s*\d+\.\s*(.+?)$'   # Numbered lists
        ]
        
        for pattern in list_patterns:
            matches = re.findall(pattern, text, re.MULTILINE)
            for match in matches:
                task_text = match.strip()
                if len(task_text) > 5 and len(task_text) < 200:
                    tasks.append({
                        'title': task_text,
                        'source': 'email_list',
                        'context': f"From email: {subject}"
                    })
        
        return tasks
    
    def extract_due_dates(self, text: str) -> Optional[str]:
        """Extract potential due dates from text"""
        date_patterns = [
            r'(?i)(?:by|due|deadline)\s*(?:on|by)?\s*(\w+\s+\d{1,2}(?:st|nd|rd|th)?)',
            r'(?i)(?:by|due|deadline)\s*(?:on|by)?\s*(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
            r'(?i)(?:by|due|deadline)\s*(?:on|by)?\s*(tomorrow|today|next week|this week)',
            r'(?i)(?:by|due|deadline)\s*(?:on|by)?\s*(monday|tuesday|wednesday|thursday|friday|saturday|sunday)'
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        
        return None
    
    async def create_task(self, title: str, notes: str = "", due_date: str = "") -> Dict:
        """Create a task in Google Tasks"""
        try:
            task = {
                'title': title,
                'notes': notes
            }
            
            if due_date:
                # Parse due date (simplified - you might want more robust parsing)
                task['due'] = due_date
            
            result = self.tasks_service.tasks().insert(
                tasklist='@default',
                body=task
            ).execute()
            
            return {
                'id': result['id'],
                'title': result['title'],
                'status': 'created'
            }
            
        except HttpError as error:
            logger.error(f"Tasks API error: {error}")
            return {'error': str(error)}


# Initialize the extractor
extractor = GmailTaskExtractor()

# Create MCP server
server = Server("gmail-tasks-mcp")

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """List available MCP tools"""
    return [
        types.Tool(
            name="search_emails_for_tasks",
            description="Search Gmail for emails and extract potential tasks",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Gmail search query (e.g., 'is:unread', 'from:boss@company.com', 'subject:project')"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of emails to search (default: 10)",
                        "default": 10
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="extract_tasks_from_email",
            description="Extract tasks from a specific email ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "email_id": {
                        "type": "string",
                        "description": "Gmail message ID"
                    }
                },
                "required": ["email_id"]
            }
        ),
        types.Tool(
            name="create_task_from_email",
            description="Create a Google Task from email content",
            inputSchema={
                "type": "object",
                "properties": {
                    "email_id": {
                        "type": "string",
                        "description": "Gmail message ID"
                    },
                    "task_title": {
                        "type": "string",
                        "description": "Custom task title (optional - will extract from email if not provided)"
                    },
                    "auto_extract": {
                        "type": "boolean",
                        "description": "Automatically extract multiple tasks from email content",
                        "default": False
                    }
                },
                "required": ["email_id"]
            }
        ),
        types.Tool(
            name="bulk_extract_tasks",
            description="Extract tasks from multiple emails matching a search query",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Gmail search query"
                    },
                    "max_emails": {
                        "type": "integer",
                        "description": "Maximum emails to process",
                        "default": 5
                    },
                    "create_tasks": {
                        "type": "boolean",
                        "description": "Automatically create tasks in Google Tasks",
                        "default": False
                    }
                },
                "required": ["query"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> List[types.TextContent]:
    """Handle tool calls"""
    try:
        # Ensure authentication
        if not extractor.gmail_service:
            await extractor.authenticate()
        
        if name == "search_emails_for_tasks":
            query = arguments.get("query", "")
            max_results = arguments.get("max_results", 10)
            
            emails = await extractor.search_emails(query, max_results)
            
            # Extract tasks from each email
            all_tasks = []
            for email in emails:
                tasks = extractor.extract_tasks_from_text(
                    email['body'] + " " + email['snippet'],
                    email['subject']
                )
                
                for task in tasks:
                    task['email_id'] = email['id']
                    task['email_subject'] = email['subject']
                    task['email_from'] = email['from']
                    all_tasks.append(task)
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "found_emails": len(emails),
                    "extracted_tasks": len(all_tasks),
                    "tasks": all_tasks
                }, indent=2)
            )]
        
        elif name == "extract_tasks_from_email":
            email_id = arguments.get("email_id", "")
            
            # Get specific email
            msg = extractor.gmail_service.users().messages().get(
                userId='me',
                id=email_id
            ).execute()
            
            email_data = extractor._parse_email(msg)
            tasks = extractor.extract_tasks_from_text(
                email_data['body'] + " " + email_data['snippet'],
                email_data['subject']
            )
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "email_subject": email_data['subject'],
                    "email_from": email_data['from'],
                    "extracted_tasks": tasks
                }, indent=2)
            )]
        
        elif name == "create_task_from_email":
            email_id = arguments.get("email_id", "")
            task_title = arguments.get("task_title", "")
            auto_extract = arguments.get("auto_extract", False)
            
            # Get email content
            msg = extractor.gmail_service.users().messages().get(
                userId='me',
                id=email_id
            ).execute()
            
            email_data = extractor._parse_email(msg)
            
            created_tasks = []
            
            if auto_extract:
                # Extract multiple tasks from email
                tasks = extractor.extract_tasks_from_text(
                    email_data['body'] + " " + email_data['snippet'],
                    email_data['subject']
                )
                
                for task in tasks:
                    due_date = extractor.extract_due_dates(email_data['body'])
                    notes = f"From email: {email_data['subject']}\nSender: {email_data['from']}"
                    
                    result = await extractor.create_task(
                        task['title'],
                        notes,
                        due_date
                    )
                    created_tasks.append(result)
            else:
                # Create single task
                title = task_title or f"Follow up on: {email_data['subject']}"
                notes = f"From email: {email_data['subject']}\nSender: {email_data['from']}\n\n{email_data['snippet']}"
                due_date = extractor.extract_due_dates(email_data['body'])
                
                result = await extractor.create_task(title, notes, due_date)
                created_tasks.append(result)
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "email_subject": email_data['subject'],
                    "created_tasks": created_tasks
                }, indent=2)
            )]
        
        elif name == "bulk_extract_tasks":
            query = arguments.get("query", "")
            max_emails = arguments.get("max_emails", 5)
            create_tasks = arguments.get("create_tasks", False)
            
            emails = await extractor.search_emails(query, max_emails)
            
            all_tasks = []
            created_tasks = []
            
            for email in emails:
                tasks = extractor.extract_tasks_from_text(
                    email['body'] + " " + email['snippet'],
                    email['subject']
                )
                
                for task in tasks:
                    task['email_id'] = email['id']
                    task['email_subject'] = email['subject']
                    all_tasks.append(task)
                    
                    if create_tasks:
                        due_date = extractor.extract_due_dates(email['body'])
                        notes = f"From email: {email['subject']}\nSender: {email['from']}"
                        
                        result = await extractor.create_task(
                            task['title'],
                            notes,
                            due_date
                        )
                        created_tasks.append(result)
            
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "processed_emails": len(emails),
                    "extracted_tasks": len(all_tasks),
                    "created_tasks": len(created_tasks),
                    "tasks": all_tasks,
                    "created_task_results": created_tasks
                }, indent=2)
            )]
        
        else:
            return [types.TextContent(
                type="text",
                text=f"Unknown tool: {name}"
            )]
    
    except Exception as e:
        logger.error(f"Error in {name}: {str(e)}")
        return [types.TextContent(
            type="text",
            text=f"Error: {str(e)}"
        )]


async def main():
    """Main server entry point"""
    # Initialize server options
    options = InitializationOptions(
        server_name="gmail-tasks-mcp",
        server_version="1.0.0",
        capabilities=types.ServerCapabilities(
            tools={}
        )
    )
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            options
        )


if __name__ == "__main__":
    import os
    import base64
    
    asyncio.run(main())
