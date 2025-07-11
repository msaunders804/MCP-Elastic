#!/usr/bin/env python3
"""
Simple MCP Client for Gmail Tasks
"""

import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class GmailTasksClient:
    def __init__(self, server_path: str):
        self.server_path = server_path
        self.session = None
    
    async def connect(self):
        """Connect to the MCP server"""
        server_params = StdioServerParameters(
            command="python",
            args=[self.server_path]
        )
        
        self.session = await stdio_client(server_params)
        print("Connected to Gmail Tasks MCP Server")
    
    async def list_tools(self):
        """List available tools"""
        tools = await self.session.list_tools()
        print("Available tools:")
        for tool in tools.tools:
            print(f"  - {tool.name}: {tool.description}")
        return tools
    
    async def search_emails_for_tasks(self, query: str, max_results: int = 10):
        """Search emails and extract tasks"""
        result = await self.session.call_tool(
            "search_emails_for_tasks",
            {
                "query": query,
                "max_results": max_results
            }
        )
        return json.loads(result.content[0].text)
    
    async def extract_tasks_from_email(self, email_id: str):
        """Extract tasks from specific email"""
        result = await self.session.call_tool(
            "extract_tasks_from_email",
            {"email_id": email_id}
        )
        return json.loads(result.content[0].text)
    
    async def create_task_from_email(self, email_id: str, task_title: str = "", auto_extract: bool = False):
        """Create Google Tasks from email"""
        result = await self.session.call_tool(
            "create_task_from_email",
            {
                "email_id": email_id,
                "task_title": task_title,
                "auto_extract": auto_extract
            }
        )
        return json.loads(result.content[0].text)
    
    async def bulk_extract_tasks(self, query: str, max_emails: int = 5, create_tasks: bool = False):
        """Process multiple emails at once"""
        result = await self.session.call_tool(
            "bulk_extract_tasks",
            {
                "query": query,
                "max_emails": max_emails,
                "create_tasks": create_tasks
            }
        )
        return json.loads(result.content[0].text)
    
    async def close(self):
        """Close the connection"""
        if self.session:
            await self.session.close()


async def main():
    """Interactive client example"""
    client = GmailTasksClient("/path/to/gmail_tasks_mcp.py")
    
    try:
        await client.connect()
        
        # List available tools
        await client.list_tools()
        
        # Interactive menu
        while True:
            print("\n=== Gmail Tasks MCP Client ===")
            print("1. Search emails for tasks")
            print("2. Extract tasks from specific email")
            print("3. Create tasks from email")
            print("4. Bulk process emails")
            print("5. Exit")
            
            choice = input("Choose an option (1-5): ").strip()
            
            if choice == "1":
                query = input("Enter Gmail search query: ").strip()
                max_results = int(input("Max results (default 10): ").strip() or "10")
                
                result = await client.search_emails_for_tasks(query, max_results)
                print(f"\nFound {result['found_emails']} emails with {result['extracted_tasks']} potential tasks:")
                
                for i, task in enumerate(result['tasks'][:5]):  # Show first 5
                    print(f"{i+1}. {task['title']}")
                    print(f"   From: {task['email_subject']}")
                    print(f"   Source: {task['source']}")
                    print()
            
            elif choice == "2":
                email_id = input("Enter email ID: ").strip()
                
                result = await client.extract_tasks_from_email(email_id)
                print(f"\nEmail: {result['email_subject']}")
                print(f"From: {result['email_from']}")
                print(f"Extracted {len(result['extracted_tasks'])} tasks:")
                
                for i, task in enumerate(result['extracted_tasks']):
                    print(f"{i+1}. {task['title']}")
            
            elif choice == "3":
                email_id = input("Enter email ID: ").strip()
                task_title = input("Custom task title (optional): ").strip()
                auto_extract = input("Auto-extract multiple tasks? (y/n): ").strip().lower() == 'y'
                
                result = await client.create_task_from_email(email_id, task_title, auto_extract)
                print(f"\nProcessed email: {result['email_subject']}")
                print(f"Created {len(result['created_tasks'])} tasks:")
                
                for task in result['created_tasks']:
                    if 'error' in task:
                        print(f"  Error: {task['error']}")
                    else:
                        print(f"  ✓ {task['title']} (ID: {task['id']})")
            
            elif choice == "4":
                query = input("Enter Gmail search query: ").strip()
                max_emails = int(input("Max emails to process (default 5): ").strip() or "5")
                create_tasks = input("Create tasks automatically? (y/n): ").strip().lower() == 'y'
                
                result = await client.bulk_extract_tasks(query, max_emails, create_tasks)
                print(f"\nProcessed {result['processed_emails']} emails")
                print(f"Extracted {result['extracted_tasks']} potential tasks")
                
                if create_tasks:
                    print(f"Created {result['created_tasks']} actual tasks in Google Tasks")
            
            elif choice == "5":
                break
            
            else:
                print("Invalid choice. Please try again.")
    
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
