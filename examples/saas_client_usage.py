#!/usr/bin/env python3
"""
Sample Python client to test Falcon MCP Server in SaaS mode.
Uses httpx to send JSON-RPC requests with required SaaS headers.
"""

import asyncio
import httpx
import sys

# Configuration
SERVER_URL = "http://localhost:8000/mcp"
# Example Secret Resource Name (replace with your actual secret)
SEC_RES_NAME = "projects/PROJECT_NUM/secrets/falcon_mcp_110169484474386276334"
# The Client ID (OAuth Sub) that matches what is inside the secret
OAUTH_SUB = "110169484474386276334"


async def main():
    headers = {
        "SEC_RES_NAME": SEC_RES_NAME,
        "OAUTH_SUB": OAUTH_SUB,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    # Example payload to list tools
    list_tools_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }

    # Example payload to call a tool
    call_tool_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "falcon_check_connectivity",
            "arguments": {}
        }
    }

    async with httpx.AsyncClient() as client:
        print(f"Connecting to {SERVER_URL} with SaaS headers...")
        
        # 1. List Tools
        try:
            print("\n--- Listing Tools ---")
            response = await client.post(SERVER_URL, json=list_tools_payload, headers=headers)
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                print(response.text)
            else:
                print(response.text)
        except Exception as e:
            print(f"Error listing tools: {e}")

        # 2. Call Tool
        try:
            print("\n--- Calling falcon_check_connectivity ---")
            response = await client.post(SERVER_URL, json=call_tool_payload, headers=headers)
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                print(response.text)
            else:
                print(response.text)
        except Exception as e:
            print(f"Error calling tool: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        SERVER_URL = sys.argv[1]
    asyncio.run(main())
