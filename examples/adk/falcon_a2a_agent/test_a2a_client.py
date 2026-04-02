import httpx
import asyncio
import jwt
import sys
import os

# Configuration
AGENT_URL = "http://localhost:8001"  # Default port for to_a2a served app
# Use the sub that is mapped in mapping.json
DUMMY_SUB = "110169484474386276334"

def generate_token(sub: str) -> str:
    """Generate a dummy JWT token for testing."""
    payload = {
        "sub": sub,
        "name": "Test User",
        "role": "analyst"
    }
    # Using HS256 with a dummy secret (we are not validating signature in the agent for this demo)
    return jwt.encode(payload, "dummy_secret", algorithm="HS256")

async def main():
    token = generate_token(DUMMY_SUB)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # A2A JSON-RPC request to run the agent
    # In standard A2A, there might be a specific method to 'run' or 'ask'
    # Let's try a generic 'run' or 'execute' if we don't know the exact A2A spec,
    # or just send a prompt in 'userContent' if it's that kind of API.
    # The A2A protocol often uses standard methods. Let's try to find if we can call it.
    # If we don't know, we can try to hit /.well-known/agent-card.json first to verify connectivity!
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        # 1. Verify Agent Card (no auth needed usually, but let's test)
        try:
            print("\n--- Fetching Agent Card ---")
            response = await client.get(f"{AGENT_URL}/.well-known/agent-card.json")
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                print(response.text[:1500] + "...") # Print first 1500 chars
            else:
                print(response.text)
        except Exception as e:
            print(f"Error fetching agent card: {e}")

        # 2. Make an A2A Request
        # We need to know the endpoint. If to_a2a mounts at root, it might be POST /
        # Let's try sending a simple prompt.
        print("\n--- Sending A2A Prompt ---")
        prompt = "Check connectivity to Falcon"
        
        # A2A JSON-RPC payload often looks like this (based on standard A2A specs):
        # { "jsonrpc": "2.0", "method": "run", "params": { "prompt": "..." } }
        # Or it might be a POST with data directly if not pure RPC.
        # Let's try a standard JSON-RPC for 'run'
        payload = {'id': '50b25017-0ef7-444f-aab9-cb5e07fc7d47', 'jsonrpc': '2.0', 'method': 'message/send', 'params': {'configuration': {'acceptedOutputModes': [], 'blocking': True}, 'message': {'kind': 'message', 'messageId': 'c13a79d9825746899ca438bfd6319380', 'parts': [{'kind': 'text', 'text': prompt}], 'role': 'agent'}}}
        
        try:
            response = await client.post(f"{AGENT_URL}/", json=payload, headers=headers)
            print(f"Status: {response.status_code}")
            print(response.text)
        except Exception as e:
            print(f"Error sending prompt: {e}")

if __name__ == "__main__":
    asyncio.run(main())
