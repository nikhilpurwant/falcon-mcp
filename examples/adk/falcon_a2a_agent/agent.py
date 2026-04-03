import os
import jwt
import json
import logging
from typing import Any
from contextvars import ContextVar
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from google.adk.agents import LlmAgent  # type: ignore[import-untyped]
from google.adk.agents.callback_context import CallbackContext  # type: ignore[import-untyped]
from google.adk.models import LlmRequest, LlmResponse  # type: ignore[import-untyped]
from google.adk.a2a.utils.agent_to_a2a import to_a2a  # type: ignore[import-untyped]
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset  # type: ignore[import-untyped]
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams  # type: ignore[import-untyped]

# Configure logging
logging.basicConfig(level=logging.INFO)

# ContextVar to hold the token's sub
a2a_sub_var: ContextVar[str | None] = ContextVar("a2a_sub", default=None)

# Path to the local mapping file
MAPPING_FILE = os.path.join(os.path.dirname(__file__), "mapping.json")

def load_mapping():
    try:
        with open(MAPPING_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Mapping file not found at {MAPPING_FILE}")
        return {}
    except Exception as e:
        logging.error(f"Error loading mapping file: {e}")
        return {}

# Define the Toolset globally or keep a reference so we can modify its headers
# We use StreamableHTTPConnectionParams to connect to the SaaS MCP server
mcp_server_url = os.environ.get("FALCON_MCP_SERVER_URL", "http://localhost:8000/mcp")

mcp_toolset = MCPToolset(
    connection_params=StreamableHTTPConnectionParams(
        url=mcp_server_url,
        headers={}  # Start with empty headers, will be updated per request
    ),
    use_mcp_resources=True,
)

def before_agent_setup(callback_context: CallbackContext) -> Any | None:
    """Callback run before the agent executes. We use it to update toolset headers."""
    sub = a2a_sub_var.get()
    if sub:
        logging.info(f"Setting headers for sub: {sub} in before_agent_setup")
        mapping = load_mapping()
        secret_name = mapping.get(sub)
        if secret_name:
            # Update the toolset's connection params headers
            # The search said connection_params has headers, let's assume it's exposed or we can access it
            if hasattr(mcp_toolset, "connection_params") and hasattr(mcp_toolset.connection_params, "headers"):
                 mcp_toolset.connection_params.headers = {
                     "SEC_RES_NAME": secret_name,
                     "OAUTH_SUB": sub,
                     "Accept": "application/json, text/event-stream"
                 }
                 logging.info(f"Updated mcp_toolset headers for {sub}")
            else:
                 # Fallback if the structure is different (based on user comment _connection_params.headers)
                 if hasattr(mcp_toolset, "_connection_params"):
                     mcp_toolset._connection_params.headers = {
                         "SEC_RES_NAME": secret_name,
                         "OAUTH_SUB": sub,
                         "Accept": "application/json, text/event-stream"
                     }
                     logging.info(f"Updated mcp_toolset._connection_params headers for {sub}")
        else:
            logging.warning(f"No secret mapping found for sub: {sub}")
    else:
        logging.warning("No sub found in context for before_agent_setup - CLEARING HEADERS to prevent leak")
        if hasattr(mcp_toolset, "connection_params") and hasattr(mcp_toolset.connection_params, "headers"):
             mcp_toolset.connection_params.headers = {}
        elif hasattr(mcp_toolset, "_connection_params"):
             mcp_toolset._connection_params.headers = {}
    return None

# Instructions for the agent
agent_instruction = """You are crowdstrike falcon cybersecurity analyst. Use tools to perform tasks required by user. Be helpful. Try to product output in markdown whenever possible"""

root_agent = LlmAgent(
    model=os.environ.get("GOOGLE_MODEL", "gemini-2.5-flash"),
    name="falcon_a2a_agent",
    instruction=agent_instruction,
    before_agent_callback=before_agent_setup,
    tools=[mcp_toolset],
)

# Expose via A2A
# to_a2a creates a Starlette app
port = int(os.environ.get("A2A_AGENT_PORT", "8001"))
agent_card_path = os.path.join(os.path.dirname(__file__), "agent-card.json")

# Passing static agent card to avoid startup tool discovery crash in SaaS mode
a2a_app = to_a2a(root_agent, port=port, agent_card=agent_card_path)

# Add Starlette middleware to intercept the Bearer token
@a2a_app.middleware("http")
async def jwt_interceptor_middleware(request, call_next):
    auth_header = request.headers.get("Authorization")
    if auth_header:
        if auth_header.lower().startswith("bearer "):
            try:
                # Split at most once to separate prefix from token
                token = auth_header.split(None, 1)[1]
                
                # Check if it is a Google Opaque Access Token (ya29.)
                if token.startswith("ya29."):
                    import httpx
                    async with httpx.AsyncClient() as client:
                        resp = await client.get(
                            "https://www.googleapis.com/oauth2/v3/userinfo",
                            headers={"Authorization": f"Bearer {token}"}
                        )
                        if resp.status_code == 200:
                            payload = resp.json()
                            sub = payload.get("sub")
                        else:
                            logging.error(f"Google UserInfo API failed: {resp.status_code}")
                            sub = None
                else:
                    # Fallback to local JWT decode (Okta, etc)
                    # We are decoding insecurely for testing/demo purposes as per requirement
                    payload = jwt.decode(token, options={"verify_signature": False})
                    sub = payload.get("sub")
                
                if sub:
                    logging.info(f"Interceptor found sub: {sub}")
                    a2a_sub_var.set(sub)
                else:
                    logging.warning("No sub resolved from token")
            except Exception as e:
                logging.error(f"Error resolving identity: {e}")
    
    response = await call_next(request)
    return response
