import os
import jwt
import json
import logging
from contextvars import ContextVar
from typing import Any

from google.adk.agents import LlmAgent
from google.adk.models import LlmResponse
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.genai import types

# Configure logging
logging.basicConfig(level=logging.INFO)

# ContextVar to hold all decoded claims
a2a_claims_var: ContextVar[dict | None] = ContextVar("a2a_claims", default=None)
a2a_headers_var: ContextVar[dict | None] = ContextVar("a2a_headers", default=None)

async def dump_claims_callback(callback_context, llm_request) -> LlmResponse | None:
    """Bypasses LLM model call and returns safe headers and multi-claims dump."""
    claims_data = a2a_claims_var.get() or {}
    headers = a2a_headers_var.get() or {}
    
    safe_headers = {}
    for k, v in headers.items():
        if k.lower() in ["authorization", "x-serverless-authorization"]:
            safe_headers[k] = "[REDACTED_BEARER_TOKEN]"
        else:
            safe_headers[k] = v

    response_text = (
        "🔍 Inspection Results:\n\n"
        "### Incoming Safe Headers\n"
        f"```json\n{json.dumps(safe_headers, indent=2)}\n```\n\n"
        "### Decoded Authorization Claims\n"
        f"```json\n{json.dumps(claims_data.get('authorization') or {}, indent=2)}\n```\n\n"
        "### Decoded X-Serverless-Authorization Claims\n"
        f"```json\n{json.dumps(claims_data.get('x-serverless-authorization') or {}, indent=2)}\n```\n\n"
    )

    logging.info("Dump claims callback triggered, bypassing LLM call.")
    
    return LlmResponse(
        content=types.Content(
            role="model",
            parts=[types.Part(text=response_text)]
        )
    )

root_agent = LlmAgent(
    model=os.environ.get("GOOGLE_MODEL", "gemini-2.5-flash"),
    name="sub_client_grabber_agent",
    description="Utility agent that dumps the callers JWT claims back to them.",
    instruction="Dump JWT claims.",
    before_model_callback=dump_claims_callback,
    tools=[] # Toolless
)

from a2a.types import AgentCard

# Serve via A2A
# this port is used to create the Agent url in the card. as such the server runs on whatver we are running uvicorn on
port = int(os.environ.get("A2A_GRABBER_PORT", "8001")) 

# Build dynamic card honoring Cloud Run assignments
card_url = os.environ.get("AGENT_URL", f"http://localhost:{port}")

agent_card_data = {
  "capabilities": {},
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "description": "Utility agent that dumps the callers JWT claims back to them.",
  "name": "sub_client_grabber_agent",
  "preferredTransport": "JSONRPC",
  "protocolVersion": "0.3.0",
  "skills": [
    {
      "description": "Utility agent that dumps the callers JWT claims back to them. Dump JWT claims.",
      "examples": [],
      "id": "sub_client_grabber_agent",
      "name": "model",
      "tags": ["llm"]
    }
  ],
  "supportsAuthenticatedExtendedCard": "false",
  "url": card_url,
  "version": "0.0.1"
}

a2a_app = to_a2a(root_agent, port=port, agent_card=AgentCard(**agent_card_data))

# Add Starlette middleware to intercept the Bearer token
@a2a_app.middleware("http")
async def jwt_interceptor_middleware(request, call_next):
    # Parse standard Authorization
    claims_auth = {}
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
                            claims_auth = resp.json()
                        else:
                            claims_auth = {"error": f"Google UserInfo API failed: {resp.status_code} - {resp.text}"}
                else:
                    # Fallback to local JWT decode
                    claims_auth = jwt.decode(token, options={"verify_signature": False})
            except Exception as e:
                token_head = token[:15] if token else ""
                claims_auth = {"error": f"Resolution failed: {e}. Token head: {token_head}..."}
        else:
            claims_auth = {"error": f"Absent 'Bearer ' prefix. Value head: {auth_header[:25]}..."}

    # Parse Cloud Run Serverless Authorization
    claims_serv = {}
    serv_header = request.headers.get("x-serverless-authorization")
    if serv_header:
        if serv_header.lower().startswith("bearer "):
            try:
                token = serv_header.split(None, 1)[1]
                claims_serv = jwt.decode(token, options={"verify_signature": False})
            except Exception as e:
                claims_serv = {"error": f"JWT decode failed: {e}"}
        else:
            claims_serv = {"error": f"Absent 'Bearer ' prefix. Value head: {serv_header[:25]}..."}

    claims_data = {
        "authorization": claims_auth,
        "x-serverless-authorization": claims_serv
    }
            
    # Set context vars
    token_st = a2a_claims_var.set(claims_data)
    headers_st = a2a_headers_var.set(dict(request.headers))
    try:
        response = await call_next(request)
        return response
    finally:
        a2a_claims_var.reset(token_st)
        a2a_headers_var.reset(headers_st)
