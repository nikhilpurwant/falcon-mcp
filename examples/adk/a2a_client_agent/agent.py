import jwt
from google.adk.agents.remote_a2a_agent import AGENT_CARD_WELL_KNOWN_PATH
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.a2a.agent.config import A2aRemoteAgentConfig, RequestInterceptor, ParametersConfig
from a2a.client.middleware import ClientCallContext

# Use the sub that is mapped in mapping.json (or allowed by dummy secret cache)
DUMMY_SUB = "110169484474386276334"

def generate_token(sub: str) -> str:
    """Generate a dummy JWT token for testing."""
    payload = {
        "sub": sub,
        "name": "A2A Client Agent",
        "role": "analyst"
    }
    # Demo signature is not validated on server side currently
    return jwt.encode(payload, "dummy_secret", algorithm="HS256")

async def before_request_interceptor(ctx, a2a_message, params_config: ParametersConfig):
    token = generate_token(DUMMY_SUB)
    
    if not params_config.client_call_context:
        params_config.client_call_context = ClientCallContext()
        
    http_kwargs = params_config.client_call_context.state.get("http_kwargs", {})
    headers = http_kwargs.get("headers", {})
    headers["Authorization"] = f"Bearer {token}"
    http_kwargs["headers"] = headers
    params_config.client_call_context.state["http_kwargs"] = http_kwargs
    
    return a2a_message, params_config

config = A2aRemoteAgentConfig(
    request_interceptors=[
        RequestInterceptor(before_request=before_request_interceptor)
    ]
)

root_agent = RemoteA2aAgent(
    name="falcon_a2a_client_agent",
    description=(
        "Helpful assistant that can interact with CrowdStrike Falcon A2A agent"
    ),
    agent_card=f"http://localhost:8001/{AGENT_CARD_WELL_KNOWN_PATH}",
    config=config
)