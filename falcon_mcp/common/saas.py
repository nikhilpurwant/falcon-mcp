"""
SaaS helper module for Falcon MCP Server.

This module provides context variables and utilities for fetching secrets
from Google Cloud Secret Manager in SaaS mode.
"""

import os
from contextvars import ContextVar
from typing import TypedDict

from google.cloud import secretmanager  # type: ignore[import-untyped]

from falcon_mcp.common.logging import get_logger

logger = get_logger(__name__)


class FalconCredentials(TypedDict):
    """Type definition for Falcon credentials."""
    client_id: str
    client_secret: str
    base_url: str
    oauth_sub: str


# Context variable to hold credentials for the current request
falcon_credentials_var: ContextVar[FalconCredentials | None] = ContextVar(
    "falcon_credentials", default=None
)


def get_secret_val(secret_name: str) -> str:
    """Fetch secret value from Google Cloud Secret Manager.

    Args:
        secret_name: Full resource name of the secret, e.g.,
                    "projects/PROJECT_ID/secrets/SECRET_ID/versions/VERSION"
                    If version is not specified, it defaults to "latest".

    Returns:
        str: The secret payload as a string
    """
    # If version is not specified in the resource name, add "/versions/latest"
    if "/versions/" not in secret_name:
        secret_name = f"{secret_name}/versions/latest"

    logger.debug("Fetching secret from Secret Manager: %s", secret_name)

    try:
        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(name=secret_name)
        payload = response.payload.data.decode("UTF-8")
        return payload
    except Exception as e:
        logger.error("Failed to fetch secret %s: %s", secret_name, e)
        raise RuntimeError(f"Failed to fetch secret {secret_name}: {e}") from e


def parse_and_validate_secret(secret_val: str, header_sub: str) -> FalconCredentials:
    """Parse the secret value and validate it against the header OAUTH_SUB.

    Format: OAUTH_SUB=FALCON_CLIENT_ID=FALCON_CLIENT_SECRET=FALCON_BASE_URL

    Args:
        secret_val: The raw secret string
        header_sub: The OAUTH_SUB from the request header

    Returns:
        dict: Parsed credentials

    Raises:
        ValueError: If parsing fails or OAUTH_SUB doesn't match
    """
    parts = secret_val.strip().split("=")
    if len(parts) != 4:
        logger.error("Invalid secret format. Expected 4 parts separated by '=', got %d", len(parts))
        raise ValueError(f"Invalid secret format. Expected 4 parts, got {len(parts)}")

    oauth_sub, client_id, client_secret, base_url = parts

    if oauth_sub != header_sub:
        logger.error("OAUTH_SUB mismatch. Header: %s, Secret: %s", header_sub, oauth_sub)
        raise ValueError("OAUTH_SUB mismatch")

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "base_url": base_url,
        "oauth_sub": oauth_sub,
    }
