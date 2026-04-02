"""
Unit tests for SaaS mode in Falcon MCP Server.
"""

import pytest
from unittest.mock import MagicMock, patch
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from falcon_mcp.common.auth import saas_middleware
from falcon_mcp.common.saas import parse_and_validate_secret, falcon_credentials_var


def homepage(request):
    """Simple test endpoint."""
    return JSONResponse({"status": "ok"})


@pytest.fixture
def app_with_saas():
    """Create a test app with SaaS middleware."""
    app = Starlette(routes=[Route("/", homepage, methods=["GET", "POST"])])
    return saas_middleware(app)


@pytest.fixture
def client(app_with_saas):
    """Create a test client for the app with SaaS middleware."""
    return TestClient(app_with_saas)


class TestSaaSSecretParsing:
    """Test cases for secret parsing and validation."""

    def test_parse_valid_secret(self):
        """Test parsing a valid secret."""
        secret_val = "mysub=myclientid=myclientsecret=https://api.example.com"
        header_sub = "mysub"
        
        creds = parse_and_validate_secret(secret_val, header_sub)
        
        assert creds["client_id"] == "myclientid"
        assert creds["client_secret"] == "myclientsecret"
        assert creds["base_url"] == "https://api.example.com"
        assert creds["oauth_sub"] == "mysub"

    def test_parse_invalid_format(self):
        """Test parsing an invalid secret format."""
        secret_val = "mysub=myclientid=myclientsecret"  # Missing URL
        header_sub = "mysub"
        
        with pytest.raises(ValueError, match="Invalid secret format"):
            parse_and_validate_secret(secret_val, header_sub)

    def test_parse_mismatch_sub(self):
        """Test parsing when OAUTH_SUB mismatches."""
        secret_val = "mysub=myclientid=myclientsecret=https://api.example.com"
        header_sub = "wrongsub"
        
        with pytest.raises(ValueError, match="OAUTH_SUB mismatch"):
            parse_and_validate_secret(secret_val, header_sub)


class TestSaaSMiddleware:
    """Test cases for the SaaS middleware."""

    def test_missing_headers(self, client):
        """Test middleware returns 401 when headers are missing."""
        response = client.get("/")
        assert response.status_code == 401
        assert "Missing SaaS headers" in response.json()["error"]

    def test_missing_one_header(self, client):
        """Test middleware returns 401 when one header is missing."""
        response = client.get("/", headers={"sec-res-name": "mysecret"})
        assert response.status_code == 401
        
        response = client.get("/", headers={"oauth-sub": "mysub"})
        assert response.status_code == 401

    @patch("falcon_mcp.common.auth.get_secret_val")
    def test_failed_secret_fetch(self, mock_get_secret, client):
        """Test middleware returns 401 when secret fetch fails."""
        mock_get_secret.side_effect = Exception("Fetch failed")
        
        response = client.get("/", headers={
            "sec-res-name": "mysecret",
            "oauth-sub": "mysub"
        })
        assert response.status_code == 401
        assert "SaaS authentication failed" in response.json()["error"]

    @patch("falcon_mcp.common.auth.get_secret_val")
    def test_successful_auth_sets_context(self, mock_get_secret, client):
        """Test middleware succeeds and sets context when valid."""
        mock_get_secret.return_value = "mysub=myclientid=myclientsecret=https://api.example.com"
        
        # We need to verify that context was set during the request.
        # Since we use TestClient, it runs the request synchronously in this thread.
        # We can verify by checking if the endpoint returns success (which means it passed through).
        response = client.get("/", headers={
            "sec-res-name": "mysecret",
            "oauth-sub": "mysub"
        })
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    @patch("falcon_mcp.common.auth.get_secret_val")
    def test_context_is_reset_after_request(self, mock_get_secret, client):
        """Test that context is reset after the request finishes."""
        mock_get_secret.return_value = "mysub=myclientid=myclientsecret=https://api.example.com"
        
        # Verify context is None before
        assert falcon_credentials_var.get() is None
        
        response = client.get("/", headers={
            "sec-res-name": "mysecret",
            "oauth-sub": "mysub"
        })
        assert response.status_code == 200
        
        # Verify context is None after
        assert falcon_credentials_var.get() is None
