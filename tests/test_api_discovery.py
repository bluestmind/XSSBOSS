"""Unit tests for APIDiscovery (GraphQL and OpenAPI / Swagger)."""
import pytest
from recon_engine.api_discovery import APIDiscovery, DiscoveredAPIEndpoint


def test_graphql_schema_parsing():
    """Test parsing GraphQL introspection schema into operations and parameter schemas."""
    mock_schema = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "name": "Query",
                "fields": [
                    {
                        "name": "getUserById",
                        "args": [{"name": "userId", "type": {"kind": "SCALAR", "name": "String"}}]
                    },
                    {
                        "name": "searchProducts",
                        "args": [
                            {"name": "query", "type": {"kind": "SCALAR", "name": "String"}},
                            {"name": "category", "type": {"kind": "SCALAR", "name": "String"}}
                        ]
                    }
                ]
            },
            {
                "name": "Mutation",
                "fields": [
                    {
                        "name": "updateUserProfile",
                        "args": [
                            {"name": "bio", "type": {"kind": "SCALAR", "name": "String"}},
                            {"name": "avatarUrl", "type": {"kind": "SCALAR", "name": "String"}}
                        ]
                    }
                ]
            }
        ]
    }

    api_disc = APIDiscovery("https://api-target.com")
    endpoints = api_disc._parse_graphql_schema("https://api-target.com/graphql", mock_schema)
    assert len(endpoints) == 3

    # Check search query
    search_ep = next((e for e in endpoints if "searchProducts" in e.description), None)
    assert search_ep is not None
    assert "query" in search_ep.body_params
    assert "category" in search_ep.body_params
    assert search_ep.method == "POST"
    assert search_ep.sample_request_body is not None


def test_openapi_spec_parsing():
    """Test parsing OpenAPI 3.0 specification dict."""
    mock_spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api-target.com/v1"}],
        "paths": {
            "/users/{userId}/posts": {
                "get": {
                    "summary": "Get user posts",
                    "parameters": [
                        {"name": "userId", "in": "path", "required": True},
                        {"name": "limit", "in": "query", "required": False},
                        {"name": "offset", "in": "query", "required": False}
                    ]
                },
                "post": {
                    "summary": "Create new post",
                    "parameters": [
                        {"name": "userId", "in": "path", "required": True}
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "title": {"type": "string"},
                                        "content": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    api_disc = APIDiscovery("https://api-target.com")
    endpoints = api_disc._parse_openapi_spec(mock_spec)
    assert len(endpoints) == 2

    # Verify GET endpoint
    get_ep = next(e for e in endpoints if e.method == "GET")
    assert "userId" in get_ep.path_params
    assert "limit" in get_ep.query_params
    assert "offset" in get_ep.query_params

    # Verify POST endpoint
    post_ep = next(e for e in endpoints if e.method == "POST")
    assert "userId" in post_ep.path_params
    assert "title" in post_ep.body_params
    assert "content" in post_ep.body_params


def test_websocket_and_grpc_extraction():
    """Test extracting WebSocket URLs and gRPC routes from client script bundle code."""
    bundle_code = """
    const socket = new WebSocket('wss://realtime.target.com/cable/v2');
    const relSocket = new WebSocket('/socket.io/?EIO=4&transport=websocket');
    const client = new ProtoServiceClient('/com.company.auth.AuthService/Login');
    """
    api_disc = APIDiscovery("https://target.com")
    ws_endpoints = api_disc.extract_websocket_endpoints(bundle_code)
    assert len(ws_endpoints) >= 2
    assert any("wss://realtime.target.com/cable/v2" in e.url for e in ws_endpoints)

    grpc_endpoints = api_disc.extract_grpc_endpoints(bundle_code)
    assert len(grpc_endpoints) >= 1
    assert any("AuthService/Login" in e.url for e in grpc_endpoints)
