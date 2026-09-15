"""
API & Interface Discovery Engine for XSS Boss.

Features:
- Automated GraphQL endpoint probing, full schema introspection, and field suggestion harvesting
- OpenAPI / Swagger 2.0 & 3.0/3.1 specification parser (paths, query/path/body parameters, schemas)
- WebSocket & gRPC-Web service endpoint discovery
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import httpx
except ImportError:
    httpx = None

from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.utils.rate_limiter import rate_limited_call


@dataclass
class DiscoveredAPIEndpoint:
    """A discovered API endpoint with structured parameters."""
    url: str
    method: str = "GET"
    api_type: str = "rest"  # rest, graphql, openapi, websocket, grpc
    path_params: List[str] = field(default_factory=list)
    query_params: List[str] = field(default_factory=list)
    header_params: List[str] = field(default_factory=list)
    body_params: List[str] = field(default_factory=list)
    sample_request_body: Optional[Any] = None
    description: str = ""
    auth_required: bool = False


GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args {
          name
          type {
            kind
            name
            ofType { kind name }
          }
        }
      }
    }
  }
}
"""

CANDIDATE_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/api/v1/graphql",
    "/query",
    "/api/query",
    "/subgraph",
    "/api/v1/subgraph",
]

CANDIDATE_OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/api-docs",
    "/api-docs.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/doc/swagger.json",
    "/docs/swagger.json",
]


class APIDiscovery:
    """Discovers and parses GraphQL, OpenAPI, and modern RPC APIs."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 2.0,
        request_headers: Optional[Dict[str, str]] = None,
        response_guard: Optional[Callable[[int, str, str], None]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.request_headers = dict(request_headers or {})
        self.response_guard = response_guard

    def _fetch_post(self, url: str, json_data: Dict[str, Any]) -> Optional[Any]:
        """HTTP POST supporting httpx and urllib."""
        if httpx:
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/json",
                    **self.request_headers,
                }
                response = rate_limited_call(
                    url,
                    lambda: httpx.post(
                        url,
                        json=json_data,
                        timeout=self.timeout,
                        verify=not settings.ALLOW_INSECURE_TLS,
                        headers=headers,
                        follow_redirects=False,
                    ),
                )
                if self.response_guard:
                    self.response_guard(response.status_code, str(response.url), response.text)
                return response
            except Exception:
                return None
        if self.request_headers:
            # urllib's redirect handler may copy caller-supplied bearer headers to a
            # different origin.  Authenticated discovery therefore fails closed here.
            return None
        try:
            import urllib.request
            req = urllib.request.Request(
                url,
                data=json.dumps(json_data).encode("utf-8"),
                headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json", **self.request_headers}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                data = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                class _Resp:
                    status_code = getattr(resp, "status", getattr(resp, "code", 200))
                    text = data
                    def json(self):
                        return json.loads(data)
                return _Resp()
        except Exception:
            return None

    def _fetch_get(self, url: str) -> Optional[Any]:
        """HTTP GET supporting httpx and urllib."""
        if httpx:
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, text/yaml",
                    **self.request_headers,
                }
                response = rate_limited_call(
                    url,
                    lambda: httpx.get(
                        url,
                        timeout=self.timeout,
                        verify=not settings.ALLOW_INSECURE_TLS,
                        headers=headers,
                        follow_redirects=False,
                    ),
                )
                if self.response_guard:
                    self.response_guard(response.status_code, str(response.url), response.text)
                return response
            except Exception:
                return None
        if self.request_headers:
            return None
        try:
            import urllib.request
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json, text/yaml", **self.request_headers}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                data = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                class _Resp:
                    status_code = getattr(resp, "status", getattr(resp, "code", 200))
                    text = data
                    def json(self):
                        return json.loads(data)
                return _Resp()
        except Exception:
            return None

    def discover_all(self, html_content: Optional[str] = None, probe_remote: bool = True) -> List[DiscoveredAPIEndpoint]:
        """Run all API discovery probes and return aggregated endpoints."""
        endpoints: List[DiscoveredAPIEndpoint] = []
        if html_content:
            endpoints.extend(self.extract_websocket_endpoints(html_content))
            endpoints.extend(self.extract_grpc_endpoints(html_content))
        if probe_remote:
            endpoints.extend(self.probe_graphql())
            endpoints.extend(self.probe_openapi())
        return endpoints

    # =========================================================================
    # 1. GraphQL Discovery & Schema Introspection
    # =========================================================================
    def probe_graphql(self) -> List[DiscoveredAPIEndpoint]:
        """Probe common GraphQL endpoints, run introspection, and extract queries/mutations."""
        endpoints: List[DiscoveredAPIEndpoint] = []

        for path in CANDIDATE_GRAPHQL_PATHS:
            target_url = f"{self.base_url}{path}"
            try:
                # Send introspection query via POST
                resp = self._fetch_post(target_url, {"query": GRAPHQL_INTROSPECTION_QUERY})

                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        schema = data.get("data", {}).get("__schema")
                        if schema:
                            logger.info(f"GraphQL introspection successful on {target_url}")
                            extracted = self._parse_graphql_schema(target_url, schema)
                            endpoints.extend(extracted)
                            break  # Found primary active endpoint
                    except Exception:
                        pass
                
                # Check for GET GraphQL support or field suggestions
                resp_get = self._fetch_get(f"{target_url}?query={{__typename}}")
                if resp_get and resp_get.status_code == 200 and "__typename" in resp_get.text:
                    endpoints.append(
                        DiscoveredAPIEndpoint(
                            url=target_url,
                            method="POST",
                            api_type="graphql",
                            query_params=["query", "variables", "operationName"],
                            body_params=["query", "variables", "operationName"],
                            sample_request_body={"query": "{ __typename }"},
                            description="GraphQL endpoint with GET/POST query execution enabled",
                        )
                    )
            except Exception:
                continue

        return endpoints

    def _parse_graphql_schema(self, endpoint_url: str, schema: Dict[str, Any]) -> List[DiscoveredAPIEndpoint]:
        """Parse introspected GraphQL schema into individual executable endpoints."""
        endpoints = []
        types = schema.get("types", [])
        type_map = {t.get("name"): t for t in types if t.get("name")}

        query_type_name = (schema.get("queryType") or {}).get("name", "Query")
        mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

        # Extract queries
        query_type = type_map.get(query_type_name)
        if query_type and "fields" in query_type:
            for field in query_type.get("fields") or []:
                f_name = field.get("name")
                if not f_name or f_name.startswith("__"):
                    continue
                args = [a.get("name") for a in (field.get("args") or []) if a.get("name")]
                
                # Construct sample GraphQL query
                arg_sig = ", ".join(f"${a}: String" for a in args)
                arg_call = ", ".join(f"{a}: ${a}" for a in args)
                query_str = f"query {f_name}({arg_sig}) {{ {f_name}({arg_call}) }}" if args else f"query {{ {f_name} }}"
                
                endpoints.append(
                    DiscoveredAPIEndpoint(
                        url=endpoint_url,
                        method="POST",
                        api_type="graphql",
                        body_params=args + ["query", "variables"],
                        sample_request_body={
                            "query": query_str,
                            "variables": {a: "sample" for a in args}
                        },
                        description=f"GraphQL Query: {f_name}",
                    )
                )

        # Extract mutations
        mutation_type = type_map.get(mutation_type_name)
        if mutation_type and "fields" in mutation_type:
            for field in mutation_type.get("fields") or []:
                f_name = field.get("name")
                if not f_name or f_name.startswith("__"):
                    continue
                args = [a.get("name") for a in (field.get("args") or []) if a.get("name")]
                arg_sig = ", ".join(f"${a}: String" for a in args)
                arg_call = ", ".join(f"{a}: ${a}" for a in args)
                mutation_str = f"mutation {f_name}({arg_sig}) {{ {f_name}({arg_call}) }}" if args else f"mutation {{ {f_name} }}"

                endpoints.append(
                    DiscoveredAPIEndpoint(
                        url=endpoint_url,
                        method="POST",
                        api_type="graphql",
                        body_params=args + ["query", "variables"],
                        sample_request_body={
                            "query": mutation_str,
                            "variables": {a: "sample" for a in args}
                        },
                        description=f"GraphQL Mutation: {f_name}",
                    )
                )

        return endpoints

    # =========================================================================
    # 2. OpenAPI & Swagger Parser
    # =========================================================================
    def probe_openapi(self) -> List[DiscoveredAPIEndpoint]:
        """Probe and parse OpenAPI / Swagger definitions."""
        endpoints: List[DiscoveredAPIEndpoint] = []

        for path in CANDIDATE_OPENAPI_PATHS:
            target_url = f"{self.base_url}{path}"
            try:
                resp = self._fetch_get(target_url)
                if resp and resp.status_code == 200:
                    try:
                        spec = resp.json()
                        if isinstance(spec, dict) and ("swagger" in spec or "openapi" in spec or "paths" in spec):
                            logger.info(f"Discovered OpenAPI / Swagger specification at {target_url}")
                            parsed = self._parse_openapi_spec(spec)
                            endpoints.extend(parsed)
                            break
                    except Exception:
                        pass
            except Exception:
                continue

        return endpoints

    def _parse_openapi_spec(self, spec: Dict[str, Any]) -> List[DiscoveredAPIEndpoint]:
        """Parse OpenAPI 2.0/3.0 spec dict into DiscoveredAPIEndpoint list."""
        endpoints = []
        
        # Base URL resolution
        base_path = spec.get("basePath", "")
        servers = spec.get("servers", [])
        server_url = servers[0].get("url", "") if servers else self.base_url
        if server_url.startswith("/"):
            server_url = f"{self.base_url}{server_url}"

        paths = spec.get("paths", {})
        for p, p_methods in paths.items():
            if not isinstance(p_methods, dict):
                continue
            for method, m_info in p_methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch", "options"]:
                    continue

                full_url = f"{server_url.rstrip('/')}{base_path.rstrip('/')}/{p.lstrip('/')}"
                path_params = []
                query_params = []
                header_params = []
                body_params = []
                sample_body = None

                # Extract parameters
                parameters = m_info.get("parameters", [])
                for param in parameters:
                    p_in = param.get("in")
                    p_name = param.get("name")
                    if not p_name:
                        continue
                    if p_in == "path":
                        path_params.append(p_name)
                    elif p_in == "query":
                        query_params.append(p_name)
                    elif p_in == "header":
                        header_params.append(p_name)
                    elif p_in in ["body", "formData"]:
                        body_params.append(p_name)

                # OpenAPI 3 requestBody
                request_body = m_info.get("requestBody", {})
                content = request_body.get("content", {})
                json_schema = (content.get("application/json") or {}).get("schema", {})
                if json_schema:
                    props = json_schema.get("properties", {})
                    for prop_name in props.keys():
                        body_params.append(prop_name)
                    sample_body = {k: "test" for k in props.keys()}

                endpoints.append(
                    DiscoveredAPIEndpoint(
                        url=full_url,
                        method=method.upper(),
                        api_type="openapi",
                        path_params=path_params,
                        query_params=query_params,
                        header_params=header_params,
                        body_params=body_params,
                        sample_request_body=sample_body,
                        description=m_info.get("summary") or m_info.get("description", ""),
                    )
                )

        return endpoints

    # =========================================================================
    # 3. WebSocket & gRPC-Web Discovery
    # =========================================================================
    def extract_websocket_endpoints(self, html_or_js: str) -> List[DiscoveredAPIEndpoint]:
        """Extract WebSocket URLs from HTML or JavaScript bundle code."""
        endpoints = []
        # Pattern 1: wss:// or ws:// URLs
        ws_matches = re.finditer(r'[\'"]((?:wss?://)[a-zA-Z0-9_/.:-]+)[\'"]', html_or_js)
        for m in ws_matches:
            endpoints.append(
                DiscoveredAPIEndpoint(
                    url=m.group(1),
                    method="GET",
                    api_type="websocket",
                    description="WebSocket Endpoint URL",
                )
            )

        # Pattern 2: new WebSocket('/path')
        ws_rel_matches = re.finditer(r'new\s+WebSocket\s*\(\s*[\'"](/[^"\']+)[\'"]', html_or_js)
        for m in ws_rel_matches:
            path = m.group(1)
            ws_proto = "wss" if self.base_url.startswith("https") else "ws"
            host = urllib.parse.urlparse(self.base_url).netloc
            full_ws = f"{ws_proto}://{host}{path}"
            endpoints.append(
                DiscoveredAPIEndpoint(
                    url=full_ws,
                    method="GET",
                    api_type="websocket",
                    description=f"Relative WebSocket Path: {path}",
                )
            )

        return endpoints

    def extract_grpc_endpoints(self, html_or_js: str) -> List[DiscoveredAPIEndpoint]:
        """Extract gRPC-Web and Connect RPC method paths from bundle code."""
        endpoints = []
        # Pattern: /package.ServiceName/MethodName
        grpc_matches = re.finditer(r'[\'"](/([a-zA-Z0-9_]+\.)+[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)[\'"]', html_or_js)
        for m in grpc_matches:
            path = m.group(1)
            endpoints.append(
                DiscoveredAPIEndpoint(
                    url=f"{self.base_url}{path}",
                    method="POST",
                    api_type="grpc",
                    header_params=["content-type", "x-grpc-web"],
                    description=f"gRPC-Web / Connect RPC Service: {path}",
                )
            )
        return endpoints
