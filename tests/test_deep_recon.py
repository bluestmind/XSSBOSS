import base64
import json
import unittest
from unittest.mock import MagicMock, patch

from backend_api.models.target import Target
from recon_engine.advanced_recon import AdvancedRecon
from recon_engine.normalizer import RequestNormalizer
from recon_engine.utils.request_signature import RequestSignature


class MockResponse:
    def __init__(self, content: bytes, status: int = 200, headers: dict = None):
        self.content = content
        self.status = status
        self.status_code = status
        self.headers = headers or {"Content-Type": "application/json"}

    def read(self):
        return self.content

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestDeepRecon(unittest.TestCase):

    def test_signature_slug_and_jwt_normalization(self):
        """Verify dynamic listing slugs, dates, and JWT tokens are normalized into placeholders."""
        # 1. Product/Listing alphanumeric slug (e.g. 052R4E)
        url_listing = "https://marketplace.porsche.com/de/de_DE/porsche-approved/052R4E"
        norm_listing = RequestSignature.normalize_url(url_listing)
        self.assertIn("/{slug}", norm_listing)

        # 2. JWT token in path
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGz"
        url_jwt = f"https://example.com/auth/verify/{jwt_token}"
        norm_jwt = RequestSignature.normalize_url(url_jwt)
        self.assertIn("/{jwt}", norm_jwt)

        # 3. Date hierarchy
        url_date = "https://example.com/blog/2026/08/28/post"
        norm_date = RequestSignature.normalize_url(url_date)
        self.assertIn("/{date}/", norm_date)

    def test_nested_parameter_unpacking(self):
        """Verify Base64 and JSON encoded parameters are unpacked into child parameters."""
        # 1. Base64 encoded JSON (similar to cartRedirectPayload)
        payload = {"originUrl": "https://evil.com", "listingId": "052R4E"}
        b64_val = base64.b64encode(json.dumps(payload).encode()).decode()

        req_data = {
            "url": f"https://marketplace.porsche.com/api/cart?cartRedirectPayload={b64_val}&ref=1"
        }

        params = RequestNormalizer.extract_parameters(req_data, "GET")
        query_param_names = [p["name"] for p in params["query"]]

        # Should extract top-level parameter
        self.assertIn("cartRedirectPayload", query_param_names)
        self.assertIn("ref", query_param_names)

        # Should unpack nested parameters inside the Base64 payload!
        self.assertIn("cartRedirectPayload.originUrl", query_param_names)
        self.assertIn("cartRedirectPayload.listingId", query_param_names)

    @patch("urllib.request.urlopen")
    def test_certificate_transparency_domains(self, mock_urlopen):
        """Verify crt.sh Certificate Transparency responses are parsed for subdomains."""
        crt_data = [
            {"name_value": "marketplace.porsche.com\nidentity.porsche.com"},
            {"name_value": "finder.porsche.com"}
        ]
        mock_urlopen.return_value = MockResponse(json.dumps(crt_data).encode("utf-8"))

        db = MagicMock()
        target = Target(id=1, base_url="https://porsche.com", scope_tags={"allowed_hosts": ["*.porsche.com"]})
        db.query().filter().first.return_value = target

        recon = AdvancedRecon(db, 1)
        subdomains = recon.fetch_certificate_transparency_domains("https://porsche.com")

        self.assertIn("https://marketplace.porsche.com", subdomains)
        self.assertIn("https://identity.porsche.com", subdomains)
        self.assertIn("https://finder.porsche.com", subdomains)

    def test_graphql_introspection(self):
        """Verify GraphQL schema introspection extracts query and mutation fields."""
        gql_schema = {
            "data": {
                "__schema": {
                    "queryType": {
                        "fields": [{"name": "getCart"}, {"name": "getUserProfile"}]
                    },
                    "mutationType": {
                        "fields": [{"name": "updateRedirectUri"}]
                    }
                }
            }
        }
        db = MagicMock()
        target = Target(id=1, base_url="https://example.com")
        db.query().filter().first.return_value = target

        recon = AdvancedRecon(db, 1)
        recon._fetch_active_text = MagicMock(return_value=json.dumps(gql_schema))
        endpoints = recon.probe_graphql_schema("https://example.com")

        self.assertTrue(any("query={getCart}" in ep for ep in endpoints))
        self.assertTrue(any("query={updateRedirectUri}" in ep for ep in endpoints))


if __name__ == "__main__":
    unittest.main()
