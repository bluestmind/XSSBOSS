import unittest
from unittest.mock import MagicMock

from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding, Severity
from backend_api.models.param import Param
from backend_api.services.bounty_report_service import BountyReportService
from backend_api.services.poc_generator import PoCGenerator
from backend_api.utils.cvss_engine import CVSSEngine


class TestBountyImprovements(unittest.TestCase):

    def test_cvss_31_exact_calculation(self):
        """Verify mathematical precision of CVSS 3.1 formula against official test vectors."""
        # 1. High Impact Reflected/DOM XSS with session/account compromise potential
        score, severity, vector = CVSSEngine.calculate_from_metrics(
            av="N", ac="L", pr="N", ui="R", scope="U", c="H", i="H", a="N"
        )
        self.assertEqual(score, 8.1)
        self.assertEqual(severity, "High")
        self.assertEqual(vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N")

        # 2. Medium Impact Reflected/DOM XSS with Scope Changed
        score_med, severity_med, vector_med = CVSSEngine.calculate_from_metrics(
            av="N", ac="L", pr="N", ui="R", scope="C", c="L", i="L", a="N"
        )
        self.assertEqual(score_med, 6.1)
        self.assertEqual(severity_med, "Medium")
        self.assertEqual(vector_med, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")

    def test_poc_html_generator(self):
        """Verify standalone HTML PoC generation with auto-execution script."""
        html_poc = PoCGenerator.generate_html_poc(
            method="GET",
            url="https://marketplace.porsche.com/api/checkout/cart/redirect",
            param_name="originUrl",
            payload="javascript:alert`XSS`"
        )
        self.assertIn("<!DOCTYPE html>", html_poc)
        self.assertIn("originUrl=javascript%3Aalert%60XSS%60", html_poc)
        self.assertIn("window.location.href =", html_poc)

    def test_poc_curl_generator(self):
        """Verify copy-pasteable curl command generation."""
        curl_cmd = PoCGenerator.generate_curl_command(
            method="GET",
            url="https://marketplace.porsche.com/api/checkout/cart/redirect",
            param_name="originUrl",
            payload="javascript:alert`1`"
        )
        self.assertTrue(curl_cmd.startswith("curl -i -s -k -X GET"))
        self.assertIn("originUrl=javascript%3Aalert%601%60", curl_cmd)

    def test_markdown_sanitizer(self):
        """Verify markdown sanitizer removes broken archaeology and duplicate tokens."""
        dirty_md = "Check `[https://example.com](https://example.com)` with svgsvg and javascriptjavascript."
        clean_md = PoCGenerator.sanitize_markdown_report(dirty_md)
        self.assertNotIn("`[https://example.com](https://example.com)`", clean_md)
        self.assertIn("`https://example.com`", clean_md)
        self.assertNotIn("svgsvg", clean_md)
        self.assertIn("svg", clean_md)
        self.assertNotIn("javascriptjavascript", clean_md)
        self.assertIn("javascript", clean_md)

    def test_bounty_report_generation(self):
        """Verify bounty report service generates structured reports with CVSS 3.1 and PoCs."""
        db = MagicMock()
        endpoint = Endpoint(id=1, method="GET", url_pattern="https://marketplace.porsche.com/api/cart")
        param = Param(id=10, endpoint_id=1, name="originUrl", location="query")
        
        finding = Finding(
            id=100,
            endpoint=endpoint,
            param=param,
            severity=Severity.HIGH,
            best_payload="javascript:alert`XSS`",
            evidence_refs={"verification": {"stored": False, "authenticated": False}}
        )

        report = BountyReportService.build_report(db, finding)
        
        self.assertIn("cvss", report)
        self.assertEqual(report["cvss"]["score"], 8.1)
        self.assertEqual(report["cvss"]["severity"], "High")
        self.assertIn("poc_html", report)
        self.assertIn("poc_curl", report)
        
        # Verify markdown content
        markdown = report["markdown"]
        self.assertIn("CVSS 3.1 Vector", markdown)
        self.assertIn("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", markdown)
        self.assertIn("Proof of Concept (cURL Command)", markdown)
        self.assertIn("Standalone HTML Exploit (PoC)", markdown)


    def test_path_parameter_profiling(self):
        """Verify FilterProfiler handles param_location == 'path' properly."""
        from backend_api.utils.filter_profiler import FilterProfiler
        from unittest.mock import patch

        with patch("httpx.request") as mock_req:
            mock_resp = MagicMock(status_code=200, text="hello injected_val world", headers={})
            mock_req.return_value = mock_resp

            res = FilterProfiler.send_probe(
                method="GET",
                url="https://example.com/akam/{id}/pixel",
                param_name="id",
                param_value="injected_val",
                param_location="path"
            )
            self.assertEqual(res["status_code"], 200)
            mock_req.assert_called_once()
            call_url = mock_req.call_args[1]["url"]
            self.assertEqual(call_url, "https://example.com/akam/injected_val/pixel")


if __name__ == "__main__":
    unittest.main()
