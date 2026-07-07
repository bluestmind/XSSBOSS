"""Tests for React Server Component (RSC) flight data parser."""
import pytest
from recon_engine.rsc_parser import RSCParser

def test_extract_rsc_chunks_from_html():
    html = """
    <html>
    <head></head>
    <body>
    <script>(self.__next_f=self.__next_f||[]).push([0])</script>
    <script>self.__next_f.push([1,"1:HL[\\"https://assets.com/font.css\\",\\"style\\"]\\n"])</script>
    <script>self.__next_f.push([1,"2:I{\\"id\\":\\"48997\\",\\"name\\":\\"ClientComp\\"}"])</script>
    </body>
    </html>
    """
    chunks = RSCParser.extract_rsc_chunks_from_html(html)
    assert len(chunks) >= 2
    assert any("ClientComp" in c for c in chunks)

def test_parse_rsc_stream():
    stream = r"""
    __PAGE__?{\"category\":\"electronics\",\"page\":\"1\"}
    "/n-api/landing-page"
    "/api/checkout/cart"
    "48997a1b8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f"
    """
    res = RSCParser.parse_rsc_stream(stream)
    assert res["serialized_parameters"].get("category") == "electronics"
    assert res["serialized_parameters"].get("page") == "1"
    assert "/n-api/landing-page" in res["internal_routes"]
    assert "/api/checkout/cart" in res["internal_routes"]
    assert "48997a1b8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f" in res["server_actions"]
