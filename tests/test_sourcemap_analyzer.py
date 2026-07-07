"""Unit tests for SourceMapAnalyzer."""
import pytest
from recon_engine.sourcemap_analyzer import SourceMapAnalyzer, SourceMapFinding


def test_sourcemap_data_parsing():
    """Test parsing reconstructed source map JSON into structured code findings."""
    mock_map = {
        "version": 3,
        "sources": [
            "webpack:///src/components/UserSearch.tsx",
            "webpack:///src/api/paymentClient.ts"
        ],
        "sourcesContent": [
            """
            import React from 'react';
            export function UserSearch() {
                const query = new URLSearchParams(window.location.search).get('searchTerm');
                // TODO: SECURITY sanitize before injecting
                document.getElementById('output').innerHTML = query;
                return <div>Searching for: {query}</div>;
            }
            """,
            """
            export async function processPayment(cartId: string) {
                const res = await fetch('/api/v2/checkout/process', {
                    method: 'POST',
                    body: JSON.stringify({ cartId, debug: true })
                });
                return res.json();
            }
            """
        ]
    }

    analyzer = SourceMapAnalyzer()
    findings = analyzer.parse_sourcemap_data(mock_map)
    assert len(findings) == 2

    # Check component findings
    comp_finding = next(f for f in findings if "UserSearch.tsx" in f.original_file_path)
    assert "searchTerm" in comp_finding.discovered_parameters
    assert len(comp_finding.dom_sinks) > 0
    assert any("innerHTML" in s["sink"] for s in comp_finding.dom_sinks)
    assert any("TODO: SECURITY" in c for c in comp_finding.developer_comments)

    # Check API client findings
    api_finding = next(f for f in findings if "paymentClient.ts" in f.original_file_path)
    assert any("/api/v2/checkout/process" in ep for ep in api_finding.discovered_endpoints)
