"""Unit tests for ASTTaintGraph and Empirical Reachability Classifier."""
import unittest
from recon_engine.taint_graph import ASTTaintGraph, ReachabilityStatus


class TestASTTaintGraph(unittest.TestCase):

    def test_direct_source_to_sink_path_detection(self):
        """Detects direct un-sanitized source-to-sink flow from URL param to innerHTML."""
        js_code = """
        function renderProfile() {
            const urlParams = new URLSearchParams(window.location.search);
            const userBio = urlParams.get('bio');
            const targetDiv = document.getElementById('output');
            targetDiv.innerHTML = userBio;
        }
        """
        paths = ASTTaintGraph.build_graph_from_code(js_code)

        self.assertGreater(len(paths), 0)
        top = paths[0]
        self.assertEqual(top.source_node.name, "bio")
        self.assertEqual(top.reachability, ReachabilityStatus.PROVEN_REACHABLE)
        self.assertGreaterEqual(top.exploitability_probability, 0.85)

    def test_sanitized_flow_downgrades_probability(self):
        """Flow through a sanitizer is classified as POTENTIALLY_REACHABLE with lower probability."""
        js_code = """
        function renderSafe() {
            const query = new URLSearchParams(window.location.search).get('q');
            const clean = DOMPurify.sanitize(query);
            document.body.innerHTML = clean;
        }
        """
        paths = ASTTaintGraph.build_graph_from_code(js_code)

        self.assertGreater(len(paths), 0)
        top = paths[0]
        self.assertEqual(top.reachability, ReachabilityStatus.POTENTIALLY_REACHABLE)
        self.assertIn("sanitize", top.intermediate_transforms)
        self.assertLess(top.exploitability_probability, 0.60)

    def test_rank_parameters_by_reachability(self):
        """Ranks parameters deterministically by empirical exploitability probability."""
        js_code = """
        const dangerousParam = new URLSearchParams(window.location.search).get('danger');
        document.getElementById('view').innerHTML = dangerousParam;

        const safeParam = new URLSearchParams(window.location.search).get('safe');
        const encoded = encodeURIComponent(safeParam);
        console.log(encoded);
        """
        ranked = ASTTaintGraph.rank_parameters_by_reachability(js_code)

        self.assertIn("danger", ranked)
        self.assertTrue(ranked["danger"]["proven_connected"])
        self.assertGreater(ranked["danger"]["score"], 0.80)


if __name__ == "__main__":
    unittest.main()
