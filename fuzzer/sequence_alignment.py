import re
from html.parser import HTMLParser
from typing import List, Tuple, Dict, Set

class TreeNode:
    """A node in the parsed DOM tree representation."""
    def __init__(self, label: str):
        self.label = label
        self.children: List['TreeNode'] = []

class SimpleDOMParser(HTMLParser):
    """Robust HTML parser to construct nested TreeNode structures."""
    def __init__(self):
        super().__init__()
        self.root = TreeNode("root")
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = TreeNode(tag)
        self.stack[-1].children.append(node)
        self.stack.append(node)

    def handle_endtag(self, tag):
        if len(self.stack) > 1:
            self.stack.pop()

    def handle_data(self, data):
        if data.strip():
            self.stack[-1].children.append(TreeNode("#text"))

class DOMSequenceAligner:
    """Mathematical sequence alignment and Tree Edit Distance (TED) analysis for DOM trees using the Zhang-Shasha algorithm."""

    @staticmethod
    def html_to_tree(html: str) -> TreeNode:
        """Parses HTML string into a nested TreeNode DOM tree."""
        parser = SimpleDOMParser()
        parser.feed(html)
        return parser.root

    @staticmethod
    def get_postorder(root: TreeNode) -> List[TreeNode]:
        """Returns the nodes of the tree in postorder traversal."""
        postorder = []
        def traverse(node: TreeNode):
            for child in node.children:
                traverse(child)
            postorder.append(node)
        traverse(root)
        return postorder

    @staticmethod
    def tree_edit_distance(root_a: TreeNode, root_b: TreeNode) -> int:
        """Computes the exact Tree Edit Distance between two DOM trees using the Zhang-Shasha algorithm."""
        nodes_a = DOMSequenceAligner.get_postorder(root_a)
        nodes_b = DOMSequenceAligner.get_postorder(root_b)
        
        len_a = len(nodes_a)
        len_b = len(nodes_b)
        
        if len_a == 0:
            return len_b
        if len_b == 0:
            return len_a

        # 1-based indexing for postorder nodes
        # Find parent and leftmost leaf mappings
        leftmost_a = [0] * (len_a + 1)
        leftmost_b = [0] * (len_b + 1)
        
        # Helper to compute leftmost leaf for each node
        def compute_leftmost(nodes: List[TreeNode], leftmost: List[int]):
            # Map node object to its 1-based postorder index
            node_idx = {node: idx + 1 for idx, node in enumerate(nodes)}
            
            def get_leftmost(node: TreeNode) -> int:
                curr = node
                while curr.children:
                    curr = curr.children[0]
                return node_idx[curr]
                
            for idx, node in enumerate(nodes):
                leftmost[idx + 1] = get_leftmost(node)
                
        compute_leftmost(nodes_a, leftmost_a)
        compute_leftmost(nodes_b, leftmost_b)
        
        # Find key roots (nodes that have leftmost child different from their parent's leftmost)
        def get_keyroots(nodes: List[TreeNode], leftmost: List[int]) -> List[int]:
            keyroots = []
            # Root is always a keyroot
            keyroots.append(len(nodes))
            # Map node parents
            parent = {}
            for node in nodes:
                for child in node.children:
                    parent[child] = node
            for idx, node in enumerate(nodes):
                node_1based = idx + 1
                if node in parent:
                    p_idx = nodes.index(parent[node]) + 1
                    if leftmost[node_1based] != leftmost[p_idx]:
                        keyroots.append(node_1based)
            return sorted(list(set(keyroots)))
            
        keyroots_a = get_keyroots(nodes_a, leftmost_a)
        keyroots_b = get_keyroots(nodes_b, leftmost_b)
        
        treedist = {}
        
        # Inner forest distance DP loop
        for kr_a in keyroots_a:
            for kr_b in keyroots_b:
                # Initialize forestdist table
                forestdist = {}
                l_a = leftmost_a[kr_a]
                l_b = leftmost_b[kr_b]
                
                forestdist[(l_a - 1, l_b - 1)] = 0
                for i in range(l_a, kr_a + 1):
                    forestdist[(i, l_b - 1)] = forestdist[(i - 1, l_b - 1)] + 1
                for j in range(l_b, kr_b + 1):
                    forestdist[(l_a - 1, j)] = forestdist[(l_a - 1, j - 1)] + 1
                    
                for i in range(l_a, kr_a + 1):
                    for j in range(l_b, kr_b + 1):
                        cost = 0 if nodes_a[i - 1].label == nodes_b[j - 1].label else 1
                        
                        if leftmost_a[i] == l_a and leftmost_b[j] == l_b:
                            forestdist[(i, j)] = min(
                                forestdist[(i - 1, j)] + 1,
                                forestdist[(i, j - 1)] + 1,
                                forestdist[(i - 1, j - 1)] + cost
                            )
                            treedist[(i, j)] = forestdist[(i, j)]
                        else:
                            forestdist[(i, j)] = min(
                                forestdist[(i - 1, j)] + 1,
                                forestdist[(i, j - 1)] + 1,
                                forestdist[(leftmost_a[i] - 1, leftmost_b[j] - 1)] + treedist.get((i, j), cost)
                            )
                            
        return treedist.get((len_a, len_b), max(len_a, len_b))

    @staticmethod
    def calculate_similarity(html_a: str, html_b: str) -> float:
        """Calculates DOM Tree similarity using the Zhang-Shasha Tree Edit Distance (TED)."""
        tree_a = DOMSequenceAligner.html_to_tree(html_a)
        tree_b = DOMSequenceAligner.html_to_tree(html_b)
        
        len_a = len(DOMSequenceAligner.get_postorder(tree_a))
        len_b = len(DOMSequenceAligner.get_postorder(tree_b))
        
        max_nodes = max(len_a, len_b)
        if max_nodes == 0:
            return 1.0
            
        dist = DOMSequenceAligner.tree_edit_distance(tree_a, tree_b)
        return 1.0 - (dist / max_nodes)

