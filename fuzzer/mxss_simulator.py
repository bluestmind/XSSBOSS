import re
from typing import List, Dict, Any, Tuple

class MXSSSimulator:
    """Simulates HTML5 / SVG / MathML namespace round-tripping to identify parser mutation differentials."""

    @staticmethod
    def parse_to_tree(html: str) -> List[Dict[str, Any]]:
        """Parses a stateful HTML/SVG structure into a node tree simulating browser CDATA/RAWTEXT transitions."""
        # Regex matching tags, comments, or text
        pattern = re.compile(r'(<!--.*?-->|<[^>]+>|[^<]+)', re.DOTALL)
        tokens = pattern.findall(html)
        
        tree: List[Dict[str, Any]] = []
        stack: List[Dict[str, Any]] = []
        
        current_namespace = "html"
        
        # HTML5 parsing rawtext/rcdata states
        rcdata_tags = {"title", "textarea"}
        rawtext_tags = {"style", "xmp", "iframe", "noembed", "noframes", "noscript"}
        
        text_mode = None  # can be 'rawtext', 'rcdata', or 'plaintext'
        text_mode_tag = None
        
        for token in tokens:
            token = token.strip()
            if not token:
                continue
                
            if token.startswith("<!--") and text_mode is None:
                continue
                
            if token.startswith("<") and token.endswith(">"):
                is_closing = token.startswith("</")
                tag_content = token[2:-1] if is_closing else token[1:-1]
                
                # Extract tag name
                tag_parts = tag_content.split()
                tag_name = tag_parts[0].lower() if tag_parts else ""
                
                # If we are in rawtext/rcdata mode, ignore all tags except the closing trigger tag
                if text_mode is not None:
                    if is_closing and tag_name == text_mode_tag:
                        # Exit text mode
                        text_mode = None
                        text_mode_tag = None
                        if stack and stack[-1]["tag"] == tag_name:
                            stack.pop()
                            current_namespace = stack[-1]["namespace"] if stack else "html"
                    else:
                        # Treat tag as raw text inside CDATA/RCDATA parent
                        node = {
                            "tag": "#text",
                            "namespace": current_namespace,
                            "text": token
                        }
                        if stack:
                            stack[-1]["children"].append(node)
                        else:
                            tree.append(node)
                    continue
                
                if is_closing:
                    # Pop from stack to match tag name
                    if stack and stack[-1]["tag"] == tag_name:
                        stack.pop()
                        current_namespace = stack[-1]["namespace"] if stack else "html"
                else:
                    # Check namespace transitions
                    if tag_name in ["svg", "math"]:
                        current_namespace = tag_name
                    elif tag_name in ["foreignobject"]:
                        current_namespace = "html"
                        
                    node = {
                        "tag": tag_name,
                        "namespace": current_namespace,
                        "attributes": tag_parts[1:] if len(tag_parts) > 1 else [],
                        "children": []
                    }
                    
                    if stack:
                        stack[-1]["children"].append(node)
                    else:
                        tree.append(node)
                        
                    # Handle rawtext / rcdata / plaintext state triggers
                    if tag_name in rawtext_tags:
                        text_mode = "rawtext"
                        text_mode_tag = tag_name
                    elif tag_name in rcdata_tags:
                        text_mode = "rcdata"
                        text_mode_tag = tag_name
                    elif tag_name == "plaintext":
                        text_mode = "plaintext"
                        text_mode_tag = "plaintext"
                        
                    # Self-closing tags do not push to stack
                    if not token.endswith("/>") and tag_name not in ["img", "br", "hr", "input", "meta", "link"]:
                        stack.append(node)
            else:
                # Text node
                node = {
                    "tag": "#text",
                    "namespace": current_namespace,
                    "text": token
                }
                if stack:
                    stack[-1]["children"].append(node)
                else:
                    tree.append(node)
                    
        return tree

    @staticmethod
    def serialize_tree(tree: List[Dict[str, Any]]) -> str:
        """Serializes the parsed node tree back into a standard HTML markup representation."""
        output = []
        for node in tree:
            if node["tag"] == "#text":
                output.append(node.get("text", ""))
            else:
                attrs = " " + " ".join(node["attributes"]) if node["attributes"] else ""
                tag = node["tag"]
                if tag in ["img", "br", "hr", "input", "meta", "link"]:
                    output.append(f"<{tag}{attrs}>")
                else:
                    children_str = MXSSSimulator.serialize_tree(node["children"])
                    output.append(f"<{tag}{attrs}>{children_str}</{tag}>")
        return "".join(output)

    @staticmethod
    def check_mutation_differential(html: str) -> float:
        """Runs the parse-serialize-parse round-trip simulation.
        
        Returns a score from 0.0 (no differential) to 100.0 (significant structural mutation).
        """
        try:
            # First pass: parse original HTML to tree
            tree_a = MXSSSimulator.parse_to_tree(html)
            # Serialize tree back to markup
            serialized_a = MXSSSimulator.serialize_tree(tree_a)
            # Second pass: re-parse serialized markup to tree
            tree_b = MXSSSimulator.parse_to_tree(serialized_a)
            
            # Compare structural counts
            def count_tags(nodes: List[Dict[str, Any]]) -> List[str]:
                tags = []
                for n in nodes:
                    if n["tag"] != "#text":
                        tags.append(n["tag"])
                        tags.extend(count_tags(n["children"]))
                return tags
                
            tags_a = count_tags(tree_a)
            tags_b = count_tags(tree_b)
            
            if len(tags_a) != len(tags_b):
                # Tag counts mismatch: elements were created or destroyed during round-trip
                return 80.0
                
            for t_a, t_b in zip(tags_a, tags_b):
                if t_a != t_b:
                    # Tag name changed (e.g. namespace transformation/nesting change)
                    return 100.0
                    
            if serialized_a != html:
                # Text/attribute differences existed (potential parser confusion)
                return 40.0
                
            return 0.0
        except Exception:
            return 0.0
