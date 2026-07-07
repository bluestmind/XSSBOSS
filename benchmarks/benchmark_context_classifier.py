"""
XSSBOSS Context Classifier Accuracy Benchmark.

Measures precision, recall, and F1 across all ContextType values using a labeled
corpus of HTML documents. Each test case has a known ground-truth context type,
and the benchmark checks whether EnhancedContextClassifier returns the correct
classification.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from analysis_engine.enhanced_context_classifier import EnhancedContextClassifier
from backend_api.models.context import ContextType


MARKER = "xB0ss_CTX_PROBE_7k"


@dataclass
class LabeledSample:
    """A labeled HTML document with a known context classification."""
    name: str
    html_template: str  # Contains {MARKER}
    expected_context: str  # ContextType value
    expected_tag: Optional[str] = None
    expected_attribute: Optional[str] = None
    description: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Labeled corpus: 50+ samples covering all major context types
# ─────────────────────────────────────────────────────────────────────────────

LABELED_CORPUS: List[LabeledSample] = [
    # === HTML_TEXT ===
    LabeledSample("CTX-01", f"<div>{MARKER}</div>", "HTML_TEXT", expected_tag="div",
                  description="Basic HTML text node inside div"),
    LabeledSample("CTX-02", f"<p>Hello {MARKER} world</p>", "HTML_TEXT", expected_tag="p",
                  description="HTML text inside paragraph"),
    LabeledSample("CTX-03", f"<span class='result'>{MARKER}</span>", "HTML_TEXT", expected_tag="span",
                  description="HTML text inside span"),
    LabeledSample("CTX-04", f"<li>{MARKER}</li>", "HTML_TEXT", expected_tag="li",
                  description="HTML text inside list item"),

    # === ATTR_QUOTED ===
    LabeledSample("CTX-05", f'<input value="{MARKER}">', "ATTR_QUOTED",
                  expected_tag="input", expected_attribute="value",
                  description="Double-quoted attribute value"),
    LabeledSample("CTX-06", f"<input value='{MARKER}'>", "ATTR_QUOTED",
                  expected_tag="input", expected_attribute="value",
                  description="Single-quoted attribute value"),
    LabeledSample("CTX-07", f'<a href="{MARKER}">link</a>', "ATTR_QUOTED",
                  expected_tag="a", expected_attribute="href",
                  description="Quoted href attribute"),
    LabeledSample("CTX-08", f'<img src="{MARKER}" alt="test">', "ATTR_QUOTED",
                  expected_tag="img", expected_attribute="src",
                  description="Quoted src attribute on img"),

    # === ATTR_UNQUOTED ===
    LabeledSample("CTX-09", f"<img src=x data-val={MARKER} alt=test>", "ATTR_UNQUOTED",
                  expected_tag="img", expected_attribute="data-val",
                  description="Unquoted data attribute"),

    # === EVENT_HANDLER_ATTR ===
    LabeledSample("CTX-10", f'<div onclick="{MARKER}">click</div>', "EVENT_HANDLER_ATTR",
                  expected_tag="div", expected_attribute="onclick",
                  description="onclick event handler attribute"),
    LabeledSample("CTX-11", f'<img onerror="{MARKER}" src=x>', "EVENT_HANDLER_ATTR",
                  expected_tag="img", expected_attribute="onerror",
                  description="onerror event handler attribute"),
    LabeledSample("CTX-12", f'<body onload="{MARKER}">', "EVENT_HANDLER_ATTR",
                  expected_tag="body", expected_attribute="onload",
                  description="onload event handler"),

    # === HTML_COMMENT ===
    LabeledSample("CTX-13", f"<!-- user comment: {MARKER} -->", "HTML_COMMENT",
                  description="HTML comment context"),
    LabeledSample("CTX-14", f"<!-- {MARKER} --><div>content</div>", "HTML_COMMENT",
                  description="HTML comment before content"),

    # === JS_STRING_LITERAL ===
    LabeledSample("CTX-15", f'<script>var x = "{MARKER}";</script>', "JS_STRING_LITERAL",
                  description="JS double-quoted string in script block"),
    LabeledSample("CTX-16", f"<script>var x = '{MARKER}';</script>", "JS_STRING_LITERAL",
                  description="JS single-quoted string in script block"),
    LabeledSample("CTX-17", f'<script>console.log("{MARKER}");</script>', "JS_STRING_LITERAL",
                  description="JS string inside function call"),

    # === JS_TEMPLATE_LITERAL ===
    LabeledSample("CTX-18", f"<script>var x = `Hello {MARKER}`;</script>", "JS_TEMPLATE_LITERAL",
                  description="JS template literal with backticks"),

    # === JSON_IN_SCRIPT ===
    LabeledSample("CTX-19", f'<script type="application/json">{{"user": "{MARKER}"}}</script>',
                  "JSON_IN_SCRIPT", description="JSON inside script type=application/json"),

    # === CSS_STYLE_BLOCK ===
    LabeledSample("CTX-20", f'<style>body {{ font-family: "{MARKER}"; }}</style>', "CSS_STYLE_BLOCK",
                  description="CSS property value in style block"),
    LabeledSample("CTX-21", f'<style>.user {{ color: {MARKER}; }}</style>', "CSS_STYLE_BLOCK",
                  description="CSS property value (unquoted) in style block"),

    # === CSS_INLINE_STYLE ===
    LabeledSample("CTX-22", f'<div style="color: {MARKER}">text</div>', "CSS_INLINE_STYLE",
                  expected_tag="div", expected_attribute="style",
                  description="Inline style attribute"),

    # === URL_QUERY ===
    LabeledSample("CTX-23", f'<a href="/search?q={MARKER}">search</a>', "URL_QUERY",
                  expected_tag="a", expected_attribute="href",
                  description="URL query parameter in href"),
    LabeledSample("CTX-24", f'<form action="/submit?token={MARKER}"></form>', "URL_QUERY",
                  expected_tag="form", expected_attribute="action",
                  description="URL query parameter in form action"),

    # === HTML_RCDATA ===
    LabeledSample("CTX-25", f"<title>{MARKER}</title>", "HTML_RCDATA",
                  expected_tag="title", description="Title RCDATA context"),
    LabeledSample("CTX-26", f"<textarea>{MARKER}</textarea>", "HTML_RCDATA",
                  expected_tag="textarea", description="Textarea RCDATA context"),

    # === SVG contexts ===
    LabeledSample("CTX-27", f"<svg><text>{MARKER}</text></svg>", "SVG_TEXT",
                  expected_tag="text", description="SVG text element"),
    LabeledSample("CTX-28", f"<svg><script>{MARKER}</script></svg>", "SVG_SCRIPT",
                  expected_tag="script", description="SVG script element"),

    # === MATHML contexts ===
    LabeledSample("CTX-29", f"<math><mtext>{MARKER}</mtext></math>", "MATHML_TEXT",
                  expected_tag="mtext", description="MathML mtext element"),
    LabeledSample("CTX-30", f'<math><annotation-xml encoding="text/html">{MARKER}</annotation-xml></math>',
                  "ANNOTATION_XML", expected_tag="annotation-xml",
                  description="MathML annotation-xml with text/html encoding"),

    # === CSTI contexts ===
    LabeledSample("CTX-31", f"<div ng-app>{{{{{MARKER}}}}}</div>", "CSTI_ANGULAR",
                  description="Angular template expression"),
    LabeledSample("CTX-32", f"<div v-html=\"{MARKER}\"></div>", "CSTI_VUE",
                  expected_tag="div", expected_attribute="v-html",
                  description="Vue v-html directive"),

    # === Edge cases ===
    LabeledSample("CTX-33", f"<div>{MARKER}<script>var a = 1;</script></div>", "HTML_TEXT",
                  expected_tag="div", description="HTML text before script block"),
    LabeledSample("CTX-34", f'<input type="hidden" name="csrf" value="{MARKER}">', "ATTR_QUOTED",
                  expected_tag="input", expected_attribute="value",
                  description="Hidden input value attribute"),
    LabeledSample("CTX-35", f'<meta content="{MARKER}" name="description">', "ATTR_QUOTED",
                  expected_tag="meta", expected_attribute="content",
                  description="Meta tag content attribute"),
    LabeledSample("CTX-36", f'<script>var config = {{"key": "{MARKER}"}};</script>', "JS_STRING_LITERAL",
                  description="JS object literal string value"),
    LabeledSample("CTX-37", f'<div data-config=\'{{"val":"{MARKER}"}}\'>content</div>', "ATTR_QUOTED",
                  expected_tag="div", expected_attribute="data-config",
                  description="JSON inside single-quoted data attribute"),
    LabeledSample("CTX-38", f"<iframe srcdoc=\"{MARKER}\"></iframe>", "SRC_DOC_ATTR",
                  expected_tag="iframe", expected_attribute="srcdoc",
                  description="srcdoc attribute (double HTML decoding)"),

    # === Nested namespace edge cases ===
    LabeledSample("CTX-39", f"<svg><foreignObject><div>{MARKER}</div></foreignObject></svg>",
                  "HTML_TEXT", expected_tag="div",
                  description="HTML inside SVG foreignObject"),
    LabeledSample("CTX-40", f"<math><mtext><span>{MARKER}</span></mtext></math>",
                  "MATHML_TEXT", expected_tag="span",
                  description="HTML inside MathML mtext"),

    # === Multiple reflections ===
    LabeledSample("CTX-41", f'<div>{MARKER}</div><input value="{MARKER}">',
                  "HTML_TEXT", description="Multiple reflections — first should be HTML_TEXT"),
    LabeledSample("CTX-42", f'<script>var a = "{MARKER}"; var b = "{MARKER}";</script>',
                  "JS_STRING_LITERAL", description="Multiple JS string reflections"),

    # === HTML_RAW_TEXT ===
    LabeledSample("CTX-43", f"<xmp>{MARKER}</xmp>", "HTML_RAW_TEXT",
                  expected_tag="xmp", description="XMP raw text context"),

    # === JS_COMMENT ===
    LabeledSample("CTX-44", f"<script>// user: {MARKER}\nvar x = 1;</script>", "JS_COMMENT",
                  description="JS single-line comment"),
    LabeledSample("CTX-45", f"<script>/* comment: {MARKER} */</script>", "JS_COMMENT",
                  description="JS multi-line comment"),

    # === More attribute variants ===
    LabeledSample("CTX-46", f'<link rel="stylesheet" href="{MARKER}">', "ATTR_QUOTED",
                  expected_tag="link", expected_attribute="href",
                  description="Link tag href attribute"),
    LabeledSample("CTX-47", f'<source src="{MARKER}" type="video/mp4">', "ATTR_QUOTED",
                  expected_tag="source", expected_attribute="src",
                  description="Source tag src attribute"),
    LabeledSample("CTX-48", f'<button formaction="{MARKER}">submit</button>', "ATTR_QUOTED",
                  expected_tag="button", expected_attribute="formaction",
                  description="Button formaction attribute"),

    # === Deep nesting ===
    LabeledSample("CTX-49", f"<div><ul><li><span>{MARKER}</span></li></ul></div>", "HTML_TEXT",
                  expected_tag="span", description="Deeply nested HTML text"),
    LabeledSample("CTX-50", f'<table><tr><td onclick="{MARKER}">cell</td></tr></table>',
                  "EVENT_HANDLER_ATTR", expected_tag="td", expected_attribute="onclick",
                  description="Event handler in table cell"),
]


class ContextClassifierBenchmark:
    """Benchmark measuring context classification accuracy."""

    def run(self) -> Dict[str, Any]:
        """Run the classifier benchmark across all labeled samples."""
        start_time = time.time()
        results: List[Dict[str, Any]] = []
        per_type_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
        correct = 0
        total = 0

        for sample in LABELED_CORPUS:
            res = self._test_sample(sample)
            results.append(res)
            total += 1

            expected = sample.expected_context
            actual = res["detected_context"]

            if actual == expected:
                correct += 1
                per_type_stats[expected]["tp"] += 1
            else:
                per_type_stats[expected]["fn"] += 1
                if actual:
                    per_type_stats[actual]["fp"] += 1

        elapsed = time.time() - start_time
        accuracy = (correct / total * 100.0) if total else 0.0

        # Calculate per-type metrics
        per_type_metrics = {}
        for ctx_type, stats in per_type_stats.items():
            tp = stats["tp"]
            fp = stats["fp"]
            fn = stats["fn"]
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            per_type_metrics[ctx_type] = {
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1": round(f1, 3),
                "tp": tp, "fp": fp, "fn": fn,
            }

        return {
            "benchmark": "Context Classifier Accuracy",
            "total_samples": total,
            "correct": correct,
            "accuracy": round(accuracy, 1),
            "target_accuracy": 90.0,
            "passed": accuracy >= 90.0,
            "elapsed_seconds": elapsed,
            "per_type_metrics": per_type_metrics,
            "details": results,
        }

    def _test_sample(self, sample: LabeledSample) -> Dict[str, Any]:
        """Classify a single labeled sample and compare to ground truth."""
        html_content = sample.html_template
        contexts = EnhancedContextClassifier.classify_all_reflections(html_content, MARKER)

        detected_context = None
        detected_tag = None
        detected_attr = None

        if contexts:
            # Use the first detected context
            ctx = contexts[0]
            detected_context = ctx.context_type.value if isinstance(ctx.context_type, ContextType) else str(ctx.context_type)
            detected_tag = ctx.tag
            detected_attr = ctx.attribute

        match = detected_context == sample.expected_context

        return {
            "sample": sample.name,
            "expected_context": sample.expected_context,
            "detected_context": detected_context,
            "expected_tag": sample.expected_tag,
            "detected_tag": detected_tag,
            "match": match,
            "description": sample.description,
        }


if __name__ == "__main__":
    benchmark = ContextClassifierBenchmark()
    summary = benchmark.run()

    print("\n" + "=" * 70)
    print("     XSSBOSS CONTEXT CLASSIFIER ACCURACY BENCHMARK")
    print("=" * 70)
    print(f"Total Samples: {summary['total_samples']}")
    print(f"Correct:       {summary['correct']}")
    print(f"Accuracy:      {summary['accuracy']}% (target: ≥{summary['target_accuracy']}%)")
    print(f"Passed:        {'✅ YES' if summary['passed'] else '❌ NO'}")
    print(f"Elapsed:       {summary['elapsed_seconds']:.2f}s")
    print("-" * 70)

    print("\nPer-Type Metrics:")
    print(f"  {'Context Type':<25} {'Prec':>6} {'Rec':>6} {'F1':>6} {'TP':>4} {'FP':>4} {'FN':>4}")
    print("  " + "-" * 60)
    for ctx_type, m in sorted(summary["per_type_metrics"].items()):
        print(f"  {ctx_type:<25} {m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4}")

    print("\nMisclassifications:")
    for r in summary["details"]:
        if not r["match"]:
            print(f"  ❌ {r['sample']}: expected {r['expected_context']}, got {r['detected_context']}")
            print(f"     {r['description']}")
