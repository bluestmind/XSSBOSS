"""Smart context resolver — proven sink -> correct injection context + priority boost."""
from analysis_engine.smart_context_resolver import SmartContextResolver as R


def test_sink_to_context_mapping():
    assert R.context_for_sink("eval") == "JS_STRING_LITERAL"       # JS code, not HTML
    assert R.context_for_sink("innerHTML") == "HTML_TEXT"
    assert R.context_for_sink("navigation") == "URL_QUERY"          # href/assign
    assert R.context_for_sink("srcdoc") == "SRC_DOC_ATTR"
    assert R.context_for_sink("nope") is None


def test_resolve_gives_js_context_for_eval_param():
    js = "var cb = new URLSearchParams(location.search).get('callback'); eval(cb);"
    res = R.resolve(js)
    assert "callback" in res
    top = res["callback"][0]
    assert top["context"] == "JS_STRING_LITERAL"       # would have been blind HTML_TEXT before
    assert top["reachability"] == "reachable"


def test_contexts_for_param_reachable_only():
    js = """
      var a = new URLSearchParams(location.search).get('x');
      el.innerHTML = a;                                // reachable HTML
      location.href = encodeURIComponent(a);           // sanitized URL
    """
    reachable = R.contexts_for_param(js, "x", reachable_only=True)
    assert reachable == ["HTML_TEXT"]                  # sanitized URL flow excluded
    allctx = R.contexts_for_param(js, "x", reachable_only=False)
    assert "URL_QUERY" in allctx and "HTML_TEXT" in allctx


def test_priority_boost_ordering():
    hi = R.priority_boost("reachable", 0.9)
    lo = R.priority_boost("sanitized", 0.9)
    none = R.priority_boost("unreachable", 0.9)
    assert hi > lo > none
    assert 40 <= hi <= 80


def test_best_boost_for_param():
    js = "var q = new URLSearchParams(location.search).get('q'); eval(q);"
    assert R.best_boost_for_param(js, "q") >= 40      # eval flow is high-value
    assert R.best_boost_for_param(js, "absent") == 0
