"""Smart taint analyzer — proves source→sink data flow, not name proximity."""
from analysis_engine.smart_taint_analyzer import (
    Reachability,
    SmartTaintAnalyzer,
    prioritized_injection_targets,
)


def _find(js, sink=None, source=None):
    for f in SmartTaintAnalyzer.analyze(js):
        if (sink is None or f.sink_kind == sink) and (source is None or f.source_param == source):
            return f
    return None


# ------------------------------------------------------------- direct flow

def test_direct_source_to_innerHTML():
    js = "document.getElementById('out').innerHTML = location.hash;"
    f = _find(js, sink="innerHTML")
    assert f and f.reachability is Reachability.REACHABLE
    assert f.source_param == "hash"
    assert f.context == "HTML_TEXT"


def test_url_param_flows_through_variables():
    js = """
      var p = new URLSearchParams(location.search).get('q');
      var msg = 'Hello ' + p + '!';
      el.innerHTML = msg;
    """
    f = _find(js, sink="innerHTML")
    assert f and f.reachability is Reachability.REACHABLE
    assert f.source_param == "q"          # traced back through msg -> p -> get('q')
    assert f.hops >= 2


def test_eval_of_tainted_is_critical():
    js = "var cb = new URLSearchParams(location.search).get('callback'); eval(cb);"
    f = _find(js, sink="eval")
    assert f and f.reachability is Reachability.REACHABLE
    assert f.severity == "critical" and f.context == "JS_BLOCK"
    assert f.source_param == "callback"


def test_postmessage_to_document_write():
    js = "window.addEventListener('message', function(e){ document.write(e.data); });"
    f = _find(js, sink="document_write")
    assert f and f.reachability is Reachability.REACHABLE
    assert f.source_kind == "postmessage"


def test_jquery_html_sink():
    js = "$('#box').html(location.hash);"
    f = _find(js, sink="jquery_html")
    assert f and f.reachability is Reachability.REACHABLE


def test_navigation_sink_from_param():
    js = "location.href = new URLSearchParams(location.search).get('next');"
    f = _find(js, sink="navigation")
    assert f and f.reachability is Reachability.REACHABLE
    assert f.source_param == "next" and f.context == "URL_HREF"


# ------------------------------------------------------------- sanitizer awareness

def test_sanitized_flow_is_not_reachable():
    js = "el.innerHTML = DOMPurify.sanitize(location.hash);"
    f = _find(js, sink="innerHTML")
    assert f and f.reachability is Reachability.SANITIZED
    assert f.confidence < 0.4


def test_encoded_param_is_downgraded():
    js = """
      var raw = new URLSearchParams(location.search).get('u');
      var safe = encodeURIComponent(raw);
      location.href = safe;
    """
    f = _find(js, sink="navigation")
    assert f and f.reachability is Reachability.SANITIZED


# ------------------------------------------------------------- don't test dead sinks

def test_static_sink_produces_no_finding():
    js = "el.innerHTML = '<b>Welcome</b>';"
    assert SmartTaintAnalyzer.analyze(js) == []      # no user data -> nothing to test


def test_untainted_local_is_not_flagged():
    js = "var title = getConfig().title; el.innerHTML = title;"
    # `getConfig()` is not a known source, so this must NOT be reported as reachable.
    assert not any(f.reachability is Reachability.REACHABLE for f in SmartTaintAnalyzer.analyze(js))


# ------------------------------------------------------------- prioritized targets

def test_prioritized_targets_only_reachable_best_first():
    js = """
      var q = new URLSearchParams(location.search).get('q');
      el.innerHTML = q;                             // reachable
      other.innerHTML = DOMPurify.sanitize(q);      // sanitized
      static.innerHTML = 'hi';                       // dead
    """
    targets = prioritized_injection_targets(js)
    assert targets, "expected at least one reachable target"
    assert all(t["reachability"] == "reachable" for t in targets)
    assert targets[0]["source_param"] == "q"
    assert targets[0]["confidence"] >= targets[-1]["confidence"]
