from __future__ import annotations

from xsscollector.js_analysis import JavaScriptAnalyzer


FRONTEND = r'''
import DOMPurify from "dompurify";
export async function render(target, { fallback = "" } = {}) {
  const name = new URLSearchParams(location.search).get("name");
  const clean = DOMPurify.sanitize(name);
  target.innerHTML = clean;
  target.outerHTML = name;
  await fetch("/api/log", { method: "POST", body: name });
  return { clean, name };
}
const navigate = (url: string = "/") => window.location.href = url;
class Controller {
  handle(event) {
    const payload = event.data;
    document.write(payload);
  }
}
items.map((item) => item.value);
// ignored.innerHTML = location.hash;
const text = "eval(location.hash)";
//# sourceMappingURL=app.js.map
'''


def test_discovers_functions_inputs_outputs_calls_and_modules() -> None:
    result = JavaScriptAnalyzer.analyze(FRONTEND, "https://example.com/app.js")
    names = {item.qualified_name for item in result.functions}
    assert "render" in names
    assert "navigate" in names
    assert "Controller.handle" in names
    assert any(name.startswith("<callback@") for name in names)
    assert any(item.function == "render" and item.name == "target" for item in result.inputs)
    assert any(item.function == "render" and item.kind == "destructured" for item in result.inputs)
    assert any(item.function == "render" and item.kind == "return" for item in result.outputs)
    assert any(item.caller == "render" and item.callee == "fetch" and item.awaited for item in result.calls)
    assert result.modules[0].module == "dompurify"
    assert "render" in result.exports
    assert result.source_map_url == "app.js.map"


def test_catalogues_sources_sinks_and_sanitized_flows() -> None:
    result = JavaScriptAnalyzer.analyze(FRONTEND, "https://example.com/app.js")
    assert any(item.function == "render" and item.kind == "url-parameter" and item.input_name == "name" for item in result.sources)
    assert any(item.function == "Controller.handle" and item.kind == "message-data" for item in result.sources)
    assert not any(item.function == "navigate" and item.kind == "location" for item in result.sources)
    assert any(item.function == "render" and item.kind == "innerHTML" for item in result.sinks)
    assert any(item.function == "render" and item.kind == "outerHTML" for item in result.sinks)
    assert any(item.function == "Controller.handle" and item.kind == "document.write" for item in result.sinks)
    assert not any(item.line == 19 for item in result.sinks)
    assert any(item.sink_kind == "innerHTML" and item.sanitized for item in result.flows)
    assert any(item.sink_kind == "outerHTML" and not item.sanitized for item in result.flows)
    assert any(item.sink_kind == "document.write" and item.source_kind == "message-data" for item in result.flows)


def test_node_inputs_and_output_sinks() -> None:
    code = '''
const cp = require("child_process");
module.exports.run = function run(req, res) {
  const command = req.body.command;
  const output = cp.exec(command);
  res.send(output);
  return output;
};
'''
    result = JavaScriptAnalyzer.analyze(code, "server.js")
    assert result.module_kind == "commonjs"
    assert any(item.kind == "node-request" and item.input_name == "command" for item in result.sources)
    assert any(item.kind == "command-exec" for item in result.sinks)
    assert any(item.kind == "response-send" for item in result.sinks)
    assert any(item.sink_kind == "command-exec" for item in result.flows)
    assert "run" in result.exports
