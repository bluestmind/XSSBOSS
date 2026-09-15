"""Dependency-free structural JavaScript/TypeScript inventory and light taint analysis.

This module is intentionally static and non-executing. It inventories every construct it can
identify and labels confidence; it never claims that heuristic reachability proves exploitability.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


@dataclass(slots=True)
class JSFunction:
    name: str
    qualified_name: str
    kind: str
    parameters: list[str]
    start: int
    end: int
    start_line: int
    end_line: int
    async_flag: bool = False
    generator: bool = False
    exported: bool = False
    body_hash: str = ""
    complexity: int = 1


@dataclass(slots=True)
class JSInput:
    function: str
    name: str
    kind: str
    default_value: str | None
    type_hint: str | None
    line: int


@dataclass(slots=True)
class JSOutput:
    function: str
    kind: str
    expression: str
    line: int
    ordinal: int


@dataclass(slots=True)
class JSSource:
    function: str
    kind: str
    expression: str
    variable: str | None
    input_name: str | None
    line: int
    confidence: float


@dataclass(slots=True)
class JSSink:
    function: str
    kind: str
    category: str
    expression: str
    value_expression: str
    line: int
    severity: str
    confidence: float


@dataclass(slots=True)
class JSCall:
    caller: str
    callee: str
    arguments: list[str]
    line: int
    awaited: bool
    optional: bool


@dataclass(slots=True)
class JSFlow:
    function: str
    source_kind: str
    source_name: str
    sink_kind: str
    sink_expression: str
    path: list[str]
    line: int
    confidence: float
    sanitized: bool


@dataclass(slots=True)
class JSModuleReference:
    kind: str
    module: str
    names: list[str]
    line: int


@dataclass(slots=True)
class JSAnalysis:
    file_url: str
    sha256: str
    size_bytes: int
    module_kind: str
    source_map_url: str | None
    functions: list[JSFunction] = field(default_factory=list)
    inputs: list[JSInput] = field(default_factory=list)
    outputs: list[JSOutput] = field(default_factory=list)
    sources: list[JSSource] = field(default_factory=list)
    sinks: list[JSSink] = field(default_factory=list)
    calls: list[JSCall] = field(default_factory=list)
    flows: list[JSFlow] = field(default_factory=list)
    modules: list[JSModuleReference] = field(default_factory=list)
    globals: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "file_url": self.file_url, "sha256": self.sha256, "size_bytes": self.size_bytes,
            "module_kind": self.module_kind, "source_map_url": self.source_map_url,
            "functions": [asdict(item) for item in self.functions],
            "inputs": [asdict(item) for item in self.inputs],
            "outputs": [asdict(item) for item in self.outputs],
            "sources": [asdict(item) for item in self.sources],
            "sinks": [asdict(item) for item in self.sinks],
            "calls": [asdict(item) for item in self.calls],
            "flows": [asdict(item) for item in self.flows],
            "modules": [asdict(item) for item in self.modules],
            "globals": self.globals, "exports": self.exports, "parse_warnings": self.parse_warnings,
        }


@dataclass(frozen=True, slots=True)
class _Pattern:
    kind: str
    category: str
    regex: re.Pattern[str]
    severity: str = "info"
    confidence: float = 0.9


SOURCE_PATTERNS = [
    _Pattern("url-parameter", "request", re.compile(r"(?:URLSearchParams\s*\([^)]*\)|searchParams|urlParams|query|params)\s*(?:\.\s*get\s*\(|\[)", re.I), confidence=0.9),
    _Pattern("location", "browser", re.compile(r"(?:window\s*\.\s*)?location\s*\.\s*(?:hash|search|href|pathname|origin)\b(?!\s*=)", re.I)),
    _Pattern("document-url", "browser", re.compile(r"document\s*\.\s*(?:URL|documentURI|referrer|baseURI)\b", re.I)),
    _Pattern("cookie-read", "browser", re.compile(r"document\s*\.\s*cookie\b(?!\s*=)", re.I)),
    _Pattern("window-name", "browser", re.compile(r"window\s*\.\s*name\b", re.I)),
    _Pattern("message-data", "event", re.compile(r"(?:event|evt|ev|e|message|msg)\s*\.\s*data\b", re.I), confidence=0.8),
    _Pattern("storage-read", "storage", re.compile(r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|key)\s*\(", re.I)),
    _Pattern("dom-input", "dom", re.compile(r"(?:querySelector|getElementById|getElementsByName|currentTarget|target)[^;\n]{0,160}\.(?:value|checked|files|textContent)\b", re.I), confidence=0.75),
    _Pattern("form-data", "dom", re.compile(r"new\s+FormData\s*\(|FormData\s*\.\s*get\s*\(", re.I)),
    _Pattern("node-request", "server", re.compile(r"(?:req|request|ctx)\s*\.\s*(?:body|query|params|headers|cookies|path|url)\b", re.I)),
    _Pattern("environment", "process", re.compile(r"process\s*\.\s*env(?:\s*\.|\s*\[)", re.I)),
    _Pattern("argv", "process", re.compile(r"process\s*\.\s*argv\b", re.I)),
    _Pattern("stdin", "process", re.compile(r"process\s*\.\s*stdin\b", re.I)),
]

SINK_PATTERNS = [
    _Pattern("innerHTML", "html-injection", re.compile(r"\.\s*innerHTML\s*=(?!=)", re.I), "high"),
    _Pattern("outerHTML", "html-injection", re.compile(r"\.\s*outerHTML\s*=(?!=)", re.I), "high"),
    _Pattern("insertAdjacentHTML", "html-injection", re.compile(r"\.\s*insertAdjacentHTML\s*\(", re.I), "high"),
    _Pattern("document.write", "html-injection", re.compile(r"document\s*\.\s*write(?:ln)?\s*\(", re.I), "high"),
    _Pattern("dangerouslySetInnerHTML", "html-injection", re.compile(r"\bdangerouslySetInnerHTML\s*=|\bdangerouslySetInnerHTML\s*:", re.I), "high"),
    _Pattern("srcdoc", "html-injection", re.compile(r"\.\s*srcdoc\s*=(?!=)", re.I), "high"),
    _Pattern("createContextualFragment", "html-injection", re.compile(r"\.\s*createContextualFragment\s*\(", re.I), "high"),
    _Pattern("DOMParser.parseFromString", "html-parser", re.compile(r"(?:DOMParser\s*\(\s*\)|[\w$]+)\s*\.\s*parseFromString\s*\(", re.I), "medium"),
    _Pattern("eval", "code-execution", re.compile(r"(?<![\w$.])eval\s*\(", re.I), "critical"),
    _Pattern("Function", "code-execution", re.compile(r"(?:new\s+)?Function\s*\(", re.I), "critical"),
    _Pattern("timer-string", "code-execution", re.compile(r"\bset(?:Timeout|Interval)\s*\(", re.I), "high"),
    _Pattern("textContent", "dom-text-output", re.compile(r"\.\s*textContent\s*=(?!=)", re.I), "info", 0.8),
    _Pattern("location-write", "navigation", re.compile(r"(?:window\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?!=)", re.I), "medium"),
    _Pattern("location-call", "navigation", re.compile(r"(?:window\s*\.\s*)?location\s*\.\s*(?:assign|replace)\s*\(", re.I), "medium"),
    _Pattern("window.open", "navigation", re.compile(r"window\s*\.\s*open\s*\(", re.I), "medium"),
    _Pattern("setAttribute", "dom-attribute", re.compile(r"\.\s*setAttribute(?:NS)?\s*\(", re.I), "medium", 0.8),
    _Pattern("jquery-html", "html-injection", re.compile(r"\.\s*(?:html|append|prepend|before|after|replaceWith|wrap)\s*\(", re.I), "high", 0.75),
    _Pattern("fetch", "network-output", re.compile(r"(?<![\w$.])fetch\s*\(", re.I), "info"),
    _Pattern("axios", "network-output", re.compile(r"\baxios\s*(?:\.\s*(?:get|post|put|patch|delete|request))?\s*\(", re.I), "info"),
    _Pattern("xhr-open", "network-output", re.compile(r"\.\s*open\s*\(", re.I), "info", 0.65),
    _Pattern("xhr-send", "network-output", re.compile(r"\.\s*send\s*\(", re.I), "info", 0.65),
    _Pattern("WebSocket", "network-output", re.compile(r"new\s+WebSocket\s*\(", re.I), "info"),
    _Pattern("sendBeacon", "network-output", re.compile(r"navigator\s*\.\s*sendBeacon\s*\(", re.I), "info"),
    _Pattern("postMessage", "cross-context-output", re.compile(r"\.\s*postMessage\s*\(", re.I), "medium"),
    _Pattern("storage-write", "storage-output", re.compile(r"(?:localStorage|sessionStorage)\s*\.\s*(?:setItem|removeItem|clear)\s*\(", re.I), "info"),
    _Pattern("cookie-write", "storage-output", re.compile(r"document\s*\.\s*cookie\s*=(?!=)", re.I), "medium"),
    _Pattern("command-exec", "command-execution", re.compile(r"(?:child_process\s*\.\s*)?(?:exec|execSync|spawn|spawnSync)\s*\(", re.I), "critical", 0.8),
    _Pattern("vm-exec", "code-execution", re.compile(r"(?:vm\s*\.\s*)?runIn(?:This|New)Context\s*\(", re.I), "critical"),
    _Pattern("filesystem-write", "filesystem-output", re.compile(r"(?:fs\s*\.\s*)?(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(", re.I), "medium", 0.75),
    _Pattern("database-query", "database-output", re.compile(r"\.\s*(?:query|execute|exec|raw)\s*\(", re.I), "high", 0.65),
    _Pattern("response-send", "http-output", re.compile(r"(?:res|response)\s*\.\s*(?:send|json|write|end|render)\s*\(", re.I), "info"),
    _Pattern("response-redirect", "http-output", re.compile(r"(?:res|response)\s*\.\s*redirect\s*\(", re.I), "medium"),
]

SANITIZER_RE = re.compile(
    r"\b(?:DOMPurify\s*\.\s*sanitize|sanitize(?:HTML|Html)?|escape(?:HTML|Html)?|encodeURI(?:Component)?|"
    r"CSS\s*\.\s*escape|trustedTypes\s*\.\s*createPolicy|Number|parseInt|parseFloat)\s*\(", re.I
)

CALL_RE = re.compile(r"(?<!\bfunction\s)(?<!\bclass\s)\b([A-Za-z_$][\w$]*(?:\s*(?:\.|\?\.)\s*[A-Za-z_$][\w$]*)*)\s*(\?\.)?\s*\(")
CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "with", "function", "return", "throw", "typeof", "delete", "void", "new", "super", "import"}


class JavaScriptAnalyzer:
    """Structural scanner with source/sink cataloguing and intra-function flow tracing."""

    @classmethod
    def analyze(cls, code: str, file_url: str = "inline.js") -> JSAnalysis:
        original = code or ""
        masked = _mask_non_code(original)
        analysis = JSAnalysis(
            file_url=file_url,
            sha256=hashlib.sha256(original.encode("utf-8", errors="replace")).hexdigest(),
            size_bytes=len(original.encode("utf-8", errors="replace")),
            module_kind="esm" if re.search(r"^\s*(?:import|export)\b", masked, re.M) else "commonjs" if "require(" in masked or "module.exports" in masked else "script",
            source_map_url=_source_map_url(original),
        )
        analysis.functions = cls._functions(original, masked)
        module_fn = JSFunction("<module>", "<module>", "module", [], 0, len(original), 1,
                               max(1, original.count("\n") + 1), body_hash=hashlib.sha256(original.encode()).hexdigest(),
                               complexity=_complexity(masked))
        intervals = [module_fn, *analysis.functions]
        analysis.inputs = cls._inputs(original, analysis.functions)
        analysis.outputs = cls._outputs(original, masked, analysis.functions)
        analysis.sources = cls._sources(original, masked, intervals)
        analysis.sinks = cls._sinks(original, masked, intervals)
        analysis.calls = cls._calls(original, masked, intervals)
        analysis.modules, analysis.exports = cls._modules(original, masked)
        analysis.globals = cls._globals(original, masked, analysis.functions)
        analysis.flows = cls._flows(original, masked, intervals, analysis.inputs, analysis.sources, analysis.sinks)
        if _unbalanced(masked):
            analysis.parse_warnings.append("Unbalanced delimiters detected; some function boundaries may be incomplete.")
        return analysis

    @classmethod
    def _functions(cls, code: str, masked: str) -> list[JSFunction]:
        candidates: list[tuple[int, int, str, str, str, bool, bool, bool]] = []
        named_arrow_positions: set[int] = set()
        class_ranges: list[tuple[int, int, str]] = []
        for class_match in re.finditer(r"\bclass\s+([A-Za-z_$][\w$]*)[^\{]*\{", masked):
            class_close = _matching(masked, class_match.end() - 1, "{", "}")
            class_ranges.append((class_match.start(), class_close if class_close >= 0 else len(masked), class_match.group(1)))
        function_re = re.compile(r"(?:(export)\s+(?:default\s+)?)?(?:(async)\s+)?function\s*(\*)?\s*([A-Za-z_$][\w$]*)?\s*\(([^)]*)\)\s*\{", re.M)
        for match in function_re.finditer(masked):
            name = match.group(4)
            if not name:
                prefix = masked[max(0, match.start() - 150):match.start()]
                assigned = re.search(r"([A-Za-z_$][\w$]*)\s*(?:=|:)\s*$", prefix)
                name = assigned.group(1) if assigned else "default" if match.group(1) else f"<anonymous@{_line(code, match.start())}>"
            candidates.append((match.start(), match.end() - 1, name, name, match.group(5), bool(match.group(2)), bool(match.group(3)), bool(match.group(1))))

        arrow_re = re.compile(r"(?:(export)\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:(async)\s*)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*(\{)?", re.M)
        for match in arrow_re.finditer(masked):
            params = match.group(4) if match.group(4) is not None else match.group(5) or ""
            brace = match.end() - 1 if match.group(6) else -1
            candidates.append((match.start(), brace, match.group(2), match.group(2), params, bool(match.group(3)), False, bool(match.group(1))))
            named_arrow_positions.add(masked.find("=>", match.start(), match.end()))

        assignment_arrow = re.compile(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*=\s*(?:(async)\s*)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*(\{)?", re.M)
        for match in assignment_arrow.finditer(masked):
            params = match.group(3) if match.group(3) is not None else match.group(4) or ""
            brace = match.end() - 1 if match.group(5) else -1
            qualified = re.sub(r"\s+", "", match.group(1))
            candidates.append((match.start(), brace, qualified.rsplit(".", 1)[-1], qualified, params, bool(match.group(2)), False, False))
            named_arrow_positions.add(masked.find("=>", match.start(), match.end()))

        generic_arrow = re.compile(r"(?:(async)\s*)?(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*(\{)?", re.M)
        for match in generic_arrow.finditer(masked):
            arrow_position = masked.find("=>", match.start(), match.end())
            if arrow_position in named_arrow_positions:
                continue
            line = _line(code, match.start())
            column = match.start() - code.rfind("\n", 0, match.start())
            name = f"<callback@{line}:{column}>"
            params = match.group(2) if match.group(2) is not None else match.group(3) or ""
            brace = match.end() - 1 if match.group(4) else -1
            candidates.append((match.start(), brace, name, name, params, bool(match.group(1)), False, False))

        method_re = re.compile(r"(?m)(?:^|[;{}]\s*)(?:(async)\s+)?(?:(get|set)\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{")
        for match in method_re.finditer(masked):
            name = match.group(3)
            if name in CONTROL_WORDS or any(start <= match.start() < open_brace + 1 for start, open_brace, *_ in candidates):
                continue
            candidates.append((match.start(), match.end() - 1, name, name, match.group(4), bool(match.group(1)), False, False))

        functions: list[JSFunction] = []
        used: set[tuple[int, str]] = set()
        for start, brace, name, qualified, raw_params, async_flag, generator, exported in sorted(candidates):
            if (start, qualified) in used:
                continue
            used.add((start, qualified))
            if brace >= 0:
                close = _matching(masked, brace, "{", "}")
                end = close + 1 if close >= 0 else len(code)
                body_start = brace + 1
            else:
                end = _expression_end(masked, start)
                body_start = masked.find("=>", start, end) + 2
            params = [item.strip() for item in _split_top_level(code[code.find("(", start, body_start) + 1:code.find(")", start, body_start + 1)])] if "(" in code[start:body_start] else [raw_params.strip()] if raw_params.strip() else []
            if raw_params and not params:
                params = _split_top_level(raw_params)
            body = code[body_start:end]
            if qualified == name:
                owner_class = next((class_name for class_start, class_end, class_name in class_ranges
                                    if class_start < start < class_end), None)
                if owner_class and not name.startswith("<"):
                    qualified = f"{owner_class}.{name}"
            functions.append(JSFunction(
                name=name, qualified_name=qualified, kind="arrow" if "=>" in masked[start:body_start + 2] else "method" if not masked[start:body_start].lstrip().startswith(("function", "async function", "export")) else "function",
                parameters=params, start=start, end=end, start_line=_line(code, start), end_line=_line(code, max(start, end - 1)),
                async_flag=async_flag, generator=generator, exported=exported,
                body_hash=hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(), complexity=_complexity(masked[body_start:end]),
            ))
        return functions

    @staticmethod
    def _inputs(code: str, functions: list[JSFunction]) -> list[JSInput]:
        result: list[JSInput] = []
        for function in functions:
            for raw in function.parameters:
                raw = raw.strip()
                if not raw:
                    continue
                left, default = _split_default(raw)
                name_part, type_hint = _split_type(left)
                kind = "rest" if name_part.lstrip().startswith("...") else "destructured" if name_part.lstrip().startswith(("{", "[")) else "parameter"
                name = name_part.strip().removeprefix("...").strip()
                result.append(JSInput(function.qualified_name, name[:300], kind, default[:500] if default else None,
                                      type_hint[:200] if type_hint else None, function.start_line))
                if kind == "destructured":
                    for child in re.findall(r"[A-Za-z_$][\w$]*", name):
                        if child not in {"as", "true", "false", "null", "undefined"}:
                            result.append(JSInput(function.qualified_name, child, "destructured-member", None, None, function.start_line))
        return _dedupe(result, lambda item: (item.function, item.name, item.kind))

    @staticmethod
    def _outputs(code: str, masked: str, functions: list[JSFunction]) -> list[JSOutput]:
        result: list[JSOutput] = []
        for function in functions:
            body_mask = masked[function.start:function.end]
            ordinal = 0
            for match in re.finditer(r"\b(return|throw|yield)\b(?:\s*\*)?", body_mask):
                absolute = function.start + match.start()
                expression = _read_expression(code, function.start + match.end(), function.end)
                ordinal += 1
                result.append(JSOutput(function.qualified_name, match.group(1), expression[:1000], _line(code, absolute), ordinal))
            header = masked[function.start:min(function.end, function.start + 1000)]
            if function.kind == "arrow" and "=>" in header and "{" not in header.split("=>", 1)[1][:5]:
                arrow = code.find("=>", function.start, function.end)
                result.append(JSOutput(function.qualified_name, "implicit-return", code[arrow + 2:function.end].strip()[:1000], function.start_line, 1))
            elif not any(item.function == function.qualified_name for item in result):
                result.append(JSOutput(function.qualified_name, "implicit-undefined", "undefined", function.end_line, 1))
        return result

    @staticmethod
    def _sources(code: str, masked: str, intervals: list[JSFunction]) -> list[JSSource]:
        result: list[JSSource] = []
        for pattern in SOURCE_PATTERNS:
            for match in pattern.regex.finditer(masked):
                expression = _statement(code, match.start())
                result.append(JSSource(
                    _owner(intervals, match.start()).qualified_name, pattern.kind, expression[:1000],
                    _assigned_variable(code, match.start()), _input_name(expression, pattern.kind),
                    _line(code, match.start()), pattern.confidence,
                ))
        return _dedupe(result, lambda item: (item.function, item.kind, item.line, item.expression))

    @staticmethod
    def _sinks(code: str, masked: str, intervals: list[JSFunction]) -> list[JSSink]:
        result: list[JSSink] = []
        for pattern in SINK_PATTERNS:
            for match in pattern.regex.finditer(masked):
                expression = _statement(code, match.start())
                result.append(JSSink(_owner(intervals, match.start()).qualified_name, pattern.kind, pattern.category,
                                     expression[:1000], _sink_value(code, masked, match, pattern.kind)[:1000],
                                     _line(code, match.start()), pattern.severity, pattern.confidence))
        return _dedupe(result, lambda item: (item.function, item.kind, item.line, item.expression))

    @staticmethod
    def _calls(code: str, masked: str, intervals: list[JSFunction]) -> list[JSCall]:
        result: list[JSCall] = []
        for match in CALL_RE.finditer(masked):
            callee = re.sub(r"\s+", "", match.group(1))
            if callee in CONTROL_WORDS or masked[max(0, match.start() - 12):match.start()].rstrip().endswith(("function", "class")):
                continue
            open_paren = masked.find("(", match.start(), match.end() + 1)
            close = _matching(masked, open_paren, "(", ")")
            args = _split_top_level(code[open_paren + 1:close]) if close >= 0 else []
            prefix = masked[max(0, match.start() - 20):match.start()]
            result.append(JSCall(_owner(intervals, match.start()).qualified_name, callee, [arg.strip()[:500] for arg in args],
                                 _line(code, match.start()), bool(re.search(r"\bawait\s*$", prefix)), bool(match.group(2) or "?." in match.group(1))))
        return _dedupe(result, lambda item: (item.caller, item.callee, item.line, tuple(item.arguments)))

    @staticmethod
    def _modules(code: str, masked: str) -> tuple[list[JSModuleReference], list[str]]:
        refs: list[JSModuleReference] = []
        exports: set[str] = set()
        for match in re.finditer(r"\bimport\s+(.+?)\s+from\s+(['\"])(.*?)\2", code, re.M):
            refs.append(JSModuleReference("import", match.group(3), re.findall(r"[A-Za-z_$][\w$]*", match.group(1)), _line(code, match.start())))
        for match in re.finditer(r"\brequire\s*\(\s*(['\"])(.*?)\1\s*\)", code):
            refs.append(JSModuleReference("require", match.group(2), [], _line(code, match.start())))
        for match in re.finditer(r"\bimport\s*\(\s*(['\"])(.*?)\1\s*\)", code):
            refs.append(JSModuleReference("dynamic-import", match.group(2), [], _line(code, match.start())))
        for match in re.finditer(r"\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)?\s*([A-Za-z_$][\w$]*)?", masked):
            exports.add(match.group(1) or "default")
        for match in re.finditer(r"(?:module\s*\.\s*exports|exports\s*\.\s*([A-Za-z_$][\w$]*))\s*=", masked):
            exports.add(match.group(1) or "module.exports")
        return _dedupe(refs, lambda item: (item.kind, item.module, tuple(item.names))), sorted(exports)

    @staticmethod
    def _globals(code: str, masked: str, functions: list[JSFunction]) -> list[str]:
        names = set()
        for match in re.finditer(r"\b(?:const|let|var|class|function)\s+([A-Za-z_$][\w$]*)", masked):
            if not any(function.start < match.start() < function.end for function in functions):
                names.add(match.group(1))
        return sorted(names)

    @staticmethod
    def _flows(code: str, masked: str, intervals: list[JSFunction], inputs: list[JSInput],
               sources: list[JSSource], sinks: list[JSSink]) -> list[JSFlow]:
        flows: list[JSFlow] = []
        for function in intervals:
            fn_sources = [item for item in sources if item.function == function.qualified_name]
            fn_sinks = [item for item in sinks if item.function == function.qualified_name]
            taint: dict[str, tuple[str, str, list[str], bool]] = {}
            for item in inputs:
                if item.function == function.qualified_name:
                    for identifier in re.findall(r"[A-Za-z_$][\w$]*", item.name):
                        taint[identifier] = ("function-parameter", item.name, [identifier], False)
            for source in fn_sources:
                if source.variable:
                    taint[source.variable] = (source.kind, source.input_name or source.variable, [source.variable], False)
            assignments = []
            body_mask = masked[function.start:function.end]
            for match in re.finditer(r"(?:\b(?:const|let|var)\s+)?(?<!\.)([A-Za-z_$][\w$]*)\s*=(?!=|>)", body_mask):
                absolute = function.start + match.start()
                assignments.append((match.group(1), _read_expression(code, function.start + match.end(), function.end), absolute))
            for _ in range(min(50, len(assignments) + 2)):
                changed = False
                for target, rhs, _ in assignments:
                    direct = next((source for source in fn_sources if source.expression and source.expression in _statement(code, _)), None)
                    refs = re.findall(r"[A-Za-z_$][\w$]*", rhs)
                    origin = next((taint[ref] for ref in refs if ref in taint and ref != target), None)
                    if direct and direct.variable == target:
                        origin = (direct.kind, direct.input_name or target, [target], False)
                    if origin:
                        sanitized = origin[3] or bool(SANITIZER_RE.search(rhs))
                        path = origin[2] if origin[2] and origin[2][-1] == target else [*origin[2], target]
                        candidate = (origin[0], origin[1], path, sanitized)
                        if taint.get(target) != candidate:
                            taint[target] = candidate
                            changed = True
                if not changed:
                    break
            for sink in fn_sinks:
                refs = re.findall(r"[A-Za-z_$][\w$]*", sink.value_expression)
                origins = [taint[ref] for ref in refs if ref in taint]
                direct_sources = [src for src in fn_sources if src.expression and src.expression == sink.expression]
                if direct_sources and not origins:
                    src = direct_sources[0]
                    origins.append((src.kind, src.input_name or src.variable or src.kind, [src.expression[:120]], False))
                for source_kind, source_name, path, sanitized in origins:
                    flows.append(JSFlow(function.qualified_name, source_kind, source_name, sink.kind, sink.expression,
                                        path, sink.line, 0.95 if len(path) <= 2 else max(0.65, 0.95 - .05 * len(path)),
                                        sanitized or bool(SANITIZER_RE.search(sink.value_expression))))
        return _dedupe(flows, lambda item: (item.function, item.source_kind, item.source_name, item.sink_kind, item.line, item.sanitized))


def _mask_non_code(code: str) -> str:
    chars = list(code)
    i = 0
    state = "code"
    quote = ""
    while i < len(chars):
        current = chars[i]
        next_char = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if current == "/" and next_char == "/":
                chars[i] = chars[i + 1] = " "
                state = "line-comment"
                i += 2
                continue
            if current == "/" and next_char == "*":
                chars[i] = chars[i + 1] = " "
                state = "block-comment"
                i += 2
                continue
            if current in "'\"`":
                quote = current
                state = "string"
        elif state == "line-comment":
            if current == "\n":
                state = "code"
            else:
                chars[i] = " "
        elif state == "block-comment":
            if current == "*" and next_char == "/":
                chars[i] = chars[i + 1] = " "
                state = "code"
                i += 2
                continue
            if current != "\n":
                chars[i] = " "
        elif state == "string":
            if current == "\\":
                if current != "\n":
                    chars[i] = " "
                if i + 1 < len(chars) and chars[i + 1] != "\n":
                    chars[i + 1] = " "
                i += 2
                continue
            if current == quote:
                state = "code"
            elif current != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def _matching(masked: str, start: int, opening: str, closing: str) -> int:
    if start < 0 or start >= len(masked) or masked[start] != opening:
        return -1
    depth = 0
    for index in range(start, len(masked)):
        if masked[index] == opening:
            depth += 1
        elif masked[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _expression_end(masked: str, start: int) -> int:
    depth = 0
    for index in range(start, len(masked)):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif depth == 0 and char in ";\n":
            return index
    return len(masked)


def _read_expression(code: str, start: int, limit: int) -> str:
    masked = _mask_non_code(code[start:limit])
    end = _expression_end(masked, 0)
    return code[start:start + end].strip()


def _statement(code: str, position: int) -> str:
    left = max(code.rfind(";", 0, position), code.rfind("\n", 0, position), code.rfind("{", 0, position)) + 1
    masked = _mask_non_code(code[position:])
    end = _expression_end(masked, 0)
    return " ".join(code[left:position + end].strip().split())


def _owner(intervals: list[JSFunction], position: int) -> JSFunction:
    matches = [item for item in intervals if item.start <= position < item.end]
    return min(matches, key=lambda item: (item.end - item.start, item.kind == "module")) if matches else intervals[0]


def _line(code: str, position: int) -> int:
    return code.count("\n", 0, max(0, position)) + 1


def _split_top_level(value: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    for index, char in enumerate(value):
        if quote:
            if char == quote and (index == 0 or value[index - 1] != "\\"):
                quote = None
        elif char in "'\"`":
            quote = char
        elif char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
    if value[start:].strip():
        result.append(value[start:].strip())
    return result


def _split_default(value: str) -> tuple[str, str | None]:
    parts = _split_at_top_level(value, "=")
    return (parts[0], parts[1]) if len(parts) > 1 else (value, None)


def _split_type(value: str) -> tuple[str, str | None]:
    parts = _split_at_top_level(value, ":")
    return (parts[0], parts[1]) if len(parts) > 1 else (value, None)


def _split_at_top_level(value: str, delimiter: str) -> list[str]:
    depth = 0
    quote = None
    for index, char in enumerate(value):
        if quote:
            if char == quote and value[index - 1] != "\\":
                quote = None
        elif char in "'\"`":
            quote = char
        elif char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        elif char == delimiter and depth == 0:
            return [value[:index].strip(), value[index + 1:].strip()]
    return [value.strip()]


def _assigned_variable(code: str, position: int) -> str | None:
    boundary = max(code.rfind(";", 0, position), code.rfind("\n", 0, position), code.rfind("{", 0, position)) + 1
    prefix = code[boundary:position]
    match = re.search(r"(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=.*$", prefix, re.S)
    return match.group(1) if match else None


def _sink_value(code: str, masked: str, match: re.Match[str], kind: str) -> str:
    assignment_kinds = {
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML", "srcdoc", "script-text",
        "location-write", "cookie-write",
    }
    if kind in assignment_kinds:
        operator = ":" if kind == "dangerouslySetInnerHTML" and ":" in code[match.start():match.end()] else "="
        position = code.find(operator, match.start(), min(len(code), match.end() + 4))
        if position >= 0:
            return _read_expression(code, position + 1, min(len(code), position + 5000))
    open_paren = masked.find("(", match.start(), min(len(masked), match.end() + 4))
    close_paren = _matching(masked, open_paren, "(", ")") if open_paren >= 0 else -1
    if close_paren >= 0:
        args = _split_top_level(code[open_paren + 1:close_paren])
        if kind in {"insertAdjacentHTML", "setAttribute"} and len(args) > 1:
            return args[1].strip()
        return ", ".join(args).strip()
    return _statement(code, match.start())


def _input_name(expression: str, kind: str) -> str | None:
    if kind in {"url-parameter", "storage-read"}:
        match = re.search(r"(?:get|getItem)\s*\(\s*['\"]([^'\"]+)", expression, re.I)
        if match:
            return match.group(1)
    if kind == "node-request":
        match = re.search(r"(?:body|query|params|headers|cookies)\s*(?:\.\s*([\w$-]+)|\[\s*['\"]([^'\"]+))", expression)
        if match:
            return match.group(1) or match.group(2)
    return None


def _source_map_url(code: str) -> str | None:
    match = re.search(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)", code)
    return match.group(1).strip() if match else None


def _complexity(masked: str) -> int:
    return 1 + len(re.findall(r"\b(?:if|for|while|case|catch)\b|&&|\|\||\?", masked))


def _unbalanced(masked: str) -> bool:
    for opening, closing in (("(", ")"), ("{", "}"), ("[", "]")):
        if masked.count(opening) != masked.count(closing):
            return True
    return False


def _dedupe(items: Iterable[Any], key) -> list[Any]:
    result = []
    seen = set()
    for item in items:
        identity = key(item)
        if identity not in seen:
            seen.add(identity)
            result.append(item)
    return result
