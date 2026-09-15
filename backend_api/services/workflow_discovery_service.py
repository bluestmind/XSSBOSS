"""Discover safe stateful form workflows and attach them to live endpoints."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.experiment import Experiment
from backend_api.services.autonomous_workflow_engine import (
    AutonomousWorkflowEngine,
    DestructivePolicy,
    FormField,
    FormSpec,
    SafetyClass,
)


_SAFE_SELECTOR_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")


@dataclass
class _ParsedForm:
    action: str = ""
    method: str = "GET"
    fields: List[FormField] = field(default_factory=list)
    submit_selector: str = "button[type='submit'],input[type='submit']"
    submit_label: str = ""


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[_ParsedForm] = []
        self.current: Optional[_ParsedForm] = None
        self._button_depth = 0
        self._button_text: List[str] = []

    @staticmethod
    def _attrs(attrs: list[tuple[str, Optional[str]]]) -> Dict[str, str]:
        return {str(key).lower(): str(value or "") for key, value in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        values = self._attrs(attrs)
        if tag == "form" and self.current is None:
            self.current = _ParsedForm(
                action=values.get("action", ""),
                method=(values.get("method") or "GET").upper(),
            )
            return
        if self.current is None:
            return
        if tag in {"input", "textarea", "select"}:
            name = values.get("name", "")
            field_id = values.get("id", "")
            if not any(_SAFE_SELECTOR_TOKEN.match(value) for value in (field_id, name) if value):
                return
            field_type = values.get("type") or ("textarea" if tag == "textarea" else "select" if tag == "select" else "text")
            if field_type.lower() in {"submit", "button", "image"}:
                if values.get("value"):
                    self.current.submit_label = values["value"][:120]
                if field_id:
                    self.current.submit_selector = f"#{field_id}"
                elif name:
                    self.current.submit_selector = f"[name='{name}']"
                return
            self.current.fields.append(FormField(
                name=name,
                id=field_id,
                field_type=field_type,
                required="required" in values,
                label=values.get("aria-label", "")[:120],
            ))
        elif tag == "button":
            self._button_depth += 1
            self._button_text = []
            if values.get("id") and _SAFE_SELECTOR_TOKEN.match(values["id"]):
                self.current.submit_selector = f"#{values['id']}"

    def handle_data(self, data: str) -> None:
        if self.current is not None and self._button_depth:
            self._button_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self.current is None:
            return
        if tag == "button" and self._button_depth:
            label = " ".join("".join(self._button_text).split())
            if label:
                self.current.submit_label = label[:120]
            self._button_depth = max(0, self._button_depth - 1)
            self._button_text = []
        elif tag == "form":
            self.forms.append(self.current)
            self.current = None
            self._button_depth = 0
            self._button_text = []


class WorkflowDiscoveryService:
    """Bridge sampled HTML forms into executor-compatible, validated workflows."""

    @staticmethod
    def _canonical(url: str) -> str:
        split = urlsplit(url)
        path = (split.path or "/").rstrip("/") or "/"
        return urlunsplit((split.scheme.lower(), split.netloc.lower(), path, "", ""))

    @classmethod
    def _forms(cls, html: str) -> List[_ParsedForm]:
        parser = _FormParser()
        try:
            parser.feed((html or "")[:2_000_000])
            parser.close()
        except Exception:
            return []
        return parser.forms

    @classmethod
    def discover_for_experiment(
        cls,
        db: Session,
        experiment_id: int,
        endpoint_ids: Iterable[int],
    ) -> Dict[str, Any]:
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment is None:
            raise ValueError(f"Experiment {experiment_id} not found")
        ids = list(dict.fromkeys(int(value) for value in endpoint_ids))[:5000]
        endpoints = db.query(Endpoint).filter(Endpoint.id.in_(ids)).all() if ids else []
        pages = [row for row in endpoints if row.sample_response_body and row.method.upper() == "GET"]
        targets = [row for row in endpoints if row.params and not row.custom_steps]
        # HTML parsing is proportional to page count, not endpoint × page count.
        # Large captured pages made this phase appear hung when reparsed for every
        # candidate endpoint.
        forms_by_page = {
            page.id: cls._forms(page.sample_response_body)[:50]
            for page in pages[:250]
        }
        allowed_origins = [experiment.target.base_url]
        attached = 0
        rejected = 0
        llm_calls = 0
        records = []

        for target in targets:
            if not AutonomousWorkflowEngine._in_scope(target.url_pattern, allowed_origins):
                rejected += 1
                continue
            candidates_by_param: Dict[str, List[Dict[str, Any]]] = {}
            target_url = cls._canonical(target.url_pattern)
            target_method = target.method.upper()
            param_names = {param.name for param in target.params}
            for page in pages[:250]:
                for parsed in forms_by_page.get(page.id, []):
                    action_url = urljoin(page.url_pattern, parsed.action or page.url_pattern)
                    if parsed.method != target_method or cls._canonical(action_url) != target_url:
                        continue
                    field_names = {field.name for field in parsed.fields if field.name}
                    injectable_names = {
                        field.name for field in parsed.fields
                        if field.name and field.field_type.lower() not in {
                            "hidden", "submit", "button", "image", "file", "checkbox", "radio", "select"
                        }
                    }
                    injection_names = sorted(param_names & injectable_names)
                    if not injection_names:
                        continue
                    form = FormSpec(
                        action_url=action_url,
                        page_url=page.url_pattern,
                        method=parsed.method,
                        fields=parsed.fields,
                        submit_selector=parsed.submit_selector,
                        submit_label=parsed.submit_label,
                        endpoint_id=target.id,
                    )
                    for injection_name in injection_names:
                        plan = AutonomousWorkflowEngine.build_plan(
                            form,
                            injection_name,
                            "{{PAYLOAD}}",
                            experiment.target.base_url,
                        )
                        valid, reason = AutonomousWorkflowEngine.validate_plan(
                            plan,
                            experiment.target.base_url,
                            allowed_origins=allowed_origins,
                            policy=DestructivePolicy.STRICT,
                        )
                        if not valid or plan.safety is not SafetyClass.SAFE:
                            rejected += 1
                            continue
                        candidates_by_param.setdefault(injection_name, []).append({
                            "plan": plan,
                            "method": parsed.method,
                            "field_names": sorted(field_names)[:40],
                            "submit_label": parsed.submit_label,
                            "field_coverage": len(param_names & field_names) / max(1, len(param_names)),
                            "exact_action_match": True,
                            "reason": reason,
                        })

            selected_steps: Dict[str, List[Dict[str, Any]]] = {}
            for injection_name, candidates in candidates_by_param.items():
                candidates.sort(key=lambda item: (-item["field_coverage"], len(item["plan"].steps)))
                chosen_index = 0
                rationale = "deterministic highest coverage / shortest validated workflow"
                if (
                    len(candidates) > 1
                    and settings.LLM_ENABLED
                    and settings.LLM_WORKFLOW_ADVISOR
                    and llm_calls < max(0, settings.LLM_WORKFLOW_MAX_CALLS)
                    and not os.getenv("PYTEST_CURRENT_TEST")
                ):
                    try:
                        from backend_api.services.llm_service import LLMService

                        advice = LLMService.advise_workflow([
                            {
                                "id": index,
                                "method": item["method"],
                                "field_names": item["field_names"],
                                "submit_label": item["submit_label"],
                                "step_count": len(item["plan"].steps),
                                "field_coverage": item["field_coverage"],
                                "exact_action_match": item["exact_action_match"],
                            }
                            for index, item in enumerate(candidates[:12])
                        ])
                        llm_calls += 1
                        selected = advice.get("selected_candidate_id")
                        if isinstance(selected, int) and 0 <= selected < min(12, len(candidates)):
                            chosen_index = selected
                            rationale = str(advice.get("rationale") or rationale)[:400]
                    except Exception:
                        llm_calls += 1

                chosen = candidates[chosen_index]
                selected_steps[injection_name] = chosen["plan"].steps
                attached += 1
                records.append({
                    "endpoint_id": target.id,
                    "param_name": injection_name,
                    "candidate_count": len(candidates),
                    "selected_index": chosen_index,
                    "step_count": len(chosen["plan"].steps),
                    "rationale": rationale,
                })
            if selected_steps:
                target.custom_steps = {"by_param": selected_steps, "source": "autonomous_form_discovery_v1"}

        limits = dict(experiment.limits or {})
        limits["workflow_discovery"] = {
            "attached": attached,
            "rejected": rejected,
            "llm_calls": llm_calls,
            "records": records[:100],
        }
        experiment.limits = limits
        db.commit()
        return limits["workflow_discovery"]
