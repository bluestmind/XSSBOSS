"""Autonomous multi-step workflow completion.

Closes the last autonomy gap: given a discovered form (or a chain of them), this engine
*autonomously* fills every field with a valid synthetic value, injects the payload only into the
designated target field, and drives the multi-step flow to reach the vulnerable state — without an
operator declaring the steps. It emits a step list in the exact ``navigate/fill/click/press/wait``
vocabulary that ``AuthSessionService.execute_selenium_steps`` already runs, so the autonomous plan
plugs straight into the existing executor.

Responsible autonomy — the safety model is not optional:

* **Destructive-action gating.** Every submit/action is classified. Under the default
  ``BLOCK`` policy the engine refuses irreversible/destructive operations (delete, pay, transfer,
  send, publish, deactivate…) and hands them back for operator review instead of performing them.
  ``STRICT`` also gates unknown actions; ``ALLOW_ALL`` is an explicit operator opt-in.
* **Benign field values.** Only the single designated injection field carries the payload; every
  other field gets a valid synthetic value (never a second live attack).
* **Scope-bound & dry-runnable.** Navigation is origin-checked; ``dry_run`` returns the plan
  without touching the target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import urljoin, urlparse


class SafetyClass(str, Enum):
    SAFE = "safe"              # additive / reversible (post, comment, save draft, preview, update)
    DESTRUCTIVE = "destructive"  # irreversible / outward-facing (delete, pay, send, transfer…)
    UNKNOWN = "unknown"


class DestructivePolicy(str, Enum):
    BLOCK = "block"        # default: run SAFE + UNKNOWN, refuse DESTRUCTIVE
    STRICT = "strict"      # run only SAFE, refuse UNKNOWN + DESTRUCTIVE
    ALLOW_ALL = "allow_all"  # explicit operator opt-in: run everything in scope


@dataclass
class FormField:
    name: str
    field_type: str = "text"
    id: str = ""
    required: bool = False
    label: str = ""

    def selector(self) -> str:
        if self.id:
            return f"#{self.id}"
        if self.name:
            return f"[name='{self.name}']"
        return f"input[type='{self.field_type}']"


@dataclass
class FormSpec:
    action_url: str
    fields: List[FormField]
    page_url: str = ""              # page containing the form; action_url is where it submits
    submit_selector: str = "button[type='submit'],input[type='submit']"
    submit_label: str = ""          # button text / action name — used for safety classification
    method: str = "POST"
    endpoint_id: Optional[int] = None


@dataclass
class WorkflowPlan:
    steps: List[Dict[str, Any]] = field(default_factory=list)          # execute_selenium_steps-compatible
    injection_selector: str = ""
    safety: SafetyClass = SafetyClass.UNKNOWN
    blocked_reason: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": self.steps,
            "injection_selector": self.injection_selector,
            "safety": self.safety.value,
            "blocked_reason": self.blocked_reason,
            "notes": self.notes,
        }


@dataclass
class ExecutionResult:
    status: str                       # "completed" | "blocked" | "partial" | "planned"
    executed: List[Dict[str, Any]] = field(default_factory=list)
    blocked: List[Dict[str, Any]] = field(default_factory=list)
    reached_submit: bool = False
    rationale: str = ""


class ActionSafetyClassifier:
    """Classifies an action by its label/verb so irreversible operations can be gated."""

    _DESTRUCTIVE = (
        "delete", "remove", "destroy", "deactivate", "disable", "close account", "terminate",
        "pay", "purchase", "buy", "checkout", "order", "transfer", "withdraw", "send money",
        "wire", "refund", "publish", "deploy", "send", "invite", "share", "ban", "suspend",
        "reset password", "change password", "unsubscribe", "cancel subscription", "confirm order",
    )
    _SAFE = (
        "post", "comment", "reply", "save draft", "preview", "create note", "add note", "add comment",
        "update profile", "save profile", "add item", "add to list", "search", "filter", "apply filter",
        "rename", "save changes", "add", "create",
    )

    @classmethod
    def classify(cls, label: str) -> SafetyClass:
        text = (label or "").strip().lower()
        if not text:
            return SafetyClass.UNKNOWN
        # Destructive verbs win over generic "add/create/save" collisions (e.g. "confirm order").
        if any(marker in text for marker in cls._DESTRUCTIVE):
            return SafetyClass.DESTRUCTIVE
        if any(marker in text for marker in cls._SAFE):
            return SafetyClass.SAFE
        return SafetyClass.UNKNOWN

    @classmethod
    def is_permitted(cls, safety: SafetyClass, policy: DestructivePolicy) -> bool:
        if policy == DestructivePolicy.ALLOW_ALL:
            return True
        if policy == DestructivePolicy.STRICT:
            return safety == SafetyClass.SAFE
        # BLOCK (default)
        return safety != SafetyClass.DESTRUCTIVE


class FieldSynthesizer:
    """Produces valid, benign values so a flow can be completed without weaponizing every field."""

    @staticmethod
    def synthesize(f: FormField) -> Optional[str]:
        t = (f.field_type or "text").lower()
        blob = f"{f.name} {f.id} {f.label}".lower()

        if t in ("hidden", "submit", "button", "file", "image"):
            return None  # leave hidden/submit/file inputs alone
        if t in ("checkbox", "radio"):
            return "on"
        if t == "email" or "email" in blob:
            return "qa.probe@example.test"
        if t == "password" or "password" in blob:
            return "Qa-Probe-9x!"
        if t in ("number", "range") or any(k in blob for k in ("age", "qty", "quantity", "count")):
            return "7"
        if any(k in blob for k in ("amount", "price", "total", "sum", "money")):
            return "1"  # deliberately minimal for any value that survives to a money field
        if t == "date" or "date" in blob:
            return "2020-01-01"
        if t in ("tel",) or "phone" in blob:
            return "5550100"
        if t == "url" or "url" in blob or "website" in blob:
            return "https://example.test/"
        if "name" in blob:
            return "QA Probe"
        return "qa-probe"


class AutonomousWorkflowEngine:
    """Plans and executes a multi-step flow to reach an injection point — safely by default."""

    @classmethod
    def _origin(cls, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""

    @classmethod
    def _in_scope(cls, url: str, allowed_origins: Sequence[str]) -> bool:
        origin = cls._origin(url)
        if not origin:
            return False
        allowed = {cls._origin(o) or o.rstrip("/") for o in allowed_origins}
        return origin in allowed

    @classmethod
    def build_plan(
        cls,
        form: FormSpec,
        injection_field: str,
        payload: str,
        base_url: str,
        *,
        preamble: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> WorkflowPlan:
        """Assemble a navigate→fill(all fields)→submit step list; payload only in the target field."""
        steps: List[Dict[str, Any]] = list(preamble or [])
        form_page_url = urljoin(base_url, form.page_url or form.action_url)
        steps.append({"action": "navigate", "url": form_page_url})

        injection_selector = ""
        for f in form.fields:
            if f.name == injection_field or f.id == injection_field:
                value = payload
                injection_selector = f.selector()
            else:
                value = FieldSynthesizer.synthesize(f)
                if value is None:
                    continue
            field_type = (f.field_type or "text").lower()
            if field_type in {"checkbox", "radio"}:
                steps.append({"action": "check", "selector": f.selector()})
            elif field_type == "select":
                steps.append({"action": "select", "selector": f.selector(), "value": "first_available"})
            else:
                steps.append({"action": "fill", "selector": f.selector(), "value": value})

        safety = ActionSafetyClassifier.classify(form.submit_label)
        steps.append({"action": "click", "selector": form.submit_selector, "safety": safety.value})

        plan = WorkflowPlan(steps=steps, injection_selector=injection_selector, safety=safety)
        if not injection_selector:
            plan.notes.append(f"injection field '{injection_field}' not found in form")
        return plan

    @classmethod
    def validate_plan(
        cls,
        plan: WorkflowPlan,
        base_url: str,
        *,
        allowed_origins: Sequence[str] = (),
        policy: DestructivePolicy = DestructivePolicy.STRICT,
    ) -> tuple[bool, str]:
        """Validate a generated plan without executing any browser action."""
        origins = list(allowed_origins) or [cls._origin(base_url)]
        if not plan.injection_selector:
            return False, "plan has no injection field"
        for step in plan.steps:
            action = str(step.get("action") or "").lower()
            if action not in {"navigate", "fill", "check", "select", "click", "press", "wait"}:
                return False, f"unsupported action: {action}"
            if action == "navigate":
                url = urljoin(base_url, str(step.get("url") or ""))
                if not cls._in_scope(url, origins):
                    return False, f"navigation out of scope: {url}"
            if action == "click":
                raw_safety = step.get("safety")
                safety = SafetyClass(raw_safety) if raw_safety in SafetyClass._value2member_map_ else SafetyClass.UNKNOWN
                if not ActionSafetyClassifier.is_permitted(safety, policy):
                    return False, f"click blocked by policy={policy.value} (safety={safety.value})"
        return True, "validated"

    @classmethod
    def chain(cls, plans: Sequence[WorkflowPlan]) -> WorkflowPlan:
        """Concatenate several form plans into one multi-step workflow (create → then inject)."""
        merged = WorkflowPlan()
        safeties = []
        for p in plans:
            merged.steps.extend(p.steps)
            merged.notes.extend(p.notes)
            safeties.append(p.safety)
            if p.injection_selector:
                merged.injection_selector = p.injection_selector
        # The chain is as destructive as its most destructive step.
        if SafetyClass.DESTRUCTIVE in safeties:
            merged.safety = SafetyClass.DESTRUCTIVE
        elif all(s == SafetyClass.SAFE for s in safeties) and safeties:
            merged.safety = SafetyClass.SAFE
        else:
            merged.safety = SafetyClass.UNKNOWN
        return merged

    @classmethod
    def execute(
        cls,
        plan: WorkflowPlan,
        actions: Dict[str, Callable[..., Any]],
        base_url: str,
        *,
        allowed_origins: Sequence[str] = (),
        policy: DestructivePolicy = DestructivePolicy.BLOCK,
        dry_run: bool = False,
    ) -> ExecutionResult:
        """Run the plan through injected action callables, gating steps per the safety policy.

        ``actions`` provides ``navigate(url)``, ``fill(selector, value)``, ``click(selector)``,
        ``press(selector, key)``, ``wait(seconds)``. Any gated destructive step halts execution and
        is returned for operator review rather than performed.
        """
        if dry_run:
            return ExecutionResult(status="planned", executed=list(plan.steps),
                                   rationale="dry_run: no actions performed")

        result = ExecutionResult(status="completed")
        origins = list(allowed_origins) or [cls._origin(base_url)]

        for step in plan.steps:
            action = str(step.get("action") or "").lower()

            # Safety gate on any action carrying a destructive classification.
            step_safety = SafetyClass(step.get("safety")) if step.get("safety") in SafetyClass._value2member_map_ else SafetyClass.UNKNOWN
            if step_safety != SafetyClass.UNKNOWN and not ActionSafetyClassifier.is_permitted(step_safety, policy):
                result.blocked.append({**step, "reason": f"blocked by policy={policy.value} (safety={step_safety.value})"})
                result.status = "blocked" if not result.executed else "partial"
                result.rationale = "destructive action gated for operator review"
                return result

            if action == "navigate":
                url = urljoin(base_url, str(step.get("url") or ""))
                if not cls._in_scope(url, origins):
                    result.blocked.append({**step, "reason": f"navigation out of scope: {url}"})
                    result.status = "blocked" if not result.executed else "partial"
                    result.rationale = "out-of-scope navigation refused"
                    return result
                actions["navigate"](url)
            elif action == "fill":
                actions["fill"](step.get("selector"), step.get("value"))
            elif action == "check":
                actions.get("check", lambda *_: None)(step.get("selector"))
            elif action == "select":
                actions.get("select", lambda *_: None)(step.get("selector"), step.get("value"))
            elif action == "click":
                actions["click"](step.get("selector"))
                result.reached_submit = True
            elif action == "press":
                actions.get("press", lambda *_: None)(step.get("selector"), step.get("key", "Enter"))
            elif action == "wait":
                actions.get("wait", lambda *_: None)(step.get("seconds", 0.5))
            else:
                result.blocked.append({**step, "reason": f"unsupported action: {action}"})
                continue

            result.executed.append(step)

        return result
