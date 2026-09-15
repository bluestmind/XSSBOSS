"""Autonomous multi-step workflow completion: synthesis, safety gating, scope, and end-to-end."""
from backend_api.services.autonomous_workflow_engine import (
    ActionSafetyClassifier,
    AutonomousWorkflowEngine,
    DestructivePolicy,
    ExecutionResult,
    FieldSynthesizer,
    FormField,
    FormSpec,
    SafetyClass,
)

BASE = "http://app.test/"
ORIGINS = ["http://app.test"]
PAYLOAD = "<img src=x onerror=__XSS__('t')>"


# --------------------------------------------------------------- field synthesis

def test_field_synthesis_types():
    assert "@" in FieldSynthesizer.synthesize(FormField("email", "email"))
    assert FieldSynthesizer.synthesize(FormField("age", "number")).isdigit()
    assert FieldSynthesizer.synthesize(FormField("dob", "date")) == "2020-01-01"
    assert FieldSynthesizer.synthesize(FormField("amount", "text", label="Amount")) == "1"
    assert FieldSynthesizer.synthesize(FormField("full_name", "text")) == "QA Probe"
    assert FieldSynthesizer.synthesize(FormField("csrf", "hidden")) is None  # left alone
    assert FieldSynthesizer.synthesize(FormField("agree", "checkbox")) == "on"


# ------------------------------------------------------------------ safety gate

def test_safety_classifier():
    assert ActionSafetyClassifier.classify("Delete account") is SafetyClass.DESTRUCTIVE
    assert ActionSafetyClassifier.classify("Transfer funds") is SafetyClass.DESTRUCTIVE
    assert ActionSafetyClassifier.classify("Confirm order") is SafetyClass.DESTRUCTIVE
    assert ActionSafetyClassifier.classify("Post comment") is SafetyClass.SAFE
    assert ActionSafetyClassifier.classify("Save draft") is SafetyClass.SAFE
    assert ActionSafetyClassifier.classify("Frobnicate") is SafetyClass.UNKNOWN


def test_policy_permissions():
    C = ActionSafetyClassifier
    assert C.is_permitted(SafetyClass.DESTRUCTIVE, DestructivePolicy.BLOCK) is False
    assert C.is_permitted(SafetyClass.UNKNOWN, DestructivePolicy.BLOCK) is True
    assert C.is_permitted(SafetyClass.UNKNOWN, DestructivePolicy.STRICT) is False
    assert C.is_permitted(SafetyClass.DESTRUCTIVE, DestructivePolicy.ALLOW_ALL) is True


# ------------------------------------------------------------------ plan building

def _comment_form(submit_label="Post comment"):
    return FormSpec(
        action_url="/comments",
        fields=[
            FormField("author", "text"),
            FormField("email", "email"),
            FormField("body", "text", id="body"),
        ],
        submit_label=submit_label,
    )


def test_build_plan_injects_only_target_field():
    plan = AutonomousWorkflowEngine.build_plan(_comment_form(), "body", PAYLOAD, BASE)
    fills = {s["selector"]: s["value"] for s in plan.steps if s["action"] == "fill"}
    assert fills["#body"] == PAYLOAD                       # target carries the payload
    assert fills["[name='email']"] == "qa.probe@example.test"  # others get benign values
    assert PAYLOAD not in fills["[name='author']"]
    assert plan.injection_selector == "#body"
    assert plan.safety is SafetyClass.SAFE
    assert plan.steps[0]["action"] == "navigate"
    assert plan.steps[-1]["action"] == "click"


# --------------------------------------------------------------- execution / safety

class Recorder:
    def __init__(self, store=None):
        self.calls = []
        self.store = store if store is not None else {}
    def actions(self):
        return {
            "navigate": lambda u: self.calls.append(("navigate", u)),
            "fill": lambda s, v: self.store.__setitem__(s, v) or self.calls.append(("fill", s, v)),
            "click": lambda s: self.calls.append(("click", s)),
        }


def test_execute_safe_flow_completes_and_submits_payload():
    plan = AutonomousWorkflowEngine.build_plan(_comment_form(), "body", PAYLOAD, BASE)
    rec = Recorder()
    res = AutonomousWorkflowEngine.execute(plan, rec.actions(), BASE, allowed_origins=ORIGINS)
    assert res.status == "completed"
    assert res.reached_submit is True
    assert rec.store["#body"] == PAYLOAD            # payload actually filled into the target
    assert ("click", plan.steps[-1]["selector"]) in rec.calls


def test_execute_destructive_submit_is_gated_by_default():
    plan = AutonomousWorkflowEngine.build_plan(_comment_form(submit_label="Delete account"), "body", PAYLOAD, BASE)
    rec = Recorder()
    res = AutonomousWorkflowEngine.execute(plan, rec.actions(), BASE, allowed_origins=ORIGINS)
    assert res.status in ("blocked", "partial")
    assert res.reached_submit is False              # never clicked the destructive submit
    assert res.blocked and res.blocked[0]["action"] == "click"
    assert not any(c[0] == "click" for c in rec.calls)


def test_execute_destructive_runs_only_with_explicit_opt_in():
    plan = AutonomousWorkflowEngine.build_plan(_comment_form(submit_label="Delete account"), "body", PAYLOAD, BASE)
    rec = Recorder()
    res = AutonomousWorkflowEngine.execute(
        plan, rec.actions(), BASE, allowed_origins=ORIGINS, policy=DestructivePolicy.ALLOW_ALL
    )
    assert res.status == "completed"
    assert res.reached_submit is True


def test_out_of_scope_navigation_refused():
    form = FormSpec(action_url="http://evil.test/steal", fields=[FormField("x")], submit_label="Post")
    plan = AutonomousWorkflowEngine.build_plan(form, "x", PAYLOAD, BASE)
    rec = Recorder()
    res = AutonomousWorkflowEngine.execute(plan, rec.actions(), BASE, allowed_origins=ORIGINS)
    assert res.status == "blocked"
    assert not rec.calls  # nothing executed


def test_dry_run_touches_nothing():
    plan = AutonomousWorkflowEngine.build_plan(_comment_form(), "body", PAYLOAD, BASE)
    rec = Recorder()
    res = AutonomousWorkflowEngine.execute(plan, rec.actions(), BASE, allowed_origins=ORIGINS, dry_run=True)
    assert res.status == "planned"
    assert rec.calls == []
    assert len(res.executed) == len(plan.steps)


# --------------------------------------------------------------- multi-step chain

def test_chain_multi_step_flow_and_safety_propagation():
    create = FormSpec(action_url="/posts/new", fields=[FormField("title")], submit_label="Create post")
    comment = _comment_form()
    p1 = AutonomousWorkflowEngine.build_plan(create, "title", "QA", BASE)
    p2 = AutonomousWorkflowEngine.build_plan(comment, "body", PAYLOAD, BASE)
    chained = AutonomousWorkflowEngine.chain([p1, p2])
    assert chained.injection_selector == "#body"
    # navigate+fill+click twice
    assert sum(1 for s in chained.steps if s["action"] == "navigate") == 2
    assert chained.safety is SafetyClass.SAFE

    # A destructive step anywhere makes the whole chain destructive.
    p_del = AutonomousWorkflowEngine.build_plan(
        FormSpec(action_url="/x", fields=[FormField("x")], submit_label="Delete"), "x", "QA", BASE
    )
    assert AutonomousWorkflowEngine.chain([p1, p_del]).safety is SafetyClass.DESTRUCTIVE


# --------------------------------------------------------------- end-to-end reach

def test_e2e_autonomous_flow_reaches_stored_sink():
    """Full autonomy: fill an undeclared form and drive it to plant the payload into a store."""
    backend_store = {}

    def fill(selector, value):
        backend_store[selector] = value

    def click(_selector):
        # Simulate the server persisting the submitted comment body.
        backend_store["persisted_comment"] = backend_store.get("#body")

    actions = {"navigate": lambda u: None, "fill": fill, "click": click}
    plan = AutonomousWorkflowEngine.build_plan(_comment_form(), "body", PAYLOAD, BASE)
    res = AutonomousWorkflowEngine.execute(plan, actions, BASE, allowed_origins=ORIGINS)

    assert res.status == "completed"
    assert backend_store["persisted_comment"] == PAYLOAD  # payload reached the stored sink
