"""Orchestrator: wires connector -> SOC agent -> IR agent -> action plane, with the approval gate.

This is the only place actuators are called. Automatic actions run immediately; gated actions
go to the approval queue (or, with interactive=True, are put to the operator on the spot).
"""
from . import org as orgmod
from . import state
from .connectors.actuators import default_actuators
from .connectors.alert_source import from_source, missing_required
from .ir_agent import IRAgent
from .triage_agent import SOCTriageAgent

LINE = "-" * 78


def to_alert(org, data, source="edr-text"):
    """Raw text or vendor JSON from one of the org's sources -> canonical alert (ValueError if unusable)."""
    sources = org.sources()
    if source not in sources:
        raise ValueError("Unknown source '{}' for org {} (configured: {})".format(
            source, org.id, ", ".join(sorted(sources))))
    try:
        alert = from_source(data, source, sources[source])
    except (ValueError, KeyError, TypeError) as e:
        raise ValueError("Could not parse alert for source '{}': {}".format(source, e))
    missing = missing_required(alert)
    if missing:
        raise ValueError("Alert from '{}' is missing required fields {}; check sources/{}.json".format(
            source, missing, source))
    return alert


class Pipeline:
    def __init__(self, interactive=False, out=print, close_threshold=None):
        self.org = orgmod.current()
        self.soc = SOCTriageAgent()
        self._ir = None
        self.actuators = default_actuators()
        self.interactive = interactive
        self.out = out
        self.close_threshold = close_threshold

    @property
    def ir(self):          # loaded on first escalation only
        if self._ir is None:
            self._ir = IRAgent()
        return self._ir

    def process_text(self, text, label="alert", source="edr-text"):
        return self.process_alert(to_alert(self.org, text, source), label)

    def process_alert(self, alert, label="alert"):
        self.out(LINE)
        if alert.get("format") == "mapped":
            self.out("SOURCE {} (vendor id {}) mapped and rendered into the model's alert layout".format(
                alert["source"], alert.get("vendor_alert_id") or "-"))
        self.out("ALERT {}  [{}]  {} on {} (user {})".format(label, alert["alert_id"], alert["detection"],
                                                             alert["host"], alert["user"]))
        result = self.soc.process(alert, self.close_threshold)
        t = result["triage"]
        self.out("  SOC agent  verdict={} confidence={} techniques={}".format(
            t["verdict"], t["confidence_label"], ",".join(t["attack_techniques"]) or "-"))
        for g in result["guardrails"]:
            self.out("  GUARDRAIL  {} -> {}: {}".format(g["rule"], g["effect"], g["reason"]))
        self.out("  DISPOSITION {}  ({})".format(result["disposition"], result["rationale"]))
        try:
            self._escalate(result)
        finally:
            state.save_alert(self.record(label, alert, result))
        return result

    @staticmethod
    def record(label, alert, result):
        """What the UI and a reviewer need about one processed alert."""
        pkg, incident = result.get("package") or {}, result.get("incident") or {}
        return {"alert_id": alert["alert_id"], "label": label, "processed_at": state.now(),
                "alert": alert, "disposition": result["disposition"], "confidence": result["confidence"],
                "rationale": result["rationale"], "triage": result["triage"], "guardrails": result["guardrails"],
                "retrieved": result["retrieved"], "raw_answer": result["raw_answer"],
                "escalation_id": pkg.get("escalation_id"), "merged": result.get("merged", False),
                "incident_id": incident.get("incident_id") or (
                    find_incident_for(pkg["escalation_id"]) if pkg else None)}

    def _escalate(self, result):
        if result["disposition"] != "ESCALATE":
            return
        pkg = result["package"]
        if result["merged"]:
            self.out("  DEDUP      merged into {} (key {})".format(pkg["escalation_id"], pkg["idempotency_key"]))
            return
        self.out("  ESCALATION {} key={}".format(pkg["escalation_id"], pkg["idempotency_key"]))

        incident, actions = self.ir.handle(pkg)
        result["incident"] = incident
        if incident:
            self.out("  IR agent   {} opened: {} (score {}; {})".format(
                incident["incident_id"], incident["severity"], incident["severity_detail"]["score"],
                "; ".join(incident["severity_detail"]["reasons"])))
            self.out("             impact={} scope={} playbook={} sla={}".format(
                incident["facts"]["impact"], incident["facts"]["scope"], incident["playbook_id"] or "-",
                incident["sla"] or "-"))
        else:
            self.out("  IR agent   declined {} as not an incident".format(pkg["escalation_id"]))
        result["actions"] = [self.dispatch(a) for a in actions]
        if incident:
            incident["actions"] = [{k: a.get(k) for k in ("action_id", "type", "target", "gated", "reason", "rule_id")}
                                   for a in actions]
            state.save_incident(incident)

    def dispatch(self, action):
        if not action["gated"]:
            msg = self.actuators[action["type"]].execute(action)
            state.audit("orchestrator", "action_auto", action["action_id"], action["reason"], intent=msg)
            self.out("  AUTO       {}".format(msg))
            return dict(action, status="executed", intent=msg)

        if self.interactive:
            answer = input("  APPROVE?   {} {} -> {} [y/N] ".format(action["action_id"], action["type"],
                                                                     action["target"])).strip().lower()
            state.queue_approval(action)
            return approve(action["action_id"], "operator(cli)", out=self.out) if answer == "y" else \
                deny(action["action_id"], "operator(cli)", out=self.out)
        state.queue_approval(action)
        state.audit("orchestrator", "action_gated", action["action_id"], action["reason"],
                    type=action["type"], target=action["target"])
        self.out("  GATED      {} {} -> {}  (pending human approval: {})".format(
            action["action_id"], action["type"], action["target"], action["reason"]))
        return dict(action, status="pending")


def find_incident_for(escalation_id):
    return next((i["incident_id"] for i in state.load_incidents().values()
                 if i["escalation_id"] == escalation_id), None)


def action_status(action_id, approvals=None, executed=None):
    """Live status of a planned action: executed / pending / approved / denied."""
    approvals = state.load_approvals() if approvals is None else approvals
    executed = {a["action_id"]: a for a in state.load_actions()} if executed is None else executed
    if action_id in approvals:
        a = approvals[action_id]
        return a["status"], executed.get(action_id, {}).get("intent", ""), a.get("resolved_by", "")
    if action_id in executed:
        return "executed", executed[action_id]["intent"], "auto"
    return "planned", "", ""


def approve(action_id, by, note="", out=print):
    action = state.resolve_approval(action_id, "approved", by, note)
    if action["type"] == "confirm_not_incident":
        msg = "closed escalation {} as not an incident".format(action["escalation_id"])
    else:
        msg = default_actuators()[action["type"]].execute(action)
    state.audit(by, "action_approved", action_id, note or "approved by human", intent=msg)
    out("  APPROVED   {} by {}: {}".format(action_id, by, msg))
    return dict(action, intent=msg)


def deny(action_id, by, note="", out=print):
    action = state.resolve_approval(action_id, "denied", by, note)
    state.audit(by, "action_denied", action_id, note or "denied by human")
    out("  DENIED     {} by {} ({} -> {})".format(action_id, by, action["type"], action["target"]))
    return action
