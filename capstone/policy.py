"""Escalation policy: an org's declarative rules -> the action plan for one incident.

Rule format (orgs/<id>/org.json "escalation_policy"):
  {"id": "page-ir", "action": "page_oncall", "target": "Alice (ir-primary)",
   "when": {"severity_at_most": "SEV2"}, "reason": "SEV1-SEV2 page IR"}

Conditions in "when" (all stated conditions must hold):
  always: true                  severity_at_most / severity_at_least: "SEV1".."SEV4"
  signals_any: [...]            any of: exfiltration, destructive, credential_theft, disabled_account, tier0
  host_prefix_any: [...]        any incident host starts with one of these
  techniques_any: [...]         any ATT&CK ID (parent match: T1003 matches T1003.001)

Safety invariant, enforced here and in validate(): actions that reach a person or leave the
security team (paging, stakeholders, external notification) are ALWAYS human-gated. An org can
gate more actions ("mode": "gated" on an internal action) but can never auto-run these.
"""
AUTO_ALLOWED = {"open_case", "create_channel", "post_summary"}           # internal, reversible
ALWAYS_GATED = {"page_oncall", "add_stakeholder", "notify_external"}     # reach people / leave security
ACTIONS = AUTO_ALLOWED | ALWAYS_GATED
SIGNALS = {"exfiltration", "destructive", "credential_theft", "disabled_account", "tier0"}
CONDITIONS = {"always", "severity_at_most", "severity_at_least", "signals_any", "host_prefix_any", "techniques_any"}
SEVERITIES = ("SEV1", "SEV2", "SEV3", "SEV4")


def _sev(s):
    return int(str(s)[-1])


def matches(when, incident, signals):
    if not when:
        return False
    level = _sev(incident["severity"])
    hosts = [h.upper() for h in incident.get("hosts", [])]
    techs = incident.get("attack_techniques", [])
    tests = {
        "always": lambda v: bool(v),
        "severity_at_most": lambda v: level <= _sev(v),
        "severity_at_least": lambda v: level >= _sev(v),
        "signals_any": lambda v: any(signals.get(s) for s in v),
        "host_prefix_any": lambda v: any(h.startswith(p.upper()) for h in hosts for p in v),
        "techniques_any": lambda v: any(t == x or t.split(".")[0] == x for t in techs for x in v),
    }
    return all(tests[k](v) for k, v in when.items() if k in tests)


def mode_for(rule):
    """Gated unless the action is internal AND the rule doesn't ask for gating."""
    if rule["action"] in ALWAYS_GATED:
        return "gated"
    return "gated" if rule.get("mode") == "gated" else "auto"


def plan(policy, incident, signals):
    """Return [{'rule_id','action','target','gated','reason'}] for the rules that fire."""
    out = []
    for rule in policy:
        if rule.get("action") in ACTIONS and matches(rule.get("when", {}), incident, signals):
            target = rule.get("target") or ("#" + incident["incident_id"] if rule["action"] in
                                            ("create_channel", "post_summary") else incident["incident_id"])
            out.append({"rule_id": rule.get("id", rule["action"]), "action": rule["action"], "target": target,
                        "gated": mode_for(rule) == "gated", "reason": rule.get("reason", rule.get("id", ""))})
    return out


def validate(policy):
    """[(level, message)] problems in an escalation policy. level is 'error' or 'warning'."""
    problems = []
    if not isinstance(policy, list) or not policy:
        return [("error", "escalation_policy must be a non-empty list of rules")]
    seen = set()
    for i, rule in enumerate(policy):
        where = "rule {} ({})".format(i + 1, rule.get("id", "no id") if isinstance(rule, dict) else "?")
        if not isinstance(rule, dict):
            problems.append(("error", where + ": must be an object"))
            continue
        if rule.get("id") in seen:
            problems.append(("error", where + ": duplicate id"))
        seen.add(rule.get("id"))
        action = rule.get("action")
        if action not in ACTIONS:
            problems.append(("error", "{}: unknown action '{}' (known: {})".format(where, action, sorted(ACTIONS))))
        if action in ALWAYS_GATED and rule.get("mode") == "auto":
            problems.append(("error", "{}: '{}' reaches people and is always human-gated; "
                                      "'mode: auto' is not allowed".format(where, action)))
        if action in ALWAYS_GATED and not rule.get("target"):
            problems.append(("error", where + ": needs a 'target' (who to page / add)"))
        when = rule.get("when")
        if not isinstance(when, dict) or not when:
            problems.append(("error", where + ": needs a non-empty 'when'"))
            continue
        for k, v in when.items():
            if k not in CONDITIONS:
                problems.append(("error", "{}: unknown condition '{}' (known: {})".format(where, k, sorted(CONDITIONS))))
            elif k.startswith("severity") and v not in SEVERITIES:
                problems.append(("error", "{}: {} must be one of {}".format(where, k, SEVERITIES)))
            elif k == "signals_any" and not set(v) <= SIGNALS:
                problems.append(("error", "{}: unknown signals {} (known: {})".format(
                    where, sorted(set(v) - SIGNALS), sorted(SIGNALS))))
    if not any(r.get("action") == "open_case" for r in policy if isinstance(r, dict)):
        problems.append(("warning", "no 'open_case' rule: incidents will not get a case"))
    if not any(r.get("action") == "page_oncall" for r in policy if isinstance(r, dict)):
        problems.append(("warning", "no 'page_oncall' rule: nobody is ever paged"))
    return problems
