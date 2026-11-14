"""Severity rubric (IR-SEV-01 in the demo org; thresholds and asset rules come from the org pack).

The IR agent's LLM only extracts facts (impact, scope, exfiltration...). This module turns
those facts into a severity deterministically, so the same facts always give the same SEV
and every point can be explained. The point scale and the safety overrides are fixed in code;
an org configures its asset rules, Tier-0 accounts and the score needed for each level.
"""
import re

from . import org as orgmod

CRITICALITY_POINTS = {"critical": 3, "high": 2, "medium": 1, "low": 0}
IMPACT_POINTS = {"none": 0, "attempted": 1, "executed": 2, "exposed": 3, "destructive": 4}
SCOPE_POINTS = {"single_host": 0, "multiple_hosts": 1, "domain_wide": 2}


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _rule_matches(rule, host, group):
    """An asset rule matches when every condition it states matches (case-insensitive)."""
    checks = {
        "host_prefix": lambda vals: any(host.startswith(v.upper()) for v in vals),
        "device_group": lambda vals: group in [v.lower() for v in vals],
        "device_group_prefix": lambda vals: any(group.startswith(v.lower()) for v in vals),
        "device_group_contains": lambda vals: any(v.lower() in group for v in vals),
    }
    conds = [(k, _as_list(v)) for k, v in rule.items() if k in checks]
    return bool(conds) and all(checks[k](vals) for k, vals in conds)


def asset_rule(alert, org=None):
    org = org or orgmod.current()
    host, group = (alert.get("host") or "").upper(), (alert.get("device_group") or "").lower()
    for rule in org.assets.get("rules", []):
        if _rule_matches(rule, host, group):
            return rule
    return None


def asset_criticality(alert, org=None):
    """Return (level, reason) from the org's asset rules (first match wins)."""
    org = org or orgmod.current()
    rule = asset_rule(alert, org)
    if rule:
        conds = ", ".join("{}={}".format(k, v) for k, v in rule.items() if k not in ("level", "tier0"))
        return rule["level"], "asset rule ({}) -> {}".format(conds, rule["level"])
    level = org.assets.get("default", "medium")
    return level, "no asset rule matched '{}' / '{}'; default {}".format(
        alert.get("host"), alert.get("device_group") or "unknown", level)


def tier0_signals(alert, org=None):
    """Deterministic Tier-0 evidence in the alert itself."""
    org = org or orgmod.current()
    reasons = []
    rule = asset_rule(alert, org)
    if rule and rule.get("tier0"):
        reasons.append("Tier-0 asset ({})".format(alert.get("host")))
    names = org.tier0_accounts()
    if names:
        pattern = re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b", re.I)
        m = pattern.search(" ".join([alert.get("user", ""), alert.get("command_line", ""), alert.get("context", "")]))
        if m:
            reasons.append("Tier-0 account/group referenced: " + m.group(0))
    return reasons


def _level(score, levels):
    for n in (1, 2, 3):
        if score >= levels["SEV{}".format(n)]:
            return n
    return 4


def score_severity(criticality, impact, scope, tier0=False, destructive=False,
                   exfiltration=False, disabled_account=False, org=None):
    """Apply the rubric. Returns {'severity': 'SEV2', 'score': 5, 'breakdown': ..., 'reasons': [...]}."""
    levels = (org or orgmod.current()).severity["levels"]
    criticality = criticality if criticality in CRITICALITY_POINTS else "medium"
    impact = impact if impact in IMPACT_POINTS else "executed"   # unknown impact: assume it ran
    scope = scope if scope in SCOPE_POINTS else "single_host"
    if destructive:
        impact = "destructive"
    breakdown = {"asset_criticality": (criticality, CRITICALITY_POINTS[criticality]),
                 "impact": (impact, IMPACT_POINTS[impact]), "scope": (scope, SCOPE_POINTS[scope])}
    score = sum(p for _, p in breakdown.values())
    level = _level(score, levels)
    reasons = ["score {} = criticality {} + impact {} + scope {}".format(
        score, CRITICALITY_POINTS[criticality], IMPACT_POINTS[impact], SCOPE_POINTS[scope])]
    # Safety overrides: fixed in code, not configurable per org
    if tier0 or impact == "destructive":
        level = 1
        reasons.append("SEV1 override: " + ("Tier-0 involved" if tier0 else "destructive impact"))
    if exfiltration:
        level = min(level - 1, 2) if level > 1 else 1
        reasons.append("exfiltration override: raised one level, minimum SEV2")
    if disabled_account and level > 2:
        level = 2
        reasons.append("disabled-account override: minimum SEV2")
    return {"severity": "SEV{}".format(level), "score": score,
            "breakdown": {k: {"value": v, "points": p} for k, (v, p) in breakdown.items()},
            "reasons": reasons}


def response_for(severity, org=None):
    return (org or orgmod.current()).severity["response"].get(severity, "")
