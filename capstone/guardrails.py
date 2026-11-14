"""Deterministic guardrails that bound the triage model's autonomy.

The model can be wrong (a 3B model called an offboarded admin's PsExec run "normal SCCM
activity"), and alert text is attacker-influenced (command lines, file names and context
fields can carry instructions). These checks run in code, cannot be talked out of, and can
only make a disposition MORE cautious, never less.

Org-specific inputs (the privileged-account roster, privileged prefixes, Tier-0 assets and
accounts) come from the active org pack; the injection patterns are part of the engine.
"""
import re

from . import org as orgmod
from .severity import tier0_signals

INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
    r"\bverdict\s*[:=]",
    r"\b(auto-?close|close (this|the) alert|mark (this |it )?as (benign|false positive))",
    r"\bdo not (escalate|alert|page)",
    r"\byou are (now |a |an )",
    r"\bsystem prompt\b",
    r"\b(soc|analyst|security team) (note|instruction)s?\s*:",
]
UNTRUSTED_FIELDS = ("command_line", "process_image", "process_tree", "context", "network", "detection")


def _account(alert):
    return (alert.get("user") or "").split("\\")[-1].split("@")[0].lower()


def disabled_account_hit(alert, org=None):
    org = org or orgmod.current()
    user, disabled = _account(alert), org.disabled_accounts()
    if user in disabled:
        return "account {} is disabled per the privileged-account roster: {}".format(user, disabled[user])
    return None


def unlisted_admin_hit(alert, org=None):
    """Roster policy: a privileged account that is not on the roster has no approved scope."""
    org = org or orgmod.current()
    user = _account(alert)
    if any(user.startswith(p) for p in org.privileged_prefixes()) and user not in org.roster():
        return "privileged account {} is not in the roster (no approved scope)".format(user)
    return None


def injection_hit(alert):
    """Instruction-like text inside attacker-controllable alert fields (OWASP LLM01)."""
    for field in UNTRUSTED_FIELDS:
        for pat in INJECTION_PATTERNS:
            m = re.search(pat, alert.get(field) or "", re.I)
            if m:
                return "possible prompt injection in {}: '{}'".format(field, m.group(0))
    return None


def check(alert, org=None):
    """Return a list of {'rule', 'effect', 'reason'} guardrail findings for this alert."""
    org = org or orgmod.current()
    findings = []
    reason = disabled_account_hit(alert, org)
    if reason:
        findings.append({"rule": "disabled_account", "effect": "force_escalate", "reason": reason})
    reason = unlisted_admin_hit(alert, org)
    if reason:
        findings.append({"rule": "unlisted_admin", "effect": "no_auto_close", "reason": reason})
    for reason in tier0_signals(alert, org):
        findings.append({"rule": "tier0", "effect": "no_auto_close", "reason": reason})
    reason = injection_hit(alert)
    if reason:
        findings.append({"rule": "prompt_injection", "effect": "no_auto_close", "reason": reason})
    return findings
