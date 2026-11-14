"""Validate an org pack before it is used:  python -m capstone org validate [--org <id>]

Checks org.json, asset rules, the identity roster, knowledge files and playbook format,
source mappings, the escalation policy (including the human-gate invariant) and actuators.
Returns findings as (level, area, message) with level 'error', 'warning' or 'ok'.
"""
import os
import re

from . import org as orgmod
from . import policy
from .connectors import alert_source
from .severity import CRITICALITY_POINTS

PLAYBOOK_ID = re.compile(r"^#\s+(PB(?:-[A-Z0-9]+)+-\d+)\b")
ACTUATOR_TYPES = {"mock", "slack_webhook", "pagerduty", "webhook"}
ASSET_KEYS = {"host_prefix", "device_group", "device_group_prefix", "device_group_contains", "level", "tier0"}


def check_playbook(path):
    """Problems with one Markdown knowledge file; playbooks get the stricter checks."""
    out, name = [], os.path.basename(path)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    lines = text.splitlines()
    if not lines or not lines[0].startswith("# "):
        out.append(("error", "knowledge", "{}: first line must be a '# Title' heading".format(name)))
        return out
    sections = re.findall(r"^## (.+)$", text, re.M)
    is_table = sum(l.startswith("|") for l in lines) > 2
    if not sections and not is_table:
        out.append(("warning", "knowledge", "{}: no '## ' sections or table - it becomes one large chunk, "
                                            "which retrieves poorly".format(name)))
    if name.startswith("playbook"):
        if not PLAYBOOK_ID.match(lines[0]):
            out.append(("error", "knowledge", "{}: playbook title must start with an ID like "
                                              "'# PB-CRED-01 Credential Access' or '# PB-ORG-CRED-01 ...'".format(name)))
        if not re.search(r"within \d+ (minute|hour)", text, re.I):
            out.append(("warning", "knowledge", "{}: no 'within N minutes/hours' SLA; the severity policy "
                                                "response target will be used".format(name)))
    return out


def check_mapping(name, m):
    out = []
    kind = m.get("type", "json")
    if kind == "builtin-edr-text":
        return [("ok", "sources", "{}: built-in EDR text/JSON parser".format(name))]
    if kind != "json":
        return [("error", "sources", "{}: type must be 'json' or 'builtin-edr-text'".format(name))]
    fields = m.get("fields", {})
    unknown = sorted(set(fields) - set(alert_source.CANONICAL))
    if unknown:
        out.append(("error", "sources", "{}: unknown canonical fields {} (valid: {})".format(
            name, unknown, ", ".join(alert_source.CANONICAL))))
    missing = [f for f in alert_source.REQUIRED if f not in fields and f not in m.get("constants", {})]
    if missing:
        out.append(("error", "sources", "{}: required fields not mapped: {}".format(name, missing)))
    if not m.get("id_field"):
        out.append(("warning", "sources", "{}: no id_field - webhook retries cannot be de-duplicated".format(name)))
    if not out:
        out.append(("ok", "sources", "{}: {} fields mapped".format(name, len(fields))))
    return out


def validate(org):
    f = []
    # --- profile basics
    disp = org.disposition
    if not 0 < disp.get("close_threshold", 0) <= 1.01:
        f.append(("error", "disposition", "close_threshold must be in (0, 1.01]; 1.01 = never auto-close"))
    lv = org.severity["levels"]
    if not lv["SEV1"] > lv["SEV2"] > lv["SEV3"] >= 0:
        f.append(("error", "severity", "levels must satisfy SEV1 > SEV2 > SEV3 >= 0 (got {})".format(lv)))
    # --- assets
    if org.assets.get("default", "medium") not in CRITICALITY_POINTS:
        f.append(("error", "assets", "default level must be one of {}".format(list(CRITICALITY_POINTS))))
    for i, rule in enumerate(org.assets.get("rules", [])):
        if rule.get("level") not in CRITICALITY_POINTS:
            f.append(("error", "assets", "rule {}: level must be one of {}".format(i + 1, list(CRITICALITY_POINTS))))
        if set(rule) - ASSET_KEYS:
            f.append(("error", "assets", "rule {}: unknown keys {}".format(i + 1, sorted(set(rule) - ASSET_KEYS))))
        if not set(rule) & {"host_prefix", "device_group", "device_group_prefix", "device_group_contains"}:
            f.append(("error", "assets", "rule {}: needs at least one match condition".format(i + 1)))
    if not org.assets.get("rules"):
        f.append(("warning", "assets", "no asset rules: every host gets the default criticality"))
    # --- identity
    ident = org.identity
    if ident.get("roster_file"):
        path = org.resolve(ident["roster_file"])
        if not os.path.exists(path):
            f.append(("error", "identity", "roster_file not found: {}".format(path)))
        else:
            rows = orgmod.read_table(path)
            acol, scol = ident.get("account_column", "Account"), ident.get("status_column", "Status")
            if rows and (acol not in rows[0] or scol not in rows[0]):
                f.append(("error", "identity", "roster columns '{}'/'{}' not found; available: {}".format(
                    acol, scol, list(rows[0]))))
            else:
                f.append(("ok", "identity", "roster: {} accounts, {} disabled".format(
                    len(org.roster()), len(org.disabled_accounts()))))
    else:
        f.append(("warning", "identity", "no roster_file: disabled/unlisted-account guardrails are off"))
    # --- knowledge
    for kind in ("triage", "ir"):
        files = org.knowledge_files(kind)
        if not files:
            f.append(("error", "knowledge", "no {} knowledge files matched".format(kind)))
        else:
            f.append(("ok", "knowledge", "{}: {} files".format(kind, len(files))))
    for path in sorted(set(org.knowledge_files("triage")) | set(org.knowledge_files("ir"))):
        f += check_playbook(path)
    for kind in ("triage", "ir"):
        if not os.path.exists(os.path.join(org.index_dir, kind, "soc.faiss")):
            f.append(("warning", "knowledge", "{} index not built: run python -m capstone org ingest".format(kind)))
    # --- sources
    try:
        sources = org.sources()
        if not sources:
            f.append(("error", "sources", "no sources/*.json: nothing can send alerts"))
        for name, m in sources.items():
            f += check_mapping(name, m)
    except ValueError as e:
        f.append(("error", "sources", "invalid JSON in sources/: {}".format(e)))
    # --- escalation policy
    problems = policy.validate(org.policy)
    f += [(lvl, "policy", msg) for lvl, msg in problems]
    if not any(lvl == "error" for lvl, _ in problems):
        gated = sum(policy.mode_for(r) == "gated" for r in org.policy)
        f.append(("ok", "policy", "{} rules ({} human-gated)".format(len(org.policy), gated)))
    # --- actuators
    for ch in ("chat", "pager", "case"):
        spec = org.actuators.get(ch, {"type": "mock"})
        kind = spec.get("type", "mock")
        if kind not in ACTUATOR_TYPES:
            f.append(("error", "actuators", "{}: unknown type '{}' (known: {})".format(ch, kind, sorted(ACTUATOR_TYPES))))
        elif kind != "mock":
            env = spec.get("url_env") or spec.get("routing_key_env")
            if not env:
                f.append(("error", "actuators", "{}: {} needs url_env / routing_key_env".format(ch, kind)))
            elif not os.environ.get(env):
                f.append(("warning", "actuators", "{}: ${} not set - will run as mock".format(ch, env)))
            else:
                f.append(("ok", "actuators", "{}: {} (live)".format(ch, kind)))
        else:
            f.append(("ok", "actuators", "{}: mock".format(ch)))
    return f


def errors(findings):
    return [x for x in findings if x[0] == "error"]
