"""Org packs: everything that differs between organizations, loaded from orgs/<id>/.

  orgs/<id>/org.json        profile (see capstone/templates/org/org.json for the annotated template)
  orgs/<id>/playbooks/      response playbooks (Markdown)
  orgs/<id>/knowledge/      roster, allowlists, known false positives, change calendar...
  orgs/<id>/sources/        one field-mapping file per alerting system
  orgs/<id>/samples/        example payloads

The engine reads policy only through the Org object, so swapping the pack swaps the
organization: different alerts, playbooks, assets, people and escalation rules, same agents.
"""
import csv
import glob
import json
import os
import re

from . import config

LEVELS = ("critical", "high", "medium", "low")
DEFAULT_SIGNALS = {
    "destructive": ["T1486", "T1490", "T1485", "T1561"],
    "exfiltration": ["T1567", "T1048", "T1041", "T1537", "T1020"],
    "credential_theft": ["T1003", "T1558", "T1555", "T1552"],
}
DEFAULT_SEVERITY = {
    "levels": {"SEV1": 7, "SEV2": 5, "SEV3": 3},
    "response": {"SEV1": "page IR on-call immediately; CISO informed within 1 hour",
                 "SEV2": "page IR on-call; IR lead acknowledges within 30 minutes",
                 "SEV3": "war-room and case; handled in business hours",
                 "SEV4": "case only"},
}
DEFAULT_DISPOSITION = {"close_threshold": 0.85, "confidence_score": {"High": 0.9, "Medium": 0.7, "Low": 0.5}}


class OrgError(ValueError):
    pass


class Org:
    def __init__(self, path):
        self.dir = os.path.abspath(path)
        cfg_path = os.path.join(self.dir, "org.json")
        if not os.path.exists(cfg_path):
            raise OrgError("No org.json in {}".format(self.dir))
        with open(cfg_path, encoding="utf-8") as f:
            try:
                self.cfg = json.load(f)
            except ValueError as e:
                raise OrgError("org.json is not valid JSON: {}".format(e))
        self.id = self.cfg.get("id") or os.path.basename(self.dir)
        self.name = self.cfg.get("name", self.id)
        self.disposition = dict(DEFAULT_DISPOSITION, **self.cfg.get("disposition", {}))
        self.severity = {"levels": dict(DEFAULT_SEVERITY["levels"], **self.cfg.get("severity", {}).get("levels", {})),
                         "response": dict(DEFAULT_SEVERITY["response"],
                                          **self.cfg.get("severity", {}).get("response", {}))}
        self.signals = dict(DEFAULT_SIGNALS, **self.cfg.get("signals", {}))
        self.assets = self.cfg.get("assets", {"default": "medium", "rules": []})
        self.identity = self.cfg.get("identity", {})
        self.policy = self.cfg.get("escalation_policy", [])
        self.actuators = self.cfg.get("actuators", {})
        self.ingest = self.cfg.get("ingest", {})
        self._roster = None
        self._sources = None

    # ---------------------------------------------------------------- paths
    def resolve(self, rel):
        return os.path.normpath(os.path.join(self.dir, rel))

    def knowledge_files(self, kind):
        """Files for the 'triage' or 'ir' knowledge base, from the globs in org.json."""
        patterns = self.cfg.get("knowledge", {}).get(kind)
        if patterns is None:   # conventional layout
            patterns = ["playbooks/*.md", "knowledge/*.md"] if kind == "triage" else ["playbooks/*.md", "ir/*.md"]
        files = []
        for p in patterns:
            files += sorted(glob.glob(self.resolve(p)))
        return list(dict.fromkeys(f for f in files if f.lower().endswith(".md")))

    @property
    def index_dir(self):
        return os.path.join(self.dir, ".index")

    @property
    def state_dir(self):
        return os.path.join(config.ROOT, "runs", self.id)

    # ---------------------------------------------------------------- identity
    def roster(self):
        """{account: {'status': str, 'row': dict}} from the roster file (Markdown table or CSV)."""
        if self._roster is None:
            self._roster = {}
            ident = self.identity
            path = ident.get("roster_file")
            if path:
                rows = read_table(self.resolve(path))
                acol, scol = ident.get("account_column", "Account"), ident.get("status_column", "Status")
                for row in rows:
                    acct = row.get(acol, "").strip().lower()
                    if acct:
                        self._roster[acct] = {"status": row.get(scol, ""), "row": row}
        return self._roster

    def disabled_accounts(self):
        marker = self.identity.get("disabled_marker", "DISABLED").upper()
        return {a: v["status"] for a, v in self.roster().items() if marker in v["status"].upper()}

    def privileged_prefixes(self):
        return [p.lower() for p in self.identity.get("privileged_prefixes", [])]

    def tier0_accounts(self):
        return self.identity.get("tier0_accounts", [])

    # ---------------------------------------------------------------- sources
    def sources(self):
        """{name: mapping dict} from sources/*.json."""
        if self._sources is None:
            self._sources = {}
            for p in sorted(glob.glob(os.path.join(self.dir, "sources", "*.json"))):
                with open(p, encoding="utf-8") as f:
                    m = json.load(f)
                self._sources[m.get("name") or os.path.splitext(os.path.basename(p))[0]] = m
        return self._sources

    def summary(self):
        return {"id": self.id, "name": self.name, "dir": self.dir, "disposition": self.disposition,
                "severity": self.severity, "assets": self.assets, "signals": self.signals,
                "identity": {k: v for k, v in self.identity.items()},
                "escalation_policy": self.policy, "actuators": self.actuators,
                "sources": {k: {"description": v.get("description", ""), "type": v.get("type", "json")}
                            for k, v in self.sources().items()},
                "knowledge": {k: [os.path.relpath(f, config.ROOT) for f in self.knowledge_files(k)]
                              for k in ("triage", "ir")}}


def read_table(path):
    """Rows of a Markdown pipe table or a CSV file, as dicts keyed by header."""
    if path.lower().endswith(".csv"):
        with open(path, encoding="utf-8", newline="") as f:
            return [{k.strip(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(f)]
    rows, header = [], None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("|") or re.match(r"^\|[\s:|-]+\|$", line):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if header is None:
                header = cells
            else:
                rows.append(dict(zip(header, cells)))
    return rows


# ---------------------------------------------------------------- active org

_current = None


def org_path(org_id):
    return org_id if os.path.isdir(org_id) else os.path.join(config.ORGS_DIR, org_id)


def activate(org_id=None):
    """Load an org pack and point state and indexes at it. Returns the Org."""
    global _current
    _current = Org(org_path(org_id or config.DEFAULT_ORG))
    config.STATE_DIR = _current.state_dir
    config.TRIAGE_INDEX = os.path.join(_current.index_dir, "triage")
    config.IR_INDEX = os.path.join(_current.index_dir, "ir")
    return _current


def current():
    return _current or activate()


def available():
    return sorted(d for d in os.listdir(config.ORGS_DIR)
                  if os.path.exists(os.path.join(config.ORGS_DIR, d, "org.json")))
