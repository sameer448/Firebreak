"""Persistent state under runs/: append-only audit log, processed alerts, escalations (dedup),
incidents, the approval queue, and the actuator log.

Plain JSON files so a reviewer can open them; a production build would use a database.
Every read-modify-write holds one process-wide lock, because the web app writes from its
pipeline worker thread and from approval requests at the same time.
"""
import datetime
import json
import os
import threading

from . import config

LOCK = threading.RLock()
FILES = ("audit.jsonl", "alerts.json", "escalations.json", "counters.json", "incidents.json",
         "approvals.json", "actions.jsonl", "ingested.json")


def now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _path(name):
    os.makedirs(config.STATE_DIR, exist_ok=True)
    return os.path.join(config.STATE_DIR, name)


def _load(name, default):
    p = _path(name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _save(name, data):
    with open(_path(name), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _read_jsonl(name):
    p = _path(name)
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def _append_jsonl(name, entry):
    with LOCK, open(_path(name), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def audit(actor, event, subject, rationale, **details):
    """Every decision and action carries a why. One JSON object per line."""
    entry = {"ts": now(), "actor": actor, "event": event, "subject": subject, "rationale": rationale}
    entry.update(details)
    _append_jsonl("audit.jsonl", entry)
    return entry


def load_audit():
    return _read_jsonl("audit.jsonl")


def log_action(entry):
    _append_jsonl("actions.jsonl", entry)


def load_actions():
    return _read_jsonl("actions.jsonl")


def next_id(prefix):
    with LOCK:
        counters = _load("counters.json", {})
        counters[prefix] = counters.get(prefix, 0) + 1
        _save("counters.json", counters)
    return "{}-{}-{:04d}".format(prefix, datetime.datetime.utcnow().year, counters[prefix])


# ---- Processed alerts (what the SOC agent decided, for the UI and reviewers) ----

def save_alert(record):
    with LOCK:
        data = _load("alerts.json", {})
        data[record["alert_id"]] = record
        _save("alerts.json", data)


def load_alerts():
    return _load("alerts.json", {})


# ---- Webhook ingestion: vendor alert id -> first receipt (retries are not re-processed) ----

def claim_ingest(key, record):
    """Atomically record a vendor alert. Returns the existing record if this key was seen before."""
    with LOCK:
        data = _load("ingested.json", {})
        if key in data:
            return data[key]
        data[key] = dict(record, received_at=now())
        _save("ingested.json", data)
        return None


# ---- Escalations: dedup on the idempotency key ----

def find_open_escalation(idempotency_key):
    return _load("escalations.json", {}).get(idempotency_key)


def save_escalation(package):
    with LOCK:
        data = _load("escalations.json", {})
        data[package["idempotency_key"]] = package
        _save("escalations.json", data)


def load_escalations():
    return _load("escalations.json", {})


# ---- Incidents ----

def save_incident(incident):
    with LOCK:
        data = _load("incidents.json", {})
        data[incident["incident_id"]] = incident
        _save("incidents.json", data)


def load_incidents():
    return _load("incidents.json", {})


# ---- Approval queue for gated actions ----

def queue_approval(action):
    with LOCK:
        data = _load("approvals.json", {})
        action = dict(action, status="pending", queued_at=now())
        data[action["action_id"]] = action
        _save("approvals.json", data)
    return action


def load_approvals():
    return _load("approvals.json", {})


def resolve_approval(action_id, status, by, note=""):
    with LOCK:
        data = _load("approvals.json", {})
        if action_id not in data:
            raise KeyError("No such approval: " + action_id)
        if data[action_id]["status"] != "pending":
            raise ValueError("{} is already {}".format(action_id, data[action_id]["status"]))
        data[action_id].update(status=status, resolved_by=by, resolved_at=now(), note=note)
        _save("approvals.json", data)
        return data[action_id]


def reset():
    """Clear all run state (demo convenience)."""
    with LOCK:
        for name in FILES:
            p = os.path.join(config.STATE_DIR, name)
            if os.path.exists(p):
                os.remove(p)
