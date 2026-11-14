"""SOC -> IR web console (FastAPI).

  python -m capstone.web            then open http://127.0.0.1:8765
  API docs (Swagger):               http://127.0.0.1:8765/docs

The console serves one org pack (python -m capstone.web --org <id>, or $SOC_ORG). Alerts arrive
from the console, the CLI, or alerting systems through the authenticated webhook
POST /api/ingest/{source}, which maps vendor JSON with the org's sources/<source>.json.

One background worker runs alerts through the pipeline one at a time (Ollama serves one
generation at a time on a laptop, and each triage takes ~1-2 minutes on CPU). The browser
polls /api/jobs/<id> for the live trace. Approvals call the same approve/deny functions as the CLI,
so the human gate is identical in every interface.
"""
import glob
import hmac
import json
import os
import queue
import secrets
import threading
import urllib.request
import uuid

from .. import retrieval  # noqa: F401  (puts .rag_libs on sys.path for fastapi/pydantic)
from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import config, state
from .. import org as orgmod
from ..orchestrator import Pipeline, action_status, approve, deny, to_alert
from ..validate import validate

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
DEMO_DIR = os.path.join(config.ROOT, "data", "capstone_demo")
MAX_ALERT_CHARS = 20000
MAX_BATCH = 50

ORG = orgmod.current()
_KEY_ENV = ORG.ingest.get("api_key_env", "SOC_INGEST_KEY")
INGEST_KEY = os.environ.get(_KEY_ENV) or secrets.token_urlsafe(24)
INGEST_KEY_SOURCE = "env ${}".format(_KEY_ENV) if os.environ.get(_KEY_ENV) else "generated at startup (printed in the terminal)"

app = FastAPI(title="Firebreak: SOC -> IR Agent Console",
              description="Agentic CSOC triage and incident response with a human approval gate. "
                          "Active org pack: {}".format(ORG.id))
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ---------------------------------------------------------------- pipeline worker

class Job:
    def __init__(self, data, label, source="edr-text"):
        self.id = uuid.uuid4().hex[:8]
        self.data, self.label, self.source = data, label, source
        self.status, self.lines, self.result, self.error = "queued", [], None, ""
        self.created = state.now()

    def view(self, with_lines=True):
        out = {"job_id": self.id, "label": self.label, "source": self.source, "status": self.status,
               "created": self.created, "error": self.error, "result": self.result}
        if with_lines:
            out["lines"] = self.lines
        return out


def enqueue(data, label, source):
    job = Job(data, label[:80], source)
    JOBS[job.id] = job
    JOB_ORDER.append(job.id)
    QUEUE.put(job)
    return job


JOBS, JOB_ORDER, QUEUE = {}, [], queue.Queue()
_pipeline = None


def worker():
    global _pipeline
    while True:
        job = QUEUE.get()
        job.status = "running"
        try:
            if _pipeline is None:
                job.lines.append("Loading agents and vector indexes...")
                _pipeline = Pipeline(out=None)
            _pipeline.out = job.lines.append
            res = _pipeline.process_text(job.data, label=job.label, source=job.source)
            rec = state.load_alerts().get(res["alert_id"], {})
            job.result = {"alert_id": res["alert_id"], "disposition": res["disposition"],
                          "escalation_id": rec.get("escalation_id"), "incident_id": rec.get("incident_id"),
                          "merged": res.get("merged", False)}
            job.status = "done"
        except Exception as e:  # surface the failure in the UI instead of killing the worker
            job.status, job.error = "error", "{}: {}".format(type(e).__name__, e)
            job.lines.append("ERROR " + job.error)
        finally:
            QUEUE.task_done()


threading.Thread(target=worker, daemon=True).start()


# ---------------------------------------------------------------- models

class AlertIn(BaseModel):
    text: str = Field(..., description="Raw alert: EDR text for 'edr-text', or a JSON payload for a mapped source")
    label: str = Field("pasted alert", description="Display name for the alert")
    source: str = Field("edr-text", description="One of the org's sources (see /api/org)")


class Decision(BaseModel):
    by: str = Field(..., min_length=1, max_length=80, description="Name of the approving human")
    note: str = Field("", max_length=500)


# ---------------------------------------------------------------- routes

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/health")
def health():
    """Ollama reachability, required models, and vector indexes."""
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3) as r:
            names = [m["name"] for m in json.loads(r.read())["models"]]
        ollama_ok = True
    except Exception:
        names, ollama_ok = [], False

    def has(model):
        return any(n == model or n.startswith(model + ":") for n in names)

    return {"ollama": ollama_ok,
            "models": {m: has(m) for m in (config.TRIAGE_MODEL, config.IR_MODEL, "nomic-embed-text")},
            "indexes": {"triage": os.path.exists(os.path.join(config.TRIAGE_INDEX, "soc.faiss")),
                        "ir": os.path.exists(os.path.join(config.IR_INDEX, "soc.faiss"))},
            "queue_depth": QUEUE.qsize()}


@app.get("/api/config")
def get_config():
    return {"org": ORG.id, "triage_model": config.TRIAGE_MODEL, "ir_model": config.IR_MODEL,
            "close_threshold": ORG.disposition["close_threshold"],
            "confidence_score": ORG.disposition["confidence_score"]}


@app.get("/api/org")
def get_org():
    """The active org pack: profile, sources (with webhook URLs), policy, and validation results."""
    summary = ORG.summary()
    summary["validation"] = [{"level": l, "area": a, "message": m} for l, a, m in validate(ORG)]
    summary["ingest"] = {"endpoint": "/api/ingest/{source}", "header": "X-API-Key", "key_source": INGEST_KEY_SOURCE,
                         "sources": sorted(ORG.sources())}
    return summary


@app.get("/api/demo-alerts")
def demo_alerts():
    """Sample alerts for the active org: data/capstone_demo for demo-corp, plus orgs/<id>/samples/*.
    Sample files are named <source>_<anything>.json so the console knows which mapping to use."""
    out = []
    if ORG.id == "demo-corp":
        for p in sorted(glob.glob(os.path.join(DEMO_DIR, "*.txt"))):
            with open(p, encoding="utf-8") as f:
                out.append({"name": os.path.basename(p), "text": f.read(), "source": "edr-text"})
    sources = ORG.sources()
    for p in sorted(glob.glob(os.path.join(ORG.dir, "samples", "*"))):
        name = os.path.basename(p)
        source = next((s for s in sorted(sources, key=len, reverse=True) if name.startswith(s + "_")), None)
        if source:
            with open(p, encoding="utf-8") as f:
                out.append({"name": name, "text": f.read(), "source": source})
    return out


def _check_source(source, data):
    """Map now so a bad payload is rejected at submission, not minutes later in the worker."""
    if source not in ORG.sources():
        raise HTTPException(400, "Unknown source '{}' (configured: {})".format(source, ", ".join(sorted(ORG.sources()))))
    try:
        return to_alert(ORG, data, source)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/alerts", status_code=202)
def submit_alert(body: AlertIn):
    if not body.text.strip() or len(body.text) > MAX_ALERT_CHARS:
        raise HTTPException(400, "Alert text must be 1-{} characters".format(MAX_ALERT_CHARS))
    _check_source(body.source, body.text)
    job = enqueue(body.text, body.label, body.source)
    return {"job_id": job.id, "position": QUEUE.qsize()}


@app.post("/api/ingest/{source}", status_code=202)
def ingest(source: str, payload=Body(...), x_api_key: str = Header(None)):
    """Webhook for alerting systems. Body: one vendor alert object or a list of them.
    Authenticated with the X-API-Key header. Retries with the same vendor alert id are not re-processed."""
    if not x_api_key or not hmac.compare_digest(x_api_key, INGEST_KEY):
        raise HTTPException(401, "Missing or invalid X-API-Key")
    items = payload if isinstance(payload, list) else [payload]
    if not items or len(items) > MAX_BATCH:
        raise HTTPException(400, "Send 1-{} alerts per request".format(MAX_BATCH))
    results = []
    for item in items:
        if not isinstance(item, (dict, str)) or len(json.dumps(item)) > MAX_ALERT_CHARS:
            raise HTTPException(400, "Each alert must be a JSON object under {} characters".format(MAX_ALERT_CHARS))
        alert = _check_source(source, item)
        key = "{}:{}".format(source, alert.get("vendor_alert_id") or alert["alert_id"])
        seen = state.claim_ingest(key, {"alert_id": alert["alert_id"], "source": source})
        if seen:
            results.append({"status": "duplicate", "alert_id": seen["alert_id"], "received_at": seen["received_at"]})
            continue
        label = "{} {}".format(source, alert.get("vendor_alert_id") or alert["alert_id"])
        job = enqueue(item, label, source)
        results.append({"status": "queued", "job_id": job.id, "alert_id": alert["alert_id"]})
    return {"accepted": sum(r["status"] == "queued" for r in results), "results": results}


@app.get("/api/jobs")
def list_jobs():
    return [JOBS[j].view(with_lines=False) for j in reversed(JOB_ORDER[-50:])]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "No such job")
    return JOBS[job_id].view()


@app.get("/api/alerts")
def list_alerts():
    rows = sorted(state.load_alerts().values(), key=lambda r: r["processed_at"], reverse=True)
    return [_alert_row(r) for r in rows]


def _alert_row(r):
    row = {k: r[k] for k in ("alert_id", "label", "processed_at", "disposition", "confidence", "rationale",
                             "escalation_id", "incident_id", "merged")}
    row.update(host=r["alert"].get("host"), user=r["alert"].get("user"), detection=r["alert"].get("detection"),
               verdict=r["triage"]["verdict"], confidence_label=r["triage"]["confidence_label"],
               guardrails=[g["rule"] for g in r["guardrails"]])
    return row


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    rec = state.load_alerts().get(alert_id)
    if not rec:
        raise HTTPException(404, "No such alert")
    return rec


@app.get("/api/incidents")
def list_incidents():
    approvals = state.load_approvals()
    out = []
    for inc in sorted(state.load_incidents().values(), key=lambda i: i["opened_at"], reverse=True):
        pending = sum(approvals.get(a["action_id"], {}).get("status") == "pending" for a in inc.get("actions", []))
        out.append({"incident_id": inc["incident_id"], "severity": inc["severity"], "opened_at": inc["opened_at"],
                    "hosts": inc["hosts"], "attack_techniques": inc["attack_techniques"],
                    "playbook_id": inc["playbook_id"], "summary": inc["facts"]["incident_summary"],
                    "pending_approvals": pending})
    return out


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    inc = state.load_incidents().get(incident_id)
    if not inc:
        raise HTTPException(404, "No such incident")
    approvals = state.load_approvals()
    executed = {a["action_id"]: a for a in state.load_actions()}
    actions = []
    for a in inc.get("actions", []):
        status, intent, by = action_status(a["action_id"], approvals, executed)
        actions.append(dict(a, status=status, intent=intent, by=by))
    esc = next((e for e in state.load_escalations().values() if e["escalation_id"] == inc["escalation_id"]), None)
    timeline = [e for e in state.load_audit()
                if e["subject"] in [incident_id, inc["escalation_id"]] + [a["action_id"] for a in actions]
                or e.get("escalation_id") == inc["escalation_id"]]
    return dict(inc, actions=actions, escalation=esc, timeline=timeline)


@app.get("/api/approvals")
def list_approvals(status: str = "pending"):
    items = sorted(state.load_approvals().values(), key=lambda a: a["queued_at"], reverse=True)
    return [a for a in items if status == "all" or a["status"] == status]


def _decide(action_id, body, fn):
    try:
        return fn(action_id, body.by.strip(), body.note.strip(), out=lambda *_: None)
    except KeyError:
        raise HTTPException(404, "No such approval")
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.post("/api/approvals/{action_id}/approve")
def approve_action(action_id: str, body: Decision):
    return _decide(action_id, body, approve)


@app.post("/api/approvals/{action_id}/deny")
def deny_action(action_id: str, body: Decision):
    return _decide(action_id, body, deny)


@app.get("/api/audit")
def get_audit(limit: int = 200):
    return list(reversed(state.load_audit()))[:max(1, min(limit, 2000))]


@app.get("/api/stats")
def stats():
    alerts = state.load_alerts().values()
    disp = {"CLOSE": 0, "ASK_HUMAN": 0, "ESCALATE": 0}
    for a in alerts:
        disp[a["disposition"]] = disp.get(a["disposition"], 0) + 1
    sev = {}
    for i in state.load_incidents().values():
        sev[i["severity"]] = sev.get(i["severity"], 0) + 1
    return {"alerts": len(alerts), "dispositions": disp, "incidents": sum(sev.values()), "severity": sev,
            "pending_approvals": sum(a["status"] == "pending" for a in state.load_approvals().values()),
            "guardrail_hits": sum(bool(a["guardrails"]) for a in alerts),
            "merged": sum(a.get("merged", False) for a in alerts)}


@app.get("/api/eval")
def eval_results(data: str = "test"):
    """Disposition eval over cached model answers (run capstone.eval_disposition first)."""
    from ..eval_disposition import THRESHOLDS, score
    path = os.path.join(config.ROOT, "results", "disposition_{}.jsonl".format(os.path.basename(data)))
    if not os.path.exists(path):
        return {"available": False}
    with open(path, encoding="utf-8") as f:
        records = [json.loads(l) for l in f if l.strip()]
    policies = []
    for use_g in (False, True):
        for thr in THRESHOLDS:
            s, _ = score(records, use_g, thr)
            policies.append(dict(s, policy="model + guardrails" if use_g else "model only",
                                 threshold="never" if thr > 1 else thr,
                                 default=use_g and thr == ORG.disposition["close_threshold"]))
    _, rows = score(records, True, ORG.disposition["close_threshold"])
    cols = ["scenario", "label", "verdict", "confidence", "expected", "disposition", "correct", "guardrails",
            "rationale"]
    return {"available": True, "n": len(records), "policies": policies,
            "rows": [dict(zip(cols, r)) for r in rows]}


@app.post("/api/reset")
def reset_state():
    if not QUEUE.empty() or any(j.status == "running" for j in JOBS.values()):
        raise HTTPException(409, "Wait for running alerts to finish before resetting")
    state.reset()
    JOBS.clear()
    del JOB_ORDER[:]
    return {"reset": True}
