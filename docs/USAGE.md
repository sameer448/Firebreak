# Usage Guide

1. [Requirements](#1-requirements)
2. [Installation](#2-installation)
3. [Web console](#3-web-console)
4. [Command line](#4-command-line)
5. [REST API](#5-rest-api)
6. [Evaluation](#6-evaluation)
7. [Configuration](#7-configuration)
8. [Files the system writes](#8-files-the-system-writes)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Requirements

| Component | Version / note |
|---|---|
| Python | 3.8 or later (developed and tested on 3.8.2) |
| Ollama | running on `localhost:11434` |
| Models | `soc-triage` (fine-tuned, built from `Modelfile`), `llama3.1:8b`, `nomic-embed-text` |
| Org pack | `orgs/demo-corp/` (default) or your own (see [INTEGRATION.md](INTEGRATION.md)) |
| RAM | 16 GB recommended (the 8B model needs about 5 GB) |
| GPU | optional; on CPU expect 1–2 minutes per triage and 1–2 minutes per IR assessment |

---

## 2. Installation

From the repository root:

```bash
# Models
ollama pull hf.co/Sgoyal16/soc-triage-llama3.2-3b-GGUF:Q4_K_M
ollama create soc-triage -f Modelfile
ollama pull llama3.1:8b
ollama pull nomic-embed-text

# Python libraries, into the private .rag_libs folder used by rag.py and capstone/
python -m pip install --target .rag_libs -r requirements.txt

# Org pack: validate it, then build its two vector indexes (triage + IR)
python -m capstone --org demo-corp org validate
python -m capstone --org demo-corp org ingest          # -> orgs/demo-corp/.index/{triage,ir}

# Check everything is wired up (no LLM calls)
python -m unittest discover -s tests
```

Re-run `org ingest` whenever you edit a pack's playbooks or knowledge files. Every command takes `--org <id>`; set `SOC_ORG=<id>` to change the default (`demo-corp`). To onboard a new organization, see [INTEGRATION.md](INTEGRATION.md).

---

## 3. Web console

```bash
python -m capstone.web --org demo-corp              # http://127.0.0.1:8765
python -m capstone.web --org harbor-valley-health   # a different organization, same engine
python -m capstone.web --port 9000                  # another port
```

At startup the terminal prints the console URL, the webhook URL and the sources, and the ingest API key (from the env var named in the pack, or a one-time generated key). The sidebar shows the active org pack (click it for the Organization page) and live health: Ollama, each model, the vector indexes, and the job queue depth. All three models must show green before you submit alerts.

### Pages

| Page | Use it to |
|---|---|
| **Overview** | See counts (processed, auto-closed, sent to a human, escalated, incidents, pending approvals, guardrail hits, deduplicated), the disposition and severity charts, and the job list. **Run demo set** queues all 9 demo alerts; **Reset state** clears everything. |
| **Triage an alert** | Pick a demo alert or paste your own, submit it, and watch the live trace. The step bar lights up as the alert moves through normalize → SOC triage → guardrails → disposition → escalation/dedup → IR agent → auto actions → approval gate. |
| **Alert queue** | Every processed alert with verdict, guardrails, disposition and incident link. Click a row for the full record: the reason for the disposition, the guardrail findings, the model's answer, the evidence, the retrieved documents and the raw alert. |
| **Incidents** | Incidents opened by the IR agent. Click a row to see the severity arithmetic, the extracted facts (and any impact raised by code), the SLA, the action plan with live status, the Escalation Package and the timeline. |
| **Approvals** | The human gate. Enter your name, then **Approve** or **Deny** each pending action. Switch the filter to *All* to see past decisions and who made them. The sidebar badge counts pending items. |
| **Audit log** | The append-only decision log: time, actor, event, subject and rationale. |
| **Evaluation** | Disposition metrics per policy and per-alert results, read from the cached eval answers. |
| **Organization** | The active org pack: thresholds and severity cut-offs, alert sources with their webhook URLs and an example `curl`, the escalation policy (with each rule's auto/gated mode), asset rules, identity settings, actuators, knowledge files, and the validation results. |
| **How it works** | The architecture and design principles on one page. |

### Submitting your own alert

Choose the **source** next to the label field. For a mapped source (for example `falcon` or `generic-json`), paste the vendor's JSON payload; it is mapped with the pack's `sources/<name>.json` and rejected immediately if a required field is missing. For `edr-text`, paste any alert in either supported layout. A leading line such as `Triage this alert:` is optional; everything from `EDR ALERT` onward is used.

```
EDR ALERT
Detection: <rule name>
Vendor severity: High
Timestamp: 2026-05-14T02:41:09Z
Host: WS-SLS-091 (Device group: Sales Workstations, OS: Windows 11 23H2)
User: CORP\tmurphy
Process: C:\path\to\image.exe
Command line: ...
Process tree: child <- parent <- grandparent
Signature: Signed: ... | Unsigned
Prevalence: Image seen on 1 host in last 30 days
SHA256: ...
Network: ...
Additional context: ...
```

or the JSON layout (`EDR ALERT (JSON)` followed by an object with `detection_name`, `severity`, `timestamp`, `device{hostname, device_group, os}`, `user`, `process{image, command_line, ancestry, signature, prevalence, sha256}`, `network`, `context`). See `data/capstone_demo/01_benign_sccm.txt` for an example.

Alerts are processed one at a time in submission order. You can keep using the console while they run.

---

## 4. Command line

The CLI runs the same pipeline and uses the same state as the console, so you can mix them.

```bash
# Org packs
python -m capstone org list                             # available packs
python -m capstone org init acme                        # scaffold orgs/acme/ from the template
python -m capstone --org acme org validate              # errors / warnings / ok, exit code 1 on errors
python -m capstone --org acme org ingest                # build orgs/acme/.index/{triage,ir}
python -m capstone --org acme org show                  # the loaded profile as JSON

# Alerts
python -m capstone run data/capstone_demo/*.txt          # triage files end to end (source edr-text)
python -m capstone run data/capstone_demo/05_*.txt --reset   # clear state first
python -m capstone run alert.txt --interactive          # approve gated actions at a y/N prompt
python -m capstone run alert.txt --close-threshold 0.7  # try a different auto-close threshold
python -m capstone --org harbor-valley-health run "orgs/harbor-valley-health/samples/falcon_*.json" --source falcon

# Approvals and state
python -m capstone approvals                            # list pending gated actions
python -m capstone approve act-2026-0007 --by "Sameer" --note "on-call confirmed"
python -m capstone deny    act-2026-0008 --by "Sameer" --note "not needed at SEV2"
python -m capstone status                               # dispositions, incidents, pending count
python -m capstone reset                                # clear runs/<org>/
```
`--org` goes **before** the command. JSON files for mapped sources may contain one alert or a list.

Example output for one alert:

```
ALERT 05_offboarded_psexec.txt  [alt-…]  Remote service creation (PsExec-style) on WS-SLS-118 (user CORP\adm-hschmidt)
  SOC agent  verdict=Needs Investigation confidence=Medium techniques=T1569.002,T1036.005
  GUARDRAIL  disabled_account -> force_escalate: account adm-hschmidt is disabled per admin roster: …
  DISPOSITION ESCALATE  (Guardrail forced escalation (model said Needs Investigation): …)
  ESCALATION esc-2026-0003 key=WS-SLS-118:remote-service-creation-psexec-style:2026-08-17
  IR agent   inc-2026-0003 opened: SEV2 (score 2; …; disabled-account override: minimum SEV2)
  AUTO       would open case inc-2026-0003 (SEV2)
  AUTO       would create channel #inc-2026-0003
  GATED      act-2026-0009 page_oncall -> Alice Morgan (ir-primary)  (pending human approval: …)
```

The original single-alert RAG demo still works unchanged. Build its index once with `python rag.py ingest`, then run `python rag.py ask data/rag/q1_psexec_offboarded.txt`.

---

## 5. REST API

Interactive reference (Swagger UI): **http://127.0.0.1:8765/docs**

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Ollama, model and index status; queue depth |
| GET | `/api/config` | Active org, models, close threshold, confidence mapping |
| GET | `/api/org` | Active org pack: profile, sources, policy, knowledge files, validation results |
| GET | `/api/stats` | Counters for the overview |
| GET | `/api/demo-alerts` | Sample alerts for the active org (with their source) |
| POST | `/api/alerts` | Submit `{"text": "...", "label": "...", "source": "edr-text"}` → `202 {"job_id"}` |
| POST | `/api/ingest/{source}` | **Webhook for alerting systems.** Header `X-API-Key`; body = one vendor alert or a list (max 50). Duplicates by vendor ID are skipped. See [INTEGRATION.md §2.3](INTEGRATION.md#23-sending-alerts-the-webhook) |
| GET | `/api/jobs`, `/api/jobs/{id}` | Job status and live trace lines |
| GET | `/api/alerts`, `/api/alerts/{alert_id}` | Processed alerts / full record |
| GET | `/api/incidents`, `/api/incidents/{id}` | Incidents / detail with actions, package, timeline |
| GET | `/api/approvals?status=pending\|all` | Gated actions |
| POST | `/api/approvals/{action_id}/approve` | `{"by": "name", "note": ""}` → executes the action |
| POST | `/api/approvals/{action_id}/deny` | `{"by": "name", "note": ""}` |
| GET | `/api/audit?limit=200` | Audit log, newest first |
| GET | `/api/eval` | Disposition eval over cached answers |
| POST | `/api/reset` | Clear state (refused while alerts are running) |

Error codes: `400` invalid alert text, unknown source or unmappable payload, `401` missing or wrong ingest key, `404` unknown id, `409` action already resolved or reset while busy, `422` missing approver name.

```bash
curl -X POST http://127.0.0.1:8765/api/alerts -H "Content-Type: application/json" \
     -d "{\"text\": \"EDR ALERT\nDetection: ...\", \"label\": \"my alert\"}"
curl http://127.0.0.1:8765/api/jobs/<job_id>
curl -X POST http://127.0.0.1:8765/api/approvals/act-2026-0007/approve \
     -H "Content-Type: application/json" -d "{\"by\": \"Sameer\"}"
```

---

## 6. Evaluation

```bash
python -m capstone.eval_disposition --data data/test.jsonl            # runs the model; resumable
python -m capstone.eval_disposition --data data/test.jsonl --rescore  # re-score cached answers only
python -m capstone.eval_disposition --data data/test.jsonl --limit 20 # quick partial run
```

The model is called once per alert and its answer is cached in `results/disposition_test.jsonl`. If the run is interrupted, re-running continues where it stopped. `--rescore` recomputes every policy and threshold from the cache in about a second. The per-alert table for the default policy is written to `results/disposition_test_scored.csv`.

The original triage-model evaluation is unchanged: `python evaluate.py --model soc-triage --data data/test.jsonl`.

---

## 7. Configuration

Everything organization-specific is in the **org pack** (`orgs/<id>/org.json` and its folders). It is fully documented in [INTEGRATION.md](INTEGRATION.md):

| To change… | Edit in the pack | Then |
|---|---|---|
| Auto-close threshold, confidence mapping | `org.json` → `disposition` | `org validate`; restart |
| Severity cut-offs and response targets | `org.json` → `severity` | `org validate`; restart |
| Who gets paged / added, and when | `org.json` → `escalation_policy` | `org validate`; restart |
| Asset criticality, Tier-0 hosts | `org.json` → `assets` | `org validate`; restart |
| Privileged accounts, disabled accounts | the roster file named in `identity.roster_file` | restart (read at startup) |
| Alert sources / field mappings | `sources/<name>.json` | `org validate`; restart |
| Slack / PagerDuty / webhook endpoints | `org.json` → `actuators` + environment variables | restart |
| Playbooks, knowledge, IR policy text | files matched by `knowledge` globs | `org ingest` |

Engine-level settings in `capstone/config.py`: `TRIAGE_MODEL` (`soc-triage`), `IR_MODEL` (`llama3.1:8b`), `DEFAULT_ORG` (from `$SOC_ORG`, else `demo-corp`). Injection patterns are in `guardrails.INJECTION_PATTERNS`.

---

## 8. Files the system writes

All under `runs/<org-id>/`, one folder per org pack (delete it, run `python -m capstone --org <id> reset`, or use **Reset state**). Vector indexes are under `orgs/<org-id>/.index/`.

| File | Contents |
|---|---|
| `audit.jsonl` | Every decision and action, with actor and rationale (append-only) |
| `alerts.json` | Every processed alert: canonical fields, model answer, disposition, guardrails |
| `escalations.json` | Escalation Packages keyed by idempotency key |
| `incidents.json` | Incidents: facts, severity breakdown, SLA, planned actions |
| `approvals.json` | Gated actions and their resolution (who, when, note) |
| `actions.jsonl` | What each actuator did ("did …"), would have done ("would …", mocks) or failed to do ("FAILED …") |
| `ingested.json` | Vendor alert IDs received through the webhook (retry de-duplication) |
| `counters.json` | ID counters for `esc-`, `inc-`, `act-` |

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| Sidebar shows a red model | `ollama list`; pull or `ollama create` the missing model |
| Sidebar shows red indexes | `python -m capstone --org <id> org ingest` |
| `Index missing at …` error in a job | Same as above |
| `Cannot load org pack` | Check the id with `org list`; `org.json` must be valid JSON |
| Webhook returns 401 | Send the `X-API-Key` header with the key printed at startup or set in the pack's `ingest.api_key_env` variable |
| Webhook returns 400 "missing required fields" | The mapping in `sources/<name>.json` does not reach `detection`, `host` or `timestamp` in this payload; fix the paths, then `org validate` |
| Actions show `would …` although Slack/PagerDuty is configured | The env var named in `actuators` is not set in the shell that started the console; `org validate` warns about it |
| Port already in use | `python -m capstone.web --port 9000` |
| `OSError: [WinError 87]` importing numpy | Run commands from the repository root; `.rag_libs` must be on the path as an absolute path (the code does this for you) |
| Jobs stay *queued* | Only one alert runs at a time; a long IR assessment can take 2 minutes on CPU |
| A job ends in `error` with a timeout | Ollama is busy (for example an eval is running); retry when it finishes |
| Approve button says "Enter your name" | Type a name in the field at the top of the Approvals page; every approval is attributed |
| `Reset` refused (409) | Wait for running alerts to finish |
