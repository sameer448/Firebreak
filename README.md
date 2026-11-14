# Firebreak

*A firebreak is the cleared strip that stops a fire spreading: here, the line between what the model can do on its own and what needs a person.*

**Agentic security-operations triage and incident response that runs on a laptop, with a human approval gate in front of every action that reaches a person.**

A fine-tuned small language model triages EDR alerts using retrieval over your playbooks. Deterministic guardrails and a confidence gate decide whether each alert is **closed**, **sent to an analyst**, or **escalated**. Escalations become a structured package for an incident-response agent, which extracts the facts. A severity rubric in code assigns SEV1–4, and an escalation policy plans the response. Internal, reversible steps (case, war-room channel, summary) happen automatically. Paging someone or contacting anyone outside the security team **waits for a human to approve it**.

Everything specific to an organization lives in an **org pack**: alert-source mappings, playbooks, privileged-account roster, asset rules, severity cut-offs, escalation policy, and Slack/PagerDuty endpoints. Alerting systems send their native JSON to an authenticated webhook. Two very different example organizations ship with the repo and run on the same engine.

```
 SIEM / EDR ──webhook──► source mapping ──► SOC Triage Agent ──► CLOSE | ASK_HUMAN | ESCALATE
                                         (fine-tuned 3B + RAG)                       │
                                         + confidence gate + guardrails              ▼
                                                                         Escalation Package
                                                                                     │
                                              IR Agent (8B + RAG) ─► facts ─► severity rubric ─► SEV1-4
                                                                                     │
                                          escalation policy ─► auto: case · war-room · summary
                                                            └► gated: page on-call · CISO · Legal · regulator
                                                                          └─► human approves / denies
```

> **Status:** a research and teaching project (a cybersecurity AI capstone). It is a complete, tested, local system, not a hardened production service. Read [docs/SECURITY.md](docs/SECURITY.md#4-known-limitations) before pointing it at real alerts.

## Highlights

- **The model proposes, code decides.** Dispositions, severities and action plans are computed in code, are unit-tested, and explain themselves.
- **Guardrails that can't be talked out of it.** A disabled account in the roster forces escalation even when the model says "normal activity". Instruction-like text inside an alert (prompt injection) blocks auto-close.
- **A human gate that can't be configured away.** An org's policy can add approvals but can never auto-page a person.
- **Bring your own organization.** Map any vendor JSON with a mapping file, drop in playbooks, write escalation rules, and validate it all with one command.
- **Web console:** live pipeline trace, alert queue, incident severity breakdown, approvals inbox, audit log, evaluation, org-pack view.
- **Measured.** On 91 labeled alerts, **0/37 true positives were auto-closed** (every real attack reached a person), **69% of benign alerts were auto-closed**, and triage verdict accuracy was 80% ([docs/EVALUATION.md](docs/EVALUATION.md)).

## Quick start

**Requirements:** Python 3.8+ · [Ollama](https://ollama.com) · about 8 GB of disk for models · 16 GB RAM recommended. No GPU or cloud account is needed.

```bash
git clone https://github.com/sameer448/Firebreak.git && cd Firebreak

./scripts/setup.sh                                  # macOS / Linux
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1   # Windows

.venv/bin/python -m capstone.web --org demo-corp    # Windows: .venv\Scripts\python -m capstone.web --org demo-corp
```

Open **http://127.0.0.1:8765** and click **Run demo set**, or open **Triage an alert** and pick one. On a laptop CPU, each alert takes 1–3 minutes.

The setup script creates `.venv`, installs `requirements.txt`, pulls the three models, builds the vector indexes for both example orgs, runs the test suite, and finishes with `python -m capstone doctor`, which checks everything and prints the fix for anything missing.

<details>
<summary>Manual setup</summary>

```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

ollama pull nomic-embed-text
ollama pull llama3.1:8b
ollama pull hf.co/Sgoyal16/soc-triage-llama3.2-3b-GGUF:Q4_K_M
ollama create soc-triage -f Modelfile

python -m capstone --org demo-corp org ingest
python -m capstone --org harbor-valley-health org ingest
python -m unittest discover -s tests
python -m capstone doctor
python -m capstone.web --org demo-corp
```
</details>

### Try the second organization
```bash
python -m capstone.web --org harbor-valley-health
```
This is a fictional hospital network with Sentinel-style and Falcon-style alerts, HIPAA and clinical escalation rules, and a stricter auto-close setting. The engine is the same.

### Send an alert from a SIEM
```bash
curl -X POST http://127.0.0.1:8765/api/ingest/falcon \
  -H "Content-Type: application/json" -H "X-API-Key: <key printed at startup>" \
  -d @orgs/harbor-valley-health/samples/falcon_disabled_account_lsass.json
```

## Documentation

| Read this | To learn |
|---|---|
| [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) | **Start here.** One real alert followed through every component, with the actual data at each step |
| [docs/WORKFLOWS.md](docs/WORKFLOWS.md) | Every path an alert can take, with diagrams: disposition, dedup, IR and severity, approvals, ingestion, onboarding |
| [docs/USAGE.md](docs/USAGE.md) | Install, every console page, CLI reference, REST API, configuration, troubleshooting |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | Bring your own organization: source mappings and the webhook, playbooks, roster, assets, severity, escalation policy, Slack/PagerDuty |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, engine vs. org pack, data contracts, runtime, extension points |
| [docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md) | Why it is built this way, and what testing changed |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, OWASP LLM Top 10 mapping, controls, known limitations |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Method, results, and honest findings |
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | A 12-minute presentation walkthrough |

## Repository layout

```
capstone/                    the engine
  triage_agent.py            SOC agent: model + RAG, disposition gate, dedup, Escalation Package
  ir_agent.py                IR agent: fact extraction, impact floors, incident, SLA
  guardrails.py              roster, Tier-0 and prompt-injection rules
  severity.py                severity math (org cut-offs + fixed safety overrides)
  policy.py                  escalation policy engine + human-gate invariant
  orchestrator.py            pipeline, action dispatch, approve / deny
  org.py  validate.py        org-pack loading and validation
  connectors/                alert_source.py (mapping, rendering) · actuators.py (mock, Slack, PagerDuty, webhook)
  web/                       FastAPI server + console (HTML/CSS/JS, no build step)
  eval_disposition.py        disposition evaluation
  doctor.py                  environment check
  templates/org/             starting point for `org init`
orgs/
  demo-corp/                 example org 1: the environment the model was trained on
  harbor-valley-health/      example org 2: a hospital with vendor JSON sources and HIPAA policy
data/capstone_demo/          9 scenario alerts for the demo
tests/                       58 unit and API tests (no model calls)
docs/                        documentation
scripts/                     setup.sh, setup.ps1

# The original fine-tuning project this builds on
soc_triage_finetune.ipynb    LoRA fine-tune of Llama 3.2 3B (Unsloth), exported to GGUF
generate_dataset.py          synthetic EDR alert dataset generator (+ audit_dataset.py, make_ood_test.py)
data/*.jsonl                 train / test / held-out / out-of-distribution splits
rag.py  rag_docs/            the original single-alert RAG pipeline and its knowledge base
evaluate.py                  model-level evaluation (verdict, ATT&CK, format, hallucination)
Modelfile                    Ollama definition of the `soc-triage` model
ir_docs/                     Demo Corp's IR policy documents (severity rubric, escalation contacts)
```

## How this project came about

It was built in three stages:
1. **Fine-tuning:** a synthetic dataset of EDR alerts with analyst-quality answers (`generate_dataset.py`), and a LoRA fine-tune of Llama 3.2 3B (`soc_triage_finetune.ipynb`), published as a GGUF on Hugging Face and served by Ollama as `soc-triage`.
2. **RAG:** retrieval over playbooks, an admin roster, an allowlist and a change calendar (`rag.py`), so the model can use organization context it was never trained on.
3. **Agents (this capstone):** the disposition layer, guardrails, the IR agent, the severity rubric, the policy engine, the human approval gate, org packs, the webhook, the console and the evaluation. The original design note is [capstone_architecture.md](capstone_architecture.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `python -m unittest discover -s tests` and `org validate` on both example orgs before opening a pull request.

## License

[MIT](LICENSE). The example organizations, people, hosts and alerts are fictional. Vendor names (Sentinel, Falcon, Slack, PagerDuty) describe payload formats and integrations only; this project is not affiliated with those vendors.
