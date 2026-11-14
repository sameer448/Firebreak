# Capstone — Agentic Cybersecurity Operations (CSOC → IR)

*Working architecture one-pager. Builds on the existing `soc-triage` fine-tuned model + RAG pipeline in this repo.*

---

## 1. One-sentence thesis

Specialist agents triage EDR alerts against CSOC playbooks and decide to **close / escalate / ask a human**; escalations become a structured package that an **IR agent** confirms as an incident and then orchestrates the response — severity, war-room, stakeholders, paging — with a human approving the highest-consequence actions.

---

## 2. What already exists in this repo (the core is built)

| Piece | File | Role in the capstone |
|---|---|---|
| Fine-tuned triage model `soc-triage` (Llama 3.2 3B) | `Modelfile`, `soc_triage_finetune.ipynb` | Produces the verdict, ATT&CK mapping, evidence, next actions |
| RAG pipeline (FAISS + `nomic-embed-text`) | `rag.py` | Retrieves the relevant playbook/policy chunk per alert |
| Pipeline enrichment (decode `-EncodedCommand`) | `rag.py` | Gives the small model facts it can't compute itself |
| IR playbooks w/ severity + SLA + steps | `make_rag_docs.py` → `rag_docs/` | The IR agent's RAG corpus; source of the severity rubric |
| Eval harness | `evaluate.py` | Measures triage quality; extend it to score dispositions |

**The capstone is not a rebuild — it's two new layers on top of this:** an agentic *disposition* layer around the triage model, and an *IR agent* that consumes escalations.

---

## 3. Target architecture

```
                 ┌─────────────────── Reasoning plane (agents) ───────────────────┐
  alert ──► [Connector/Normalize] ──► [SOC Triage Agent]
            (EDR/SIEM → canonical)      • runs soc-triage + RAG(CSOC playbooks)
                                        • enrich, correlate, DEDUP
                                        • emit DISPOSITION + confidence + rationale
                                                   │
                        ┌──────────────────────────┼───────────────────────────┐
                        ▼                           ▼                           ▼
                     CLOSE                    ASK HUMAN                     ESCALATE
                (high-conf benign)         (low confidence)          → Escalation Package
                        │                           │                           │
                        └────────── audit log (every decision) ─────────────────┤
                                                                                 ▼
                                                              [IR Agent]
                                                              • RAG(IR playbooks)
                                                              • incident? yes/no
                                                              • severity ← rubric, not vibes
                                                              • orchestrate downstream ▼
                 ┌───────────────── Action plane (actuators, gated) ─────────────────┐
                 │  auto:  create war-room channel   · post summary · open case       │
                 │  gated: PAGE on-call human  · pull external stakeholders           │  ← human approves
                 └────────────────────────────────────────────────────────────────────┘
```

Two planes on purpose: **reasoning** (LLM agents, non-destructive) is separated from **action** (anything that touches a real system), with an approval gate between them. That gate is the whole safety story.

---

## 4. The SOC→IR contract: the Escalation Package

The handoff is a **structured object, not a ping**. This is the most important schema in the project — it's what the IR agent reasons over and what a human reviews.

```json
{
  "escalation_id": "esc-2026-0042",
  "idempotency_key": "host123:T1003:2026-11-07",   // dedup — one incident, not five
  "created_by": "soc-triage-agent",
  "alerts": [ { /* canonical alert(s) */ } ],
  "triage_verdict": "True Positive",
  "attack_techniques": ["T1003.001"],
  "evidence": ["lsass access by non-system tool comsvcs.dll MiniDump"],
  "enrichment": { "decoded_payloads": [], "asset_criticality": "high" },
  "confidence": 0.86,
  "rationale": "why the agent escalated — human-readable",
  "sources": ["playbook_credential_access.md"]
}
```

---

## 5. Decision rules (where autonomy lives)

- **Disposition is a confidence gate, not a vibe.** Auto-close only *high-confidence benign*; anything ambiguous → human. Thresholds are a tunable design parameter you can defend in the writeup.
- **Severity = rubric + RAG, not an LLM guess.** Asset criticality × confirmed impact × scope, cross-referenced with the playbook's severity/SLA guidance (already in `rag_docs/`). The LLM extracts facts; the rubric assigns the number.
- **Autonomy boundary (tier-1, humans approve actions):**
  - **Auto (safe, reversible, internal):** create war-room channel, post the incident summary, open/track a case.
  - **Gated (human approves):** paging a human responder, looping in external stakeholders — the SOC equivalent of SecureBot's Excessive-Agency lesson (don't let the model wake someone at 3am unsupervised).
- **Everything is logged with rationale** — every close, escalate, and action carries a why, so a reviewer can audit the agents. This doubles as training data for later.

---

## 6. Scope: real reasoning, mocked actuators

To keep it demoable without live Slack/PagerDuty creds, and to make it read as *designed for production* rather than hardcoded to a demo:

- **Build for real:** connector/normalize, triage agent + RAG, disposition + confidence, escalation package, IR agent + RAG, incident decision, severity rubric.
- **Mock behind a connector interface (log the intent):** `would create channel #inc-0042`, `would page on-call = alice`, `would add stakeholder = Legal`. Same connector-layer pattern as the triage input side, so swapping in a real Slack/PagerDuty client later is a one-file change.

---

## 7. Open design questions to settle next

1. **Agent framework:** keep it as orchestrated Python around `rag.py`/Ollama, or lift into Langflow (reuses the orchestrator pattern from Assignment 2)?
2. **Correlation/dedup strategy:** what's the idempotency key, and over what time window do alerts collapse into one incident?
3. **Human-in-the-loop mechanism:** how does an analyst actually approve a gated action in the demo — CLI prompt, a simple web approval queue, or a logged "pending approval" state?
4. **Eval:** extend `evaluate.py` to score *dispositions* (did it escalate the right things?), not just triage verdicts.

---

## 8. Coursework → capstone lineage (for the writeup narrative)

- **Assignment 2 (Recon by Committee):** the multi-agent orchestrator pattern + custom normalization component → the agent layer and connector.
- **Assignment 3 (SecureBot):** OWASP LLM06 Excessive Agency → *why* the action plane is gated; prompt-injection discipline → treat ingested alert text as data, not instructions.
- **This repo:** fine-tuned triage + RAG + IR playbooks → the reasoning core the agents wrap.
