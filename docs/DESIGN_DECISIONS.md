# Design Decisions

Each section gives the decision, the alternatives considered, and the reason. The last section records what testing changed. Several decisions were reversed after running real alerts through the system.

## 1. The model proposes, code decides

**Decision:** The triage model outputs a verdict and confidence; a small, readable function (`decide()`) turns those plus guardrail findings into the disposition. The IR model outputs facts; a rubric in code turns them into a severity.

**Alternatives:** Let the model output the disposition or severity directly; or use an LLM "judge" on top.

**Why:** Dispositions and severities must be explainable, testable and consistent. The same facts must always give the same SEV, and an auditor must be able to see which rule produced it. Code can be unit-tested (`tests/test_capstone.py`); a prompt cannot. The models do what they are good at (reading messy text); code does what it is good at (applying policy the same way every time).

## 2. Disposition as a confidence gate

**Decision:** Auto-close only benign verdicts with High confidence (score ≥ 0.85). True Positives always escalate. Everything ambiguous goes to a human.

**Alternatives:** Auto-close all benign verdicts; or never auto-close.

**Why:** The two errors have very different costs. Auto-closing a real attack is the worst outcome a SOC agent can produce. Sending a benign alert to a human costs a few minutes. The threshold is a single setting and the evaluator sweeps it ([EVALUATION.md](EVALUATION.md)), so the trade-off between analyst time and risk is measured, not guessed.

**What the measurement showed:** the fine-tuned model's confidence is not calibrated. It always says *High* with a committed verdict and *Medium* with *Needs Investigation*, so thresholds from 0.5 to 0.9 behave identically. In practice the safety comes from the *Needs Investigation* fallback and the guardrails, which kept true positives auto-closed at 0/37. The gate is kept because it is the correct control once confidence is calibrated (see EVALUATION.md, finding 2).

## 3. Guardrails that only add caution

**Decision:** Four deterministic guardrails (disabled account, unlisted admin, Tier-0, prompt injection). Each can only force escalation or block auto-close.

**Why:** Policy facts such as "this account was offboarded" live in documents the model may or may not retrieve and may or may not weigh correctly. During development the 3B model saw the offboarded admin `adm-hschmidt` run PsExec, cited the SCCM allowlist entry, and concluded *Needs Investigation… normal SCCM activity*. The roster says *any logon is a security incident*. A rule that reads the roster directly cannot be talked out of it. Making guardrails one-directional means a wrong guardrail costs analyst time, never a missed incident.

## 4. Two agents, two models

**Decision:** The SOC agent uses the fine-tuned 3B model; the IR agent uses `llama3.1:8b` in JSON mode.

**Why:** Triage is a high-volume, fixed-format task the 3B model was trained for. IR runs only on escalations, needs to read a whole package against playbooks, and must return strict JSON. A larger general model with JSON mode fits that better, and its lower throughput does not matter on the smaller IR volume.

## 5. Orchestrated Python, not a low-code flow tool

**Decision:** Plain Python modules wired by an orchestrator, rather than Langflow.

**Alternatives:** Langflow (used in Assignment 2), LangGraph, CrewAI.

**Why:** The pipeline is linear with explicit branches. Every branch is a policy decision that needs a test. Plain Python keeps it readable in one sitting, runs on the existing Python 3.8 environment, and reuses `rag.py` directly. An agent framework would add dependencies without adding capability this design uses.

## 6. Dedup key

**Decision:** `host : detection rule : UTC day`, built from EDR fields only.

**Alternative tried first:** `host : parent ATT&CK technique : day`, which is what the original design sketch proposed.

**Why it changed:** In the first demo run the technique-based key used the model's ATT&CK output. The model listed `T1036` (masquerading) first for three unrelated incidents, and for the ransomware alert it added a technique (`T1482`, domain trust discovery) that nothing in the alert supported. A key that depends on model output can split one incident or merge unrelated ones. The detection rule name comes from the EDR and is stable.

**Trade-off:** A calendar day is a simple window; activity spanning midnight UTC opens two escalations. A sliding window per (host, rule) is the next step.

## 7. Human-in-the-loop mechanism

**Decision:** A persistent approval queue, worked from the web console (Approve / Deny with a required name) or the CLI (`approve` / `deny`), plus `--interactive` for live terminal demos.

**Alternatives:** CLI prompt only (blocks the pipeline); a logged "pending" state with no way to act on it.

**Why:** A queue does not block triage of the next alert, survives restarts, and gives a natural audit record: who approved what and when. Approval is the only path that executes a gated action, in every interface.

## 8. What is automatic and what is gated

| Automatic | Gated |
|---|---|
| Open case, create war-room channel, post summary | Page on-call, add CISO / Legal / insurer / external IR / Identity lead |

**Rule:** If an action is internal to the security team and reversible, it runs automatically. If it wakes a person or leaves the security team, it needs approval. This mirrors the Excessive Agency lesson from Assignment 3 (SecureBot), where model output was wired straight to refunds.

## 9. Severity rubric in a document *and* in code

**Decision:** `ir_docs/severity_rubric.md` states the policy in plain language and is indexed for retrieval; `severity.py` implements the same table; tests pin the levels.

**Why:** The original playbooks had response steps and SLAs but no severity scale, so "severity = rubric, not vibes" needed a rubric. Keeping it as a document lets analysts and the IR model read it; keeping it in code makes it enforceable.

## 10. Local-first, mocked actuators

**Decision:** Everything runs locally (Ollama, FAISS, JSON state); Slack, pager and case systems are mocks behind an `execute(action)` interface that records intent.

**Why:** The demo needs no credentials and no data leaves the machine. Swapping in a real client is a one-class change (see [ARCHITECTURE.md](ARCHITECTURE.md#6-extending)).

## 11. Plain web stack

**Decision:** FastAPI back end; a single HTML/CSS/JS page with no build step.

**Why:** It runs on the same Python 3.8 environment as the pipeline, gives a Swagger API reference for free, and needs no Node toolchain to demo. The worker-thread queue matches Ollama's one-generation-at-a-time reality on a laptop.

## 12. Org packs: engine vs. configuration

**Decision:** Everything organization-specific lives in a folder of plain files (`orgs/<id>/`): JSON for policy, Markdown and CSV for knowledge, one mapping file per alert source. The engine reads it through one module (`org.py`). Two deliberately different example orgs ship with the repo.

**Alternatives:** Python plugins per organization; a database-backed admin UI; environment variables.

**Why:** The people who own escalation policy and playbooks are security leads, not developers. Plain files can be reviewed in a pull request, diffed, and validated in CI (`org validate` exits non-zero on errors). A second org that shares nothing with the first (different vendor JSON, roster format, naming, asset tiers, cut-offs and stakeholders) is the test that the boundary is in the right place. Building it found two hidden assumptions: the playbook-ID pattern assumed one segment (`PB-CRED-01`, not `PB-HVH-CRED-01`), and the roster parser assumed Demo Corp's exact Markdown table.

**What stays fixed:** Anything that makes the system safe is engine code, not configuration. That covers the human gate on people-reaching actions, the severity overrides, the impact floors, the guardrails being monotonic, injection scanning and output escaping. An org can make the system more cautious; it cannot make it less safe.

## 13. Vendor alerts are re-rendered for the model

**Decision:** A mapped vendor alert is converted to canonical fields, then rendered back into the exact key/value layout the triage model was fine-tuned on.

**Alternative:** Pass the vendor JSON to the model as-is.

**Why:** A small fine-tuned model is sensitive to input format; it learned one layout. Re-rendering means a new alert source costs a mapping file, not a re-training run. The limitation remains that unfamiliar *content* (naming conventions, tools) can still reduce accuracy, which is why a new org should measure before enabling auto-close (Harbor Valley ships with a threshold no confidence level reaches).

## 14. What testing changed

| Observation from real runs | Change |
|---|---|
| 3B model called an offboarded admin's activity "normal SCCM activity" | `disabled_account` guardrail forces escalation |
| Exfiltration alert came from `adm-gtanaka`, who is not in the roster; roster policy says unlisted = no approved scope | `unlisted_admin` guardrail |
| Injection text in an alert made the model answer *False Positive, High* | Injection guardrail blocks auto-close; demo alert 09 keeps it under test |
| Dedup key built from model techniques was unstable | Key from EDR fields only |
| IR model rated kerberoasting with hashes written to disk as "attempted" → SEV4 | Impact floor: credential theft → at least *exposed* |
| IR model rated a 204 GB upload and a C2 beacon as "attempted" | Impact floors: confirmed True Positive → at least *executed*; exfiltration → at least *exposed* |
| IR model flagged a payload download as exfiltration, pulling in Legal | Prompt defines exfiltration as data leaving the network |
| SLA was blank: retrieval rarely returned the SLA chunk | SLA read from the playbook the IR agent named; rubric fallback |
| Same alert got different IDs from the browser (CRLF) and the CLI (LF) | Line endings normalized before hashing |
| IR model sometimes returned a playbook ID with the title attached | ID extracted with a pattern (`PB-XXX-NN`) |
| Second org: playbook IDs with two segments (`PB-HVH-CRED-01`) were rejected; roster parser assumed one Markdown table layout | ID pattern widened; roster reads CSV or any Markdown table by configured column names |
| Second org: a hospital's critical EHR and PACS servers were reported as "Tier-0 involved" (the code equated *critical* with *Tier-0*; Demo Corp's only critical assets are domain controllers, which hid it) | Tier-0 now comes only from asset rules marked `tier0` and Tier-0 accounts; regression test added |
