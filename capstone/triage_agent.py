"""SOC Triage Agent: alert -> verdict (fine-tuned model + RAG) -> DISPOSITION.

Dispositions:
  CLOSE      high-confidence benign (Benign True Positive / False Positive >= CLOSE_THRESHOLD)
  ASK_HUMAN  anything ambiguous: Needs Investigation, low-confidence benign, unparseable output,
             or a guardrail that forbids auto-close
  ESCALATE   True Positive, or a guardrail that forces escalation -> Escalation Package for IR

The model proposes a verdict; the disposition itself is decided here, in code, from the parsed
verdict, the confidence gate and the guardrails.
"""
import re

from . import config, guardrails, state
from . import org as orgmod
from .retrieval import Retriever, rag
from .severity import asset_criticality

VERDICTS = ["Benign True Positive", "Needs Investigation", "False Positive", "True Positive"]
BENIGN = ("Benign True Positive", "False Positive")


def parse_triage(answer):
    """Parse the fine-tuned model's fixed output format into fields."""
    def field(name):
        m = re.search(r"^{}:\s*(.+)$".format(re.escape(name)), answer, re.M)
        return m.group(1).strip().strip("*") if m else ""

    def bullets(header, nxt):
        m = re.search(r"{}:\s*\n(.*?)(?:\n{}:|\Z)".format(re.escape(header), re.escape(nxt)), answer, re.S)
        if not m:
            return []
        return [re.sub(r"^\s*(?:-|\d+\.)\s*", "", l).strip() for l in m.group(1).splitlines() if l.strip()]

    verdict_raw = field("Verdict")
    verdict = next((v for v in sorted(VERDICTS, key=len, reverse=True) if v.lower() in verdict_raw.lower()),
                   "Unparsed")
    conf = field("Confidence").split()[0].capitalize() if field("Confidence") else ""
    sources = [s.strip() for s in field("Sources").split(",") if s.strip()]
    return {
        "verdict": verdict,
        "confidence_label": conf if conf in ("High", "Medium", "Low") else "Unknown",
        "model_severity": field("Severity"),
        "attack_techniques": list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", field("MITRE ATT&CK")))),
        "summary": field("Summary"),
        "evidence": bullets("Key evidence", "Recommended actions"),
        "recommended_actions": bullets("Recommended actions", "Sources"),
        "sources": sources,
    }


def decide(parsed, findings, close_threshold=None):
    """Confidence gate + guardrails -> (disposition, confidence, rationale)."""
    disp = orgmod.current().disposition
    threshold = disp["close_threshold"] if close_threshold is None else close_threshold
    verdict = parsed["verdict"]
    confidence = disp["confidence_score"].get(parsed["confidence_label"], 0.0)
    effects = {f["effect"] for f in findings}

    if "force_escalate" in effects:
        why = "; ".join(f["reason"] for f in findings if f["effect"] == "force_escalate")
        return "ESCALATE", confidence, "Guardrail forced escalation (model said {}): {}".format(verdict, why)
    if verdict == "True Positive":
        return "ESCALATE", confidence, "Model verdict True Positive ({} confidence)".format(parsed["confidence_label"])
    if verdict == "Needs Investigation":
        return "ASK_HUMAN", confidence, "Model could not decide from telemetry: Needs Investigation"
    if verdict == "Unparsed":
        return "ASK_HUMAN", 0.0, "Model output did not follow the verdict format"
    # benign verdicts from here
    if "no_auto_close" in effects:
        why = "; ".join(f["reason"] for f in findings if f["effect"] == "no_auto_close")
        return "ASK_HUMAN", confidence, "Model said {}, but auto-close is blocked: {}".format(verdict, why)
    if confidence >= threshold:
        return "CLOSE", confidence, "Model verdict {} at {} confidence (>= {:.2f} close threshold)".format(
            verdict, parsed["confidence_label"], threshold)
    return "ASK_HUMAN", confidence, "Model verdict {} but confidence {} is below the {:.2f} close threshold".format(
        verdict, parsed["confidence_label"], threshold)


def idempotency_key(alert):
    """host : detection rule : UTC day. Re-fires of the same activity collapse into one escalation.

    Built only from EDR-supplied fields, never from model output: an earlier version keyed on the
    model's ATT&CK technique, and the model's technique choice varies (and can be hallucinated),
    which would split one incident into several or merge unrelated ones.
    """
    rule = re.sub(r"[^a-z0-9]+", "-", alert.get("detection", "").lower()).strip("-") or "unknown-rule"
    day = (alert.get("timestamp") or state.now())[:10]
    return "{}:{}:{}".format(alert.get("host") or "unknown-host", rule, day)


class SOCTriageAgent:
    name = "soc-triage-agent"

    def __init__(self, retriever=None, model=None):
        orgmod.current()   # make sure an org is active so the index path points at its pack
        self.retriever = retriever or Retriever(config.TRIAGE_INDEX)
        self.model = model or config.TRIAGE_MODEL

    def run_model(self, alert):
        """Same prompt layout the model was fine-tuned on: retrieved context, then the alert."""
        hits = self.retriever.search(rag.search_query(alert["raw"]))
        blocks = ["[{}]\n{}".format(src, chunk) for src, chunk, _ in hits]
        decoded = rag.decode_powershell(alert["raw"])
        for d in decoded:
            blocks.append("[pipeline_decoder]\nThe -EncodedCommand payload in this alert decodes to: " + d)
        prompt = "Retrieved context:\n\n" + "\n\n".join(blocks) + "\n\nTriage this alert:\n\n" + alert["raw"]
        reply = rag.ollama.chat(model=self.model,
                                messages=[{"role": "system", "content": rag.SYSTEM_PROMPT},
                                          {"role": "user", "content": prompt}],
                                options={"temperature": 0, "num_ctx": 4096})
        return reply["message"]["content"].strip(), sorted({s for s, _, _ in hits}), decoded

    def process(self, alert, close_threshold=None):
        answer, retrieved, decoded = self.run_model(alert)
        parsed = parse_triage(answer)
        findings = guardrails.check(alert)
        disposition, confidence, rationale = decide(parsed, findings, close_threshold)
        result = {"alert_id": alert["alert_id"], "host": alert.get("host"), "detection": alert.get("detection"),
                  "disposition": disposition, "confidence": confidence, "rationale": rationale,
                  "triage": parsed, "guardrails": findings, "retrieved": retrieved, "raw_answer": answer}
        state.audit(self.name, "disposition", alert["alert_id"], rationale, disposition=disposition,
                    verdict=parsed["verdict"], confidence=confidence, guardrails=[f["rule"] for f in findings])

        if disposition == "ESCALATE":
            result["package"], result["merged"] = self.escalate(alert, parsed, findings, confidence, rationale,
                                                                retrieved, decoded)
        return result

    def escalate(self, alert, parsed, findings, confidence, rationale, retrieved, decoded):
        """Build the SOC->IR contract, or merge into an open escalation with the same key."""
        key = idempotency_key(alert)
        canonical = {k: v for k, v in alert.items() if k != "raw"}
        existing = state.find_open_escalation(key)
        if existing:
            if alert["alert_id"] not in [a["alert_id"] for a in existing["alerts"]]:
                existing["alerts"].append(canonical)
                state.save_escalation(existing)
            state.audit(self.name, "dedup_merge", alert["alert_id"],
                        "Same host/technique/day as {}".format(existing["escalation_id"]), idempotency_key=key)
            return existing, True

        package = {
            "escalation_id": state.next_id("esc"),
            "idempotency_key": key,
            "created_by": self.name,
            "created_at": state.now(),
            "alerts": [canonical],
            "triage_verdict": parsed["verdict"],
            "attack_techniques": parsed["attack_techniques"],
            "evidence": parsed["evidence"],
            "summary": parsed["summary"],
            "enrichment": {"decoded_payloads": decoded, "asset_criticality": asset_criticality(alert)[0],
                           "guardrails": findings},
            "confidence": confidence,
            "rationale": rationale,
            "sources": sorted(set(parsed["sources"]) | set(retrieved)),
        }
        state.save_escalation(package)
        state.audit(self.name, "escalation_created", package["escalation_id"], rationale, idempotency_key=key)
        return package, False
