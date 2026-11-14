"""Score the SOC agent's DISPOSITIONS (close / ask human / escalate), not just verdicts.

  python -m capstone.eval_disposition --data data/test.jsonl              run the model (resumable)
  python -m capstone.eval_disposition --data data/test.jsonl --rescore    re-score cached answers only

Expected disposition from the label: True Positive -> ESCALATE, Needs Investigation -> ASK_HUMAN,
Benign True Positive / False Positive -> CLOSE.

Metrics (per policy):
  disp_acc        disposition matches the expected one
  tp_escalated    True Positives escalated (recall on real incidents)
  tp_auto_closed  True Positives auto-CLOSED: the unacceptable error, must be 0
  benign_closed   benign alerts auto-closed (the automation the agent buys)
  human_load      share of alerts routed to a human
Policies compared: model verdict alone vs. model + guardrails, across close thresholds.
The model is run once per alert; answers are cached in results/ so policies are re-scored offline.
"""
import argparse
import csv
import json
import os

from . import config, guardrails
from . import org as orgmod
from .connectors.alert_source import normalize
from .triage_agent import decide, parse_triage

EXPECTED = {"True Positive": "ESCALATE", "Needs Investigation": "ASK_HUMAN",
            "Benign True Positive": "CLOSE", "False Positive": "CLOSE"}
THRESHOLDS = [0.5, 0.7, 0.85, 1.01]   # 1.01 = never auto-close


def cache_path(data):
    os.makedirs(os.path.join(config.ROOT, "results"), exist_ok=True)
    return os.path.join(config.ROOT, "results", "disposition_{}.jsonl".format(
        os.path.splitext(os.path.basename(data))[0]))


def run_model(rows, path, limit):
    from .triage_agent import SOCTriageAgent
    done = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            done = {json.loads(l)["i"] for l in f}
    agent = SOCTriageAgent()
    with open(path, "a", encoding="utf-8") as f:
        for i, r in enumerate(rows[:limit] if limit else rows):
            if i in done:
                continue
            alert = normalize(r["conversations"][1]["content"])
            answer, retrieved, _ = agent.run_model(alert)
            f.write(json.dumps({"i": i, "scenario": r["meta"]["scenario"], "label": r["meta"]["verdict"],
                                "alert": {k: v for k, v in alert.items() if k != "raw"},
                                "retrieved": retrieved, "answer": answer}, ensure_ascii=False) + "\n")
            f.flush()
            print("{}/{} {:<24} {:<22} -> {}".format(i + 1, len(rows), r["meta"]["scenario"], r["meta"]["verdict"],
                                                     parse_triage(answer)["verdict"]), flush=True)


def score(records, use_guardrails, threshold):
    s = dict(n=0, ok=0, tp=0, tp_esc=0, tp_closed=0, benign=0, benign_closed=0, human=0)
    rows = []
    for rec in records:
        parsed = parse_triage(rec["answer"])
        findings = guardrails.check(rec["alert"]) if use_guardrails else []
        disp, _, why = decide(parsed, findings, close_threshold=threshold)
        exp = EXPECTED[rec["label"]]
        s["n"] += 1
        s["ok"] += disp == exp
        s["human"] += disp == "ASK_HUMAN"
        if rec["label"] == "True Positive":
            s["tp"] += 1
            s["tp_esc"] += disp == "ESCALATE"
            s["tp_closed"] += disp == "CLOSE"
        if exp == "CLOSE":
            s["benign"] += 1
            s["benign_closed"] += disp == "CLOSE"
        rows.append([rec["scenario"], rec["label"], parsed["verdict"], parsed["confidence_label"], exp, disp,
                     disp == exp, ";".join(f["rule"] for f in findings), why])
    return s, rows


def pct(a, b):
    return "{}/{} ({:.0%})".format(a, b, a / b if b else 0)


def report(path):
    with open(path, encoding="utf-8") as f:
        records = [json.loads(l) for l in f]
    verdict_ok = sum(parse_triage(r["answer"])["verdict"] == r["label"] for r in records)
    print("\nDATA: {}  alerts scored: {}  triage verdict accuracy: {}".format(
        os.path.basename(path), len(records), pct(verdict_ok, len(records))))
    hdr = ["policy", "close_thr", "disp_acc", "tp_escalated", "tp_auto_closed", "benign_closed", "human_load"]
    table = []
    for use_g in (False, True):
        for thr in THRESHOLDS:
            s, rows = score(records, use_g, thr)
            table.append(["model+guardrails" if use_g else "model only", "never" if thr > 1 else thr,
                          pct(s["ok"], s["n"]), pct(s["tp_esc"], s["tp"]), pct(s["tp_closed"], s["tp"]),
                          pct(s["benign_closed"], s["benign"]), pct(s["human"], s["n"])])
            if use_g and thr == orgmod.current().disposition["close_threshold"]:
                out = path.replace(".jsonl", "_scored.csv")
                with open(out, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["scenario", "label", "verdict", "confidence", "expected", "disposition", "correct",
                                "guardrails", "rationale"])
                    w.writerows(rows)
    widths = [max(len(str(x)) for x in col) for col in zip(hdr, *table)]
    for line in [hdr] + table:
        print("  ".join(str(x).ljust(w) for x, w in zip(line, widths)))
    print("Per-alert detail (default policy): " + path.replace(".jsonl", "_scored.csv"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join("data", "test.jsonl"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--rescore", action="store_true")
    args = ap.parse_args()
    path = cache_path(args.data)
    if not args.rescore:
        with open(args.data, encoding="utf-8") as f:
            rows = [json.loads(l) for l in f]
        run_model(rows, path, args.limit)
    report(path)


if __name__ == "__main__":
    main()
