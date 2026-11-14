"""
Score Ollama-served models on the triage test sets.

Usage:
  python evaluate.py --model llama3.2:3b --model soc-triage --data data/test.jsonl --limit 60
  python evaluate.py --model llama3.2:3b --model soc-triage --data data/ood_test.jsonl

Metrics per model:
  verdict_acc     verdict matches the label
  missed_tp       real incidents the model did NOT call True Positive / Needs Investigation
                  (the most dangerous error for a SOC)
  false_alarm     benign/FP alerts the model called True Positive (analyst fatigue)
  mitre_acc       expected technique ID (e.g. T1003.001, or parent T1003) appears in the answer
  format_ok       all required sections present
  hallucinated    answer cites an IP/host not present in the alert
Writes per-alert results to results/<data>_<model>.csv for screenshots.
Standard library only; Ollama must be running on localhost:11434.
"""
import argparse
import csv
import json
import os
import re
import time
import urllib.request

OLLAMA = "http://localhost:11434/api/chat"
SECTIONS = ["Verdict:", "Confidence:", "Severity:", "MITRE ATT&CK:", "Summary:",
            "Key evidence:", "Recommended actions:"]
LABELS = ["Benign True Positive", "Needs Investigation", "False Positive", "True Positive"]


def ask(model, messages):
    body = json.dumps({"model": model, "messages": messages, "stream": False,
                       "options": {"temperature": 0, "num_predict": 700}}).encode()
    req = urllib.request.Request(OLLAMA, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())["message"]["content"]


def parse_verdict(text):
    """Strict 'Verdict:' line first; otherwise fuzzy match so a base model that
    ignores the format still gets credit for the right call."""
    m = re.search(r"Verdict:\s*\**\s*([A-Za-z ]+)", text)
    candidate = m.group(1) if m else text[:600]
    low = candidate.lower()
    if "benign" in low:
        return "Benign True Positive"
    if "needs investigation" in low or "escalat" in low or "inconclusive" in low:
        return "Needs Investigation"
    if "false positive" in low:
        return "False Positive"
    if "true positive" in low or "malicious" in low or "incident" in low:
        return "True Positive"
    return "Unparsed"


def mitre_hit(expected, text):
    ids = re.findall(r"T\d{4}(?:\.\d{3})?", expected)
    if not ids:
        return False
    first = ids[0]
    return first in text or first.split(".")[0] in text


def hallucinated(alert, answer):
    cited = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", answer))
    cited |= set(re.findall(r"\b(?:WS|SRV|JMP)-[A-Z0-9-]+\b", answer))
    return any(c not in alert for c in cited)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", action="append", required=True)
    ap.add_argument("--data", default="data/test.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.data, encoding="utf-8")]
    if args.limit:
        rows = rows[:args.limit]
    os.makedirs("results", exist_ok=True)
    summary = []

    for model in args.model:
        stats = dict(n=0, correct=0, tp_total=0, missed_tp=0, benign_total=0, false_alarm=0,
                     mitre=0, fmt=0, halluc=0, secs=0.0)
        out_path = os.path.join("results", "{}_{}.csv".format(
            os.path.splitext(os.path.basename(args.data))[0], re.sub(r"[^A-Za-z0-9]+", "-", model)))
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["scenario", "expected", "predicted", "correct", "mitre_hit", "format_ok",
                        "hallucinated", "answer"])
            for i, r in enumerate(rows, 1):
                system, user, ref = r["conversations"]
                expected = r["meta"]["verdict"]
                ref_mitre = ref["content"].split("MITRE ATT&CK:")[1].split("\n")[0] if "MITRE ATT&CK:" in ref["content"] else r["meta"]["mitre"]
                t0 = time.time()
                ans = ask(model, [system, user])
                stats["secs"] += time.time() - t0
                pred = parse_verdict(ans)
                ok = pred == expected
                mh = mitre_hit(ref_mitre, ans)
                fm = all(s in ans for s in SECTIONS)
                hl = hallucinated(user["content"], ans)
                stats["n"] += 1
                stats["correct"] += ok
                stats["mitre"] += mh
                stats["fmt"] += fm
                stats["halluc"] += hl
                if expected == "True Positive":
                    stats["tp_total"] += 1
                    stats["missed_tp"] += pred not in ("True Positive", "Needs Investigation")
                if expected in ("Benign True Positive", "False Positive"):
                    stats["benign_total"] += 1
                    stats["false_alarm"] += pred == "True Positive"
                w.writerow([r["meta"]["scenario"], expected, pred, ok, mh, fm, hl, ans])
                print("[{}] {}/{} {:<22} -> {:<22} {}".format(model, i, len(rows), expected, pred, "OK" if ok else "XX"))
        n = max(stats["n"], 1)
        summary.append([model, stats["n"],
                        "{:.0%}".format(stats["correct"] / n),
                        "{}/{}".format(stats["missed_tp"], stats["tp_total"]),
                        "{}/{}".format(stats["false_alarm"], stats["benign_total"]),
                        "{:.0%}".format(stats["mitre"] / n),
                        "{:.0%}".format(stats["fmt"] / n),
                        "{:.0%}".format(stats["halluc"] / n),
                        "{:.1f}s".format(stats["secs"] / n)])

    hdr = ["model", "n", "verdict_acc", "missed_tp", "false_alarm", "mitre_acc", "format_ok", "hallucinated", "avg_time"]
    widths = [max(len(str(x)) for x in col) for col in zip(hdr, *summary)]
    print("\nDATASET: {}".format(args.data))
    for line in [hdr] + summary:
        print("  ".join(str(x).ljust(wd) for x, wd in zip(line, widths)))


if __name__ == "__main__":
    main()
