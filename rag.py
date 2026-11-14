"""
RAG pipeline for the fine-tuned SOC triage model (tier 3 of the comparison).

  Ingest:  python rag.py ingest
           Splits every rag_docs/*.md file into sections, embeds them with
           nomic-embed-text (served by Ollama), and stores them in a FAISS index.

  Query:   python rag.py ask data/showcase/alert1.txt
           Embeds the alert, retrieves the most relevant sections from FAISS,
           and sends them plus the alert to the fine-tuned model (soc-triage)
           running in Ollama.

The prompt layout ("Retrieved context:" + [source] blocks + the alert) is the
same layout the model saw in its training examples, so it knows to use the
documents and end its answer with a "Sources:" line.

Libraries (faiss-cpu, numpy, ollama) live in the private .rag_libs folder so
they do not interfere with other Python projects on this machine.
"""
import base64
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".rag_libs"))

import faiss  # noqa: E402
import numpy as np  # noqa: E402
import ollama  # noqa: E402

DOCS_DIR = os.path.join(HERE, "rag_docs")
INDEX_DIR = os.path.join(HERE, "rag_index")
EMBED_MODEL = "nomic-embed-text"
CHAT_MODEL = "soc-triage"          # the fine-tuned model, NOT the base model
TOP_K = 3                # at most this many chunks go to the model
MARGIN = 0.04            # ...and only those scoring within MARGIN of the best match
SYSTEM_PROMPT = open(os.path.join(HERE, "system_prompt.txt"), encoding="utf-8").read().strip()


def chunk_markdown(path):
    """One chunk per '## ' section; table documents become one chunk per row."""
    name = os.path.basename(path)
    text = open(path, encoding="utf-8").read()
    title = text.splitlines()[0].lstrip("# ").strip()
    rows = [l for l in text.splitlines() if l.startswith("|") and not l.startswith("|---")]
    if len(rows) > 1:
        return name, ["{}\n{}\n{}".format(title, rows[0], r) for r in rows[1:]]
    sections = text.split("\n## ")
    chunks = ["{}\n## {}".format(title, s.strip()) for s in sections[1:]]
    return name, chunks or [text.strip()]


def embed(texts, kind):
    """nomic-embed-text expects these task prefixes. Vectors are L2-normalized,
    so FAISS inner product equals cosine similarity."""
    prefix = "search_document: " if kind == "doc" else "search_query: "
    vecs = np.array([ollama.embeddings(model=EMBED_MODEL, prompt=prefix + t)["embedding"] for t in texts],
                    dtype="float32")
    faiss.normalize_L2(vecs)
    return vecs


QUERY_FIELDS = ("detection", "detection_name", "process", "image", "process tree", "ancestry",
                "user", "device_group", "host", "network", "additional context", "context", "signature")


def search_query(alert):
    """Build the retrieval query from the meaningful alert fields only (works for
    both the key/value and JSON alert layouts); hashes and base64 are dropped."""
    picked = []
    for line in alert.splitlines():
        m = re.match(r'\s*"?([A-Za-z _]+)"?\s*:\s*"?(.*?)"?,?\s*$', line)
        if m and m.group(1).strip().lower() in QUERY_FIELDS and m.group(2):
            picked.append(m.group(2))
    text = "\n".join(picked) or alert
    return re.sub(r"\b[A-Za-z0-9+/=]{40,}\b", " ", text).replace("\\\\", "\\")


def decode_powershell(alert):
    """Decode -EncodedCommand payloads in code. A 3B model cannot decode base64
    itself, so the pipeline supplies the true decoded text as context."""
    out = []
    for blob in re.findall(r"-(?:EncodedCommand|enc|e)\s+([A-Za-z0-9+/=]{16,})", alert, flags=re.I):
        try:
            out.append(base64.b64decode(blob).decode("utf-16-le"))
        except Exception:
            pass
    return out


def ingest():
    os.makedirs(INDEX_DIR, exist_ok=True)
    chunks, sources = [], []
    for path in sorted(glob.glob(os.path.join(DOCS_DIR, "*.md"))):
        name, parts = chunk_markdown(path)
        chunks += parts
        sources += [name] * len(parts)
        print("  {:<34} {} chunks".format(name, len(parts)))
    vecs = embed(chunks, "doc")
    index = faiss.IndexFlatIP(vecs.shape[1])
    index.add(vecs)
    faiss.write_index(index, os.path.join(INDEX_DIR, "soc.faiss"))
    with open(os.path.join(INDEX_DIR, "chunks.json"), "w", encoding="utf-8") as f:
        json.dump({"chunks": chunks, "sources": sources}, f, ensure_ascii=False)
    print("Ingested {} chunks ({}-dim vectors) into FAISS at {}".format(len(chunks), vecs.shape[1], INDEX_DIR))


def ask(alert_path):
    alert = open(alert_path, encoding="utf-8").read().strip()
    index = faiss.read_index(os.path.join(INDEX_DIR, "soc.faiss"))
    store = json.load(open(os.path.join(INDEX_DIR, "chunks.json"), encoding="utf-8"))

    # ---- INPUT: show the question exactly as it is sent to the model ----
    print("=" * 78)
    print("INPUT ALERT ({})".format(os.path.basename(alert_path)))
    print("=" * 78)
    print(alert)

    # ---- RETRIEVAL: embed the alert and search the FAISS vector store ----
    # The search uses only the meaningful alert fields; the model still sees the full alert.
    scores, ids = index.search(embed([search_query(alert)], "query"), TOP_K + 2)
    ranked = [(store["sources"][i], store["chunks"][i], float(s)) for i, s in zip(ids[0], scores[0])]
    best = ranked[0][2]
    hits = [h for h in ranked if h[2] >= best - MARGIN][:TOP_K]
    print("=" * 78)
    print("RETRIEVAL: FAISS cosine search, keeping chunks within {:.2f} of the best match".format(MARGIN))
    for src, chunk, score in ranked:
        mark = "KEEP" if (src, chunk, score) in hits else "drop"
        print("  {} {:.2f}  [{}]  {}".format(mark, score, src, chunk.splitlines()[1][:50]))

    blocks = ["[{}]\n{}".format(src, chunk) for src, chunk, _ in hits]
    # ---- ENRICHMENT: decode PowerShell payloads in code, not in the model ----
    for decoded in decode_powershell(alert):
        print("  ENRICH decoded -EncodedCommand: " + decoded[:70])
        blocks.append("[pipeline_decoder]\nThe -EncodedCommand payload in this alert decodes to: " + decoded)
    context = "Retrieved context:\n\n" + "\n\n".join(blocks)

    # ---- GENERATION: the fine-tuned model answers using the retrieved context ----
    print("=" * 78)
    print("GENERATION: {} (fine-tuned Llama 3.2 3B) via Ollama".format(CHAT_MODEL))
    reply = ollama.chat(model=CHAT_MODEL,
                        messages=[{"role": "system", "content": SYSTEM_PROMPT},
                                  {"role": "user", "content": context + "\n\n" + alert}],
                        options={"temperature": 0, "num_ctx": 4096})
    answer = reply["message"]["content"].strip()
    print("=" * 78)
    print(answer)
    if "Sources:" not in answer:
        print("\nRetrieved from: " + ", ".join(sorted({s for s, _, _ in hits})))
    print("=" * 78)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "ingest":
        ingest()
    elif len(sys.argv) >= 3 and sys.argv[1] == "ask":
        ask(sys.argv[2])
    else:
        print(__doc__)
