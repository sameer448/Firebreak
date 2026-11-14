"""Vector retrieval for both agents, reusing the chunking/embedding code from rag.py.

Each org pack has two indexes under orgs/<id>/.index/:
  triage  playbooks + knowledge (roster, allowlists, known false positives, change calendar...)
  ir      playbooks + IR policy documents (severity rubric, escalation contacts...)
The files that go into each are listed by the "knowledge" globs in org.json.
"""
import json
import os
import sys

from . import config
from . import org as orgmod

sys.path.insert(0, config.ROOT)
import rag  # noqa: E402  (also puts .rag_libs on sys.path)
import faiss  # noqa: E402

TOP_K = rag.TOP_K
MARGIN = rag.MARGIN


def ingest(kind, org=None):
    """Build one org index ('triage' or 'ir'). Returns (files, chunks)."""
    org = org or orgmod.current()
    paths = org.knowledge_files(kind)
    if not paths:
        raise FileNotFoundError("Org '{}' has no {} knowledge files".format(org.id, kind))
    chunks, sources = [], []
    for path in paths:
        name, parts = rag.chunk_markdown(path)
        chunks += parts
        sources += [name] * len(parts)
    vecs = rag.embed(chunks, "doc")
    out = os.path.join(org.index_dir, kind)
    os.makedirs(out, exist_ok=True)
    index = faiss.IndexFlatIP(vecs.shape[1])
    index.add(vecs)
    faiss.write_index(index, os.path.join(out, "soc.faiss"))
    with open(os.path.join(out, "chunks.json"), "w", encoding="utf-8") as f:
        json.dump({"chunks": chunks, "sources": sources}, f, ensure_ascii=False)
    return len(paths), len(chunks)


class Retriever:
    def __init__(self, index_dir):
        if not os.path.exists(os.path.join(index_dir, "soc.faiss")):
            raise FileNotFoundError("Index missing at {} - run the ingest step first".format(index_dir))
        self.index = faiss.read_index(os.path.join(index_dir, "soc.faiss"))
        with open(os.path.join(index_dir, "chunks.json"), encoding="utf-8") as f:
            self.store = json.load(f)

    def search(self, query, top_k=TOP_K, margin=MARGIN):
        """Same policy as rag.py: top-k chunks, kept only within `margin` of the best score."""
        scores, ids = self.index.search(rag.embed([query], "query"), top_k + 2)
        ranked = [(self.store["sources"][i], self.store["chunks"][i], float(s))
                  for i, s in zip(ids[0], scores[0]) if i >= 0]
        if not ranked:
            return []
        best = ranked[0][2]
        return [h for h in ranked if h[2] >= best - margin][:top_k]

    def chunks_from(self, source):
        """Every chunk of one document (e.g. the full severity rubric)."""
        return [c for s, c in zip(self.store["sources"], self.store["chunks"]) if s == source]
