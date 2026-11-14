"""Environment check for new installs:  python -m capstone doctor [--org <id>]

Reports, with the command that fixes each problem: Python version, Python packages, Ollama,
the three models, the org pack, and its vector indexes. Makes no model calls.
"""
import importlib
import json
import os
import sys
import urllib.request

from . import config
from . import org as orgmod

PACKAGES = ["faiss", "numpy", "ollama", "fastapi", "uvicorn", "httpx", "pydantic"]
MODELS = {
    config.TRIAGE_MODEL: "ollama pull hf.co/Sgoyal16/soc-triage-llama3.2-3b-GGUF:Q4_K_M && ollama create soc-triage -f Modelfile",
    config.IR_MODEL: "ollama pull " + config.IR_MODEL,
    "nomic-embed-text": "ollama pull nomic-embed-text",
}


def run(org_id=None, out=print):
    ok = True

    def report(good, label, fix=""):
        nonlocal ok
        ok = ok and good
        out("  [{}] {}{}".format("ok" if good else "!!", label, "" if good else "\n       fix: " + fix))

    out("Python")
    report(sys.version_info >= (3, 8), "Python {}.{}".format(*sys.version_info[:2]), "install Python 3.8 or newer")
    out("Packages")
    for name in PACKAGES:
        try:
            importlib.import_module(name)
            report(True, name)
        except Exception as e:  # ImportError or a broken binary wheel
            report(False, "{} ({})".format(name, type(e).__name__), "pip install -r requirements.txt")
    out("Ollama")
    names = []
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3) as r:
            names = [m["name"] for m in json.loads(r.read())["models"]]
        report(True, "running on localhost:11434")
    except Exception:
        report(False, "not reachable on localhost:11434", "install from https://ollama.com and start it")
    for model, fix in MODELS.items():
        report(any(n == model or n.startswith(model + ":") for n in names), "model " + model, fix)
    out("Org pack")
    try:
        org = orgmod.activate(org_id)
        report(True, "{} ({})".format(org.id, org.dir))
        from .validate import errors, validate
        errs = errors(validate(org))
        report(not errs, "validation: {} error(s)".format(len(errs)),
               "python -m capstone --org {} org validate".format(org.id))
        for kind in ("triage", "ir"):
            report(os.path.exists(os.path.join(org.index_dir, kind, "soc.faiss")), "{} index".format(kind),
                   "python -m capstone --org {} org ingest".format(org.id))
    except orgmod.OrgError as e:
        report(False, str(e), "python -m capstone org list")
    out("\n" + ("Ready: python -m capstone.web" + (" --org " + org_id if org_id else "") if ok
                else "Fix the items marked !! above, then run doctor again."))
    return ok
